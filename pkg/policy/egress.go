package policy

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/privora/privora/pkg/fsm"
)

// EgressPolicy defines organizational network routing restrictions.
type EgressPolicy struct {
	AllowLocalInference bool
	AllowEnterpriseVPC  bool
	AllowedVPCSubnets   []*net.IPNet
	DefaultConfidential bool
}

// DefaultStrictPolicy returns the strictest local-first egress policy: loopback only, default confidential.
func DefaultStrictPolicy() *EgressPolicy {
	return &EgressPolicy{
		AllowLocalInference: true,
		AllowEnterpriseVPC:  false,
		DefaultConfidential: true,
	}
}

func (p *EgressPolicy) isAllowedVPC(ip net.IP) bool {
	for _, subnet := range p.AllowedVPCSubnets {
		if subnet.Contains(ip) {
			return true
		}
	}
	return false
}

// EgressGuardTransport implements http.RoundTripper with pre-DNS filtering and raw socket protections.
type EgressGuardTransport struct {
	baseTransport *http.Transport
	policy        *EgressPolicy
}

// NewEgressGuardTransport wraps a transport with strict provenance-aware egress filtering and custom dialer.
func NewEgressGuardTransport(policy *EgressPolicy) *EgressGuardTransport {
	if policy == nil {
		policy = DefaultStrictPolicy()
	}

	dialer := NewEgressGuardDialer(policy)

	baseTransport := &http.Transport{
		Proxy:                 nil, // Disable proxy bypass
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          10,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	return &EgressGuardTransport{
		baseTransport: baseTransport,
		policy:        policy,
	}
}

// RoundTrip intercepts every outbound HTTP request and enforces the Zero-Leakage Policy.
func (t *EgressGuardTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	host := req.URL.Hostname()

	// STEP 1: Pre-DNS Host Check (blocks DNS exfiltration channels BEFORE any DNS resolution)
	if err := PreDNSHostCheck(host, t.policy); err != nil {
		return nil, err
	}

	// STEP 2: Loopback verification
	if IsLoopbackHost(host) && t.policy.AllowLocalInference {
		return t.baseTransport.RoundTrip(req)
	}

	// STEP 3: If not loopback, DNS resolution is only permitted if Enterprise VPC is explicitly configured
	if !t.policy.AllowEnterpriseVPC {
		return nil, fmt.Errorf("%w: attempt to route request to external host %q blocked",
			fsm.ErrTaintedDataEgressBlocked, host)
	}

	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, fmt.Errorf("%w: failed resolving host %q: %v", fsm.ErrTaintedDataEgressBlocked, host, err)
	}

	for _, ip := range ips {
		if !t.policy.isAllowedVPC(ip) && !ip.IsLoopback() {
			return nil, fmt.Errorf("%w: resolved IP %s is outside authorized enterprise VPC",
				fsm.ErrTaintedDataEgressBlocked, ip)
		}
	}

	return t.baseTransport.RoundTrip(req)
}

// NewSecureHTTPClient returns an http.Client wrapped with EgressGuardTransport and redirect protection.
func NewSecureHTTPClient(policy *EgressPolicy) *http.Client {
	if policy == nil {
		policy = DefaultStrictPolicy()
	}
	return &http.Client{
		Transport:     NewEgressGuardTransport(policy),
		CheckRedirect: CreateSecureRedirectPolicy(policy),
		Timeout:       10 * time.Second,
	}
}

// IsPublicEndpoint inspects an endpoint string to determine if it is an external cloud provider.
func IsPublicEndpoint(endpoint string) bool {
	lower := strings.ToLower(endpoint)
	return strings.Contains(lower, "openai.com") ||
		strings.Contains(lower, "anthropic.com") ||
		strings.Contains(lower, "googleapis.com") ||
		strings.Contains(lower, "cohere.ai")
}
