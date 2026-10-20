package policy

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/privora/privora/pkg/fsm"
)

// IsLoopbackHost checks whether a host string is literally a local loopback interface.
func IsLoopbackHost(host string) bool {
	// Strip port if present
	h, _, err := net.SplitHostPort(host)
	if err == nil {
		host = h
	}

	lower := strings.ToLower(host)
	if lower == "localhost" || lower == "127.0.0.1" || lower == "::1" || lower == "[::1]" {
		return true
	}

	ip := net.ParseIP(lower)
	if ip != nil && ip.IsLoopback() {
		return true
	}
	return false
}

// PreDNSHostCheck evaluates an address before performing any DNS resolution to prevent DNS-based data exfiltration.
func PreDNSHostCheck(host string, policy *EgressPolicy) error {
	// If it is literally loopback, it is permitted for local inference
	if IsLoopbackHost(host) && policy.AllowLocalInference {
		return nil
	}

	// If in strict local-first mode (default), any non-loopback domain or external IP is blocked PRE-DNS!
	if !policy.AllowEnterpriseVPC {
		return fmt.Errorf("%w: pre-DNS egress check blocked external host %q (DNS exfiltration prevention)",
			fsm.ErrTaintedDataEgressBlocked, host)
	}

	// If enterprise VPC is enabled, verify IP literal if provided
	h, _, err := net.SplitHostPort(host)
	if err == nil {
		host = h
	}
	ip := net.ParseIP(host)
	if ip != nil {
		if !policy.isAllowedVPC(ip) && !ip.IsLoopback() {
			return fmt.Errorf("%w: external IP %q is outside authorized enterprise VPC CIDR",
				fsm.ErrTaintedDataEgressBlocked, ip)
		}
	}

	return nil
}

// EgressGuardDialer implements a net.Dialer that mechanically blocks raw direct TCP/UDP socket connections.
type EgressGuardDialer struct {
	baseDialer *net.Dialer
	policy     *EgressPolicy
}

// NewEgressGuardDialer creates a secure dialer enforcing network egress boundaries on raw sockets.
func NewEgressGuardDialer(policy *EgressPolicy) *EgressGuardDialer {
	if policy == nil {
		policy = DefaultStrictPolicy()
	}
	return &EgressGuardDialer{
		baseDialer: &net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		},
		policy: policy,
	}
}

// DialContext intercepts raw socket connection attempts and verifies network destination.
func (d *EgressGuardDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}

	// Enforce pre-DNS check to prevent DNS leakage
	if err := PreDNSHostCheck(host, d.policy); err != nil {
		return nil, err
	}

	// Dial connection if permitted
	return d.baseDialer.DialContext(ctx, network, addr)
}

// CreateSecureRedirectPolicy returns an http.Client CheckRedirect function that blocks redirect-based escapes.
func CreateSecureRedirectPolicy(policy *EgressPolicy) func(req *http.Request, via []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return fmt.Errorf("stopped after 10 redirects")
		}

		targetHost := req.URL.Hostname()
		// Re-evaluate egress on redirect target
		if err := PreDNSHostCheck(targetHost, policy); err != nil {
			return fmt.Errorf("%w: redirect escape blocked to host %q", fsm.ErrTaintedDataEgressBlocked, targetHost)
		}
		return nil
	}
}

// ValidateDestinationURL performs comprehensive URL validation before any network operation.
func ValidateDestinationURL(rawURL string, policy *EgressPolicy) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("malformed destination URL: %w", err)
	}

	host := parsed.Hostname()
	return PreDNSHostCheck(host, policy)
}
