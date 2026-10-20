package policy_test

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/privora/privora/pkg/fsm"
	"github.com/privora/privora/pkg/policy"
)

func TestTaintedDataEgressPolicy(t *testing.T) {
	repoData := policy.NewRepoData("internal/ledger/balance.go", "func CalculateBalance() { ... }")

	// Case 1: Tainted repository data sent to public AI provider -> MUST BE BLOCKED
	err := policy.ValidateEgress(repoData, policy.DestExternalPublic)
	if err == nil {
		t.Fatalf("CRITICAL SECURITY FAILURE: Tainted repo data allowed to external public destination")
	}
	if !errors.Is(err, fsm.ErrTaintedDataEgressBlocked) {
		t.Fatalf("expected ErrTaintedDataEgressBlocked, got %v", err)
	}

	// Case 2: Tainted repository data sent to local inference runtime -> Allowed
	if err := policy.ValidateEgress(repoData, policy.DestLocalInference); err != nil {
		t.Fatalf("expected local inference to be allowed for repo data, got %v", err)
	}

	// Case 3: Tainted repository data sent to customer private enterprise VPC -> Allowed
	if err := policy.ValidateEgress(repoData, policy.DestEnterpriseVPC); err != nil {
		t.Fatalf("expected customer private VPC to be allowed for repo data, got %v", err)
	}

	// Case 4: Purely untainted synthetic data sent to external provider -> Allowed
	syntheticData := policy.TaintedData{
		Source:  "synthetic_user_prompt",
		Tag:     policy.ProvenanceUntaintedSynthetic,
		Content: "Explain Dijkstra's shortest path algorithm in Go.",
	}
	if err := policy.ValidateEgress(syntheticData, policy.DestExternalPublic); err != nil {
		t.Fatalf("expected synthetic data to pass egress check, got %v", err)
	}
}

func TestSEC04_PreDNSHostCheckAndDNSExfiltrationPrevention(t *testing.T) {
	strictPolicy := policy.DefaultStrictPolicy()

	// Case A: External domain must be blocked PRE-DNS (before any DNS query occurs)
	err := policy.PreDNSHostCheck("api.openai.com", strictPolicy)
	if !errors.Is(err, fsm.ErrTaintedDataEgressBlocked) {
		t.Fatalf("expected ErrTaintedDataEgressBlocked for external domain pre-DNS, got %v", err)
	}

	// Case B: Arbitrary exfiltration subdomain must be blocked PRE-DNS
	err = policy.PreDNSHostCheck("stolen-token-1234.attacker.com", strictPolicy)
	if !errors.Is(err, fsm.ErrTaintedDataEgressBlocked) {
		t.Fatalf("expected ErrTaintedDataEgressBlocked for exfil subdomain, got %v", err)
	}

	// Case C: Loopback hostnames must be permitted for local inference
	if err := policy.PreDNSHostCheck("localhost", strictPolicy); err != nil {
		t.Fatalf("expected localhost to be permitted, got %v", err)
	}
	if err := policy.PreDNSHostCheck("127.0.0.1:8080", strictPolicy); err != nil {
		t.Fatalf("expected 127.0.0.1 to be permitted, got %v", err)
	}
	if err := policy.PreDNSHostCheck("[::1]:11434", strictPolicy); err != nil {
		t.Fatalf("expected [::1] to be permitted, got %v", err)
	}
}

func TestSEC04_EgressGuardDialerBlocksDirectSockets(t *testing.T) {
	dialer := policy.NewEgressGuardDialer(policy.DefaultStrictPolicy())
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Direct socket connection attempt to external IP/host -> MUST BE BLOCKED
	_, err := dialer.DialContext(ctx, "tcp", "api.openai.com:443")
	if err == nil {
		t.Fatalf("CRITICAL SECURITY FAILURE: Direct TCP dial to external host was not blocked!")
	}
	if !errors.Is(err, fsm.ErrTaintedDataEgressBlocked) {
		t.Fatalf("expected ErrTaintedDataEgressBlocked on raw socket dial, got %v", err)
	}
}

func TestSEC04_RedirectEscapeProtection(t *testing.T) {
	redirectPolicy := policy.CreateSecureRedirectPolicy(policy.DefaultStrictPolicy())

	// Simulated redirect from loopback to external host
	escapedReq, err := http.NewRequest("GET", "https://api.openai.com/v1/leak", nil)
	if err != nil {
		t.Fatalf("failed creating request: %v", err)
	}
	initialReq, _ := http.NewRequest("GET", "http://127.0.0.1:8080/redirect", nil)

	err = redirectPolicy(escapedReq, []*http.Request{initialReq})
	if err == nil {
		t.Fatalf("CRITICAL SECURITY FAILURE: Redirect escape to external host was not blocked!")
	}
	if !errors.Is(err, fsm.ErrTaintedDataEgressBlocked) {
		t.Fatalf("expected ErrTaintedDataEgressBlocked on redirect escape, got %v", err)
	}
}

func TestSEC04_ContainerIsolationPolicyValidation(t *testing.T) {
	// Case A: Container with NetworkMode = "none" -> Must Pass
	secureConfig := policy.ContainerSecurityConfig{
		Image:        "alpine:latest",
		NetworkMode:  policy.NetworkModeNone,
		BindMounts:   []string{"/workspace/privora:/app"},
		ReadOnlyRoot: true,
	}
	if err := policy.ValidateContainerSecurity(secureConfig); err != nil {
		t.Fatalf("expected secure container config to pass, got %v", err)
	}

	// Case B: Container with NetworkMode = "host" -> Must Fail
	hostNetConfig := policy.ContainerSecurityConfig{
		Image:       "alpine:latest",
		NetworkMode: policy.NetworkModeHost,
	}
	err := policy.ValidateContainerSecurity(hostNetConfig)
	if !errors.Is(err, fsm.ErrInsecureContainerConfig) {
		t.Fatalf("expected ErrInsecureContainerConfig for host network, got %v", err)
	}

	// Case C: Container attempting to bind mount host ~/.ssh directory -> Must Fail
	sensitiveMountConfig := policy.ContainerSecurityConfig{
		Image:       "alpine:latest",
		NetworkMode: policy.NetworkModeNone,
		BindMounts:  []string{"/home/user/.ssh:/root/.ssh"},
	}
	err = policy.ValidateContainerSecurity(sensitiveMountConfig)
	if err == nil {
		t.Fatalf("expected error for sensitive ~/.ssh bind mount, got nil")
	}
}

func TestSEC04_EgressGuardTransportBlocksOutboundLeaks(t *testing.T) {
	client := policy.NewSecureHTTPClient(policy.DefaultStrictPolicy())

	// Case A: Attempting to send tainted context via HTTP to external host -> MUST FAIL
	req, err := http.NewRequest("POST", "https://api.openai.com/v1/chat/completions", bytes.NewBufferString(`{"model":"gpt-4"}`))
	if err != nil {
		t.Fatalf("failed building request: %v", err)
	}
	req.Header.Set("X-Privora-Provenance", string(policy.ProvenanceTaintedRepo))

	_, err = client.Do(req)
	if err == nil {
		t.Fatalf("CRITICAL SECURITY FAILURE: Outbound HTTP request to OpenAI was not blocked!")
	}
	if !errors.Is(err, fsm.ErrTaintedDataEgressBlocked) {
		t.Fatalf("expected ErrTaintedDataEgressBlocked, got %v", err)
	}
}
