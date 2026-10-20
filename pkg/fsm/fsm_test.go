package fsm_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/privora/privora/pkg/fsm"
)

// helper to create a temp repo directory
func setupTestRepo(t *testing.T) (string, func()) {
	t.Helper()
	dir, err := os.MkdirTemp("", "privora-test-repo-*")
	if err != nil {
		t.Fatalf("failed creating temp repo: %v", err)
	}

	_ = os.MkdirAll(filepath.Join(dir, "internal", "ledger"), 0755)
	_ = os.WriteFile(filepath.Join(dir, "internal", "ledger", "transfer.go"), []byte("package ledger"), 0644)

	cleanup := func() {
		_ = os.RemoveAll(dir)
	}
	return dir, cleanup
}

func setupKeys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed generating key pair: %v", err)
	}
	return pub, priv
}

func TestInitialStage(t *testing.T) {
	repoDir, cleanup := setupTestRepo(t)
	defer cleanup()

	sm, err := fsm.NewStateMachine(repoDir, nil)
	if err != nil {
		t.Fatalf("failed creating state machine: %v", err)
	}

	if sm.CurrentStage() != fsm.StageReadRepo {
		t.Fatalf("expected initial stage to be %s, got %s", fsm.StageReadRepo, sm.CurrentStage())
	}
	if !sm.CurrentStage().IsReadOnly() {
		t.Fatalf("expected initial stage to be read-only")
	}
	if sm.SessionID() == "" {
		t.Fatalf("expected non-empty cryptographic session ID")
	}
}

func TestSEC01_ManifestMutationAfterApprovalBlocked(t *testing.T) {
	repoDir, cleanup := setupTestRepo(t)
	defer cleanup()

	pub, priv := setupKeys(t)
	kr := fsm.NewKeyRegistry()
	_ = kr.RegisterApprover("lead@privora.io", pub, []string{fsm.RolePrincipalArchitect})

	sm, err := fsm.NewStateMachine(repoDir, kr)
	if err != nil {
		t.Fatalf("init failed: %v", err)
	}

	// Advance to Step 3
	_ = sm.Transition(fsm.StageUnderstandArch, nil, "mapped")
	_ = sm.Transition(fsm.StageDesignSolution, nil, "designed")

	// Set manifest during Step 3 (Allowed)
	err = sm.SetApprovedManifest("Design Document", []string{"internal/ledger/transfer.go"})
	if err != nil {
		t.Fatalf("expected SetApprovedManifest to succeed in Step 3, got %v", err)
	}

	// Sign valid Gate 1 token
	token := &fsm.ApprovalToken{
		TokenID:      "TOK-001",
		SessionID:    sm.SessionID(),
		ApproverID:   "lead@privora.io",
		Role:         fsm.RolePrincipalArchitect,
		ArtifactHash: sm.DesignHash(),
		Timestamp:    time.Now().UTC(),
	}
	_ = fsm.SignToken(priv, token)

	// Transition to Step 4
	if err := sm.Transition(fsm.StageImplementCode, token, "approved"); err != nil {
		t.Fatalf("transition to Step 4 failed: %v", err)
	}

	// ADVERSARIAL ATTEMPT: Attempt to mutate manifest while in Step 4 -> MUST FAIL!
	err = sm.SetApprovedManifest("Attacker Mutated Design", []string{"cmd/server/main.go"})
	if err == nil {
		t.Fatalf("CRITICAL SECURITY FAILURE: SetApprovedManifest succeeded while in StageImplementCode!")
	}
	if !errors.Is(err, fsm.ErrUnauthorizedStageForManifestMutation) {
		t.Fatalf("expected ErrUnauthorizedStageForManifestMutation, got %v", err)
	}
}

func TestSEC02_AuthoritativeKeyRegistryAndRoleEnforcement(t *testing.T) {
	repoDir, cleanup := setupTestRepo(t)
	defer cleanup()

	// Provision trusted architect
	archPub, archPriv := setupKeys(t)
	devPub, devPriv := setupKeys(t)
	attackerPub, attackerPriv := setupKeys(t)

	kr := fsm.NewKeyRegistry()
	_ = kr.RegisterApprover("architect@privora.io", archPub, []string{fsm.RolePrincipalArchitect})
	_ = kr.RegisterApprover("dev@privora.io", devPub, []string{"Engineer"}) // Not a Gate 1 role!

	sm, err := fsm.NewStateMachine(repoDir, kr)
	if err != nil {
		t.Fatalf("init failed: %v", err)
	}

	_ = sm.Transition(fsm.StageUnderstandArch, nil, "mapped")
	_ = sm.Transition(fsm.StageDesignSolution, nil, "designed")
	_ = sm.SetApprovedManifest("Original Design", []string{"internal/ledger/transfer.go"})

	// Case A: Missing Token -> Must Fail with ErrApprovalRequired
	err = sm.Transition(fsm.StageImplementCode, nil, "attempt with nil token")
	if !errors.Is(err, fsm.ErrApprovalRequired) {
		t.Fatalf("expected ErrApprovalRequired, got %v", err)
	}

	// Case B: Attacker-Generated Key (Not in Registry) -> Must Fail with ErrUntrustedApproverKey
	attackerToken := &fsm.ApprovalToken{
		TokenID:      "TOK-ATTACKER",
		SessionID:    sm.SessionID(),
		ApproverID:   "attacker@evil.com",
		Role:         fsm.RolePrincipalArchitect,
		ArtifactHash: sm.DesignHash(),
		Timestamp:    time.Now().UTC(),
	}
	_ = fsm.SignToken(attackerPriv, attackerToken)

	err = sm.Transition(fsm.StageImplementCode, attackerToken, "attacker attempt")
	if !errors.Is(err, fsm.ErrUntrustedApproverKey) {
		t.Fatalf("expected ErrUntrustedApproverKey for attacker key, got %v", err)
	}
	_ = attackerPub

	// Case C: Role Escalation Attempt (Registered user with unauthorized role) -> Must Fail with ErrUnauthorizedRole
	escalationToken := &fsm.ApprovalToken{
		TokenID:      "TOK-ESCALATION",
		SessionID:    sm.SessionID(),
		ApproverID:   "dev@privora.io",
		Role:         "Engineer", // Not authorized for Gate 1!
		ArtifactHash: sm.DesignHash(),
		Timestamp:    time.Now().UTC(),
	}
	_ = fsm.SignToken(devPriv, escalationToken)

	err = sm.Transition(fsm.StageImplementCode, escalationToken, "escalation attempt")
	if !errors.Is(err, fsm.ErrUnauthorizedRole) {
		t.Fatalf("expected ErrUnauthorizedRole for Engineer role at Gate 1, got %v", err)
	}

	// Case D: Role Forgery (Approver dev claims role Principal Architect in token) -> Must Fail with ErrUnauthorizedRole
	forgedRoleToken := &fsm.ApprovalToken{
		TokenID:      "TOK-FORGED-ROLE",
		SessionID:    sm.SessionID(),
		ApproverID:   "dev@privora.io",
		Role:         fsm.RolePrincipalArchitect, // dev is NOT provisioned for this role!
		ArtifactHash: sm.DesignHash(),
		Timestamp:    time.Now().UTC(),
	}
	_ = fsm.SignToken(devPriv, forgedRoleToken)

	err = sm.Transition(fsm.StageImplementCode, forgedRoleToken, "forged role attempt")
	if !errors.Is(err, fsm.ErrUnauthorizedRole) {
		t.Fatalf("expected ErrUnauthorizedRole when approver claims unassigned role, got %v", err)
	}

	// Case E: Key Revocation -> Revoking architect prevents token use
	_ = kr.RevokeApprover("architect@privora.io")

	revokedToken := &fsm.ApprovalToken{
		TokenID:      "TOK-REVOKED",
		SessionID:    sm.SessionID(),
		ApproverID:   "architect@privora.io",
		Role:         fsm.RolePrincipalArchitect,
		ArtifactHash: sm.DesignHash(),
		Timestamp:    time.Now().UTC(),
	}
	_ = fsm.SignToken(archPriv, revokedToken)

	err = sm.Transition(fsm.StageImplementCode, revokedToken, "revoked key attempt")
	if !errors.Is(err, fsm.ErrRevokedApproverKey) {
		t.Fatalf("expected ErrRevokedApproverKey after revocation, got %v", err)
	}

	// Case F: Identity Mismatch (Token says architect, but signed with dev's key) -> Must Fail with ErrInvalidSignature
	_ = kr.RegisterApprover("architect2@privora.io", archPub, []string{fsm.RolePrincipalArchitect})
	mismatchToken := &fsm.ApprovalToken{
		TokenID:      "TOK-MISMATCH-KEY",
		SessionID:    sm.SessionID(),
		ApproverID:   "architect2@privora.io",
		Role:         fsm.RolePrincipalArchitect,
		ArtifactHash: sm.DesignHash(),
		Timestamp:    time.Now().UTC(),
	}
	_ = fsm.SignToken(devPriv, mismatchToken) // signed with dev's key!

	err = sm.Transition(fsm.StageImplementCode, mismatchToken, "key mismatch attempt")
	if !errors.Is(err, fsm.ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature for identity key mismatch, got %v", err)
	}

	// Case G: Artifact Hash Mismatch -> Must Fail with ErrDesignHashMismatch
	mismatchedHashToken := &fsm.ApprovalToken{
		TokenID:      "TOK-HASH-MISMATCH",
		SessionID:    sm.SessionID(),
		ApproverID:   "architect2@privora.io",
		Role:         fsm.RolePrincipalArchitect,
		ArtifactHash: "0000000000000000000000000000000000000000000000000000000000000000",
		Timestamp:    time.Now().UTC(),
	}
	_ = fsm.SignToken(archPriv, mismatchedHashToken)

	err = sm.Transition(fsm.StageImplementCode, mismatchedHashToken, "hash mismatch attempt")
	if !errors.Is(err, fsm.ErrDesignHashMismatch) {
		t.Fatalf("expected ErrDesignHashMismatch, got %v", err)
	}
}

func TestSEC05_ReplayAndExpirationProtection(t *testing.T) {
	repoDir, cleanup := setupTestRepo(t)
	defer cleanup()

	pub, priv := setupKeys(t)
	kr := fsm.NewKeyRegistry()
	_ = kr.RegisterApprover("lead@privora.io", pub, []string{fsm.RolePrincipalArchitect})

	sm, err := fsm.NewStateMachine(repoDir, kr)
	if err != nil {
		t.Fatalf("init failed: %v", err)
	}

	_ = sm.Transition(fsm.StageUnderstandArch, nil, "mapped")
	_ = sm.Transition(fsm.StageDesignSolution, nil, "designed")
	_ = sm.SetApprovedManifest("Design", []string{"internal/ledger/transfer.go"})

	// Case A: Cross-session replay attempt -> Must Fail
	crossSessionToken := &fsm.ApprovalToken{
		TokenID:      "TOK-CROSS",
		SessionID:    "old-session-12345",
		ApproverID:   "lead@privora.io",
		Role:         fsm.RolePrincipalArchitect,
		ArtifactHash: sm.DesignHash(),
		Timestamp:    time.Now().UTC(),
	}
	_ = fsm.SignToken(priv, crossSessionToken)
	err = sm.Transition(fsm.StageImplementCode, crossSessionToken, "cross session replay")
	if !errors.Is(err, fsm.ErrSessionMismatch) {
		t.Fatalf("expected ErrSessionMismatch, got %v", err)
	}

	// Case B: Expired Token (> 15 minutes old) -> Must Fail
	expiredToken := &fsm.ApprovalToken{
		TokenID:      "TOK-EXPIRED",
		SessionID:    sm.SessionID(),
		ApproverID:   "lead@privora.io",
		Role:         fsm.RolePrincipalArchitect,
		ArtifactHash: sm.DesignHash(),
		Timestamp:    time.Now().UTC().Add(-20 * time.Minute),
	}
	_ = fsm.SignToken(priv, expiredToken)
	err = sm.Transition(fsm.StageImplementCode, expiredToken, "expired token attempt")
	if !errors.Is(err, fsm.ErrTokenExpired) {
		t.Fatalf("expected ErrTokenExpired, got %v", err)
	}

	// Case C: Valid Token used twice (Single-session replay) -> Must Fail
	validToken := &fsm.ApprovalToken{
		TokenID:      "TOK-REPLAY",
		SessionID:    sm.SessionID(),
		ApproverID:   "lead@privora.io",
		Role:         fsm.RolePrincipalArchitect,
		ArtifactHash: sm.DesignHash(),
		Timestamp:    time.Now().UTC(),
	}
	_ = fsm.SignToken(priv, validToken)

	// First use -> Succeeds
	if err := sm.Transition(fsm.StageImplementCode, validToken, "first use"); err != nil {
		t.Fatalf("first token use failed: %v", err)
	}

	// Regress back to Step 3 for revision
	_ = sm.Transition(fsm.StageDesignSolution, nil, "regress to design")

	// Attempt to replay the exact same TokenID -> MUST FAIL!
	err = sm.Transition(fsm.StageImplementCode, validToken, "replayed token")
	if !errors.Is(err, fsm.ErrTokenReplayed) {
		t.Fatalf("expected ErrTokenReplayed, got %v", err)
	}
}

func TestSEC03_PathTraversalAndSymlinkEscape(t *testing.T) {
	repoDir, cleanup := setupTestRepo(t)
	defer cleanup()

	outsideDir, outsideCleanup := setupTestRepo(t)
	defer outsideCleanup()

	pv, err := fsm.NewPathValidator(repoDir)
	if err != nil {
		t.Fatalf("path validator init failed: %v", err)
	}

	// Case A: Lexical parent directory traversal `../../` -> Must Fail
	_, err = pv.ValidateAndCanonicalize("../../../outside.txt")
	if !errors.Is(err, fsm.ErrPathEscapesRoot) {
		t.Fatalf("expected ErrPathEscapesRoot for ../../../, got %v", err)
	}

	// Case B: Null byte injection -> Must Fail
	_, err = pv.ValidateAndCanonicalize("internal/ledger/transfer.go\x00.exe")
	if !errors.Is(err, fsm.ErrPathEscapesRoot) {
		t.Fatalf("expected ErrPathEscapesRoot for null byte, got %v", err)
	}

	// Case C: Symlink pointing outside repository root -> Must Fail
	outsideTarget := filepath.Join(outsideDir, "secret.key")
	_ = os.WriteFile(outsideTarget, []byte("SUPER_SECRET"), 0600)
	symlinkPath := filepath.Join(repoDir, "symlink_escape")

	if err := os.Symlink(outsideTarget, symlinkPath); err == nil {
		_, err = pv.ValidateAndCanonicalize("symlink_escape")
		if !errors.Is(err, fsm.ErrSymlinkEscape) && !errors.Is(err, fsm.ErrPathEscapesRoot) {
			t.Fatalf("expected symlink escape error, got %v", err)
		}
	}

	// Case D: New uncreated file inside valid subfolder -> Must Succeed
	rel, err := pv.ValidateAndCanonicalize("internal/ledger/new_transfer.go")
	if err != nil {
		t.Fatalf("expected new file inside valid folder to succeed, got %v", err)
	}
	if rel != "internal/ledger/new_transfer.go" {
		t.Fatalf("unexpected canonical rel: %s", rel)
	}
}

func TestConcurrentTransitionsAndScopeChecks(t *testing.T) {
	repoDir, cleanup := setupTestRepo(t)
	defer cleanup()

	pub, priv := setupKeys(t)
	kr := fsm.NewKeyRegistry()
	_ = kr.RegisterApprover("lead@privora.io", pub, []string{fsm.RolePrincipalArchitect})

	sm, err := fsm.NewStateMachine(repoDir, kr)
	if err != nil {
		t.Fatalf("init failed: %v", err)
	}

	_ = sm.Transition(fsm.StageUnderstandArch, nil, "mapped")
	_ = sm.Transition(fsm.StageDesignSolution, nil, "designed")
	_ = sm.SetApprovedManifest("Design", []string{"internal/ledger/transfer.go"})

	token := &fsm.ApprovalToken{
		TokenID:      "TOK-CONCURRENT",
		SessionID:    sm.SessionID(),
		ApproverID:   "lead@privora.io",
		Role:         fsm.RolePrincipalArchitect,
		ArtifactHash: sm.DesignHash(),
		Timestamp:    time.Now().UTC(),
	}
	_ = fsm.SignToken(priv, token)
	_ = sm.Transition(fsm.StageImplementCode, token, "implementing")

	var wg sync.WaitGroup
	workers := 10

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_ = sm.CurrentStage()
				_ = sm.IsFileInScope("internal/ledger/transfer.go")
				_ = sm.IsFileInScope("unapproved.go")
				_ = sm.History()
			}
		}()
	}

	wg.Wait()
}
