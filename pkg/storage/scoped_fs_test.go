package storage_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/privora/privora/pkg/fsm"
	"github.com/privora/privora/pkg/storage"
)

func setupTestStorage(t *testing.T) (string, *fsm.StateMachine, ed25519.PublicKey, ed25519.PrivateKey, func()) {
	t.Helper()
	dir, err := os.MkdirTemp("", "privora-storage-test-*")
	if err != nil {
		t.Fatalf("failed creating temp dir: %v", err)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed generating keys: %v", err)
	}

	kr := fsm.NewKeyRegistry()
	_ = kr.RegisterApprover("architect@privora.io", pub, []string{fsm.RolePrincipalArchitect})

	sm, err := fsm.NewStateMachine(dir, kr)
	if err != nil {
		t.Fatalf("failed creating FSM: %v", err)
	}

	cleanup := func() {
		_ = os.RemoveAll(dir)
	}
	return dir, sm, pub, priv, cleanup
}

func TestScopedFileSystem_PointOfUseAuthorization(t *testing.T) {
	dir, sm, _, priv, cleanup := setupTestStorage(t)
	defer cleanup()

	sfs := storage.NewScopedFileSystem(sm)

	// Step 1: Read Repository - Attempting write via ScopedFileSystem MUST FAIL!
	err := sfs.WriteFile("test.go", []byte("package main"), 0644)
	if !errors.Is(err, fsm.ErrOutOfScopeModification) {
		t.Fatalf("expected ErrOutOfScopeModification in Step 1, got %v", err)
	}

	// Advance to Step 4 with approved manifest
	_ = sm.Transition(fsm.StageUnderstandArch, nil, "mapped")
	_ = sm.Transition(fsm.StageDesignSolution, nil, "designed")
	_ = sm.SetApprovedManifest("Design", []string{"pkg/wallet/balance.go"})

	token := &fsm.ApprovalToken{
		TokenID:      "TOK-FS-01",
		SessionID:    sm.SessionID(),
		ApproverID:   "architect@privora.io",
		Role:         fsm.RolePrincipalArchitect,
		ArtifactHash: sm.DesignHash(),
		Timestamp:    time.Now().UTC(),
	}
	_ = fsm.SignToken(priv, token)
	_ = sm.Transition(fsm.StageImplementCode, token, "approved")

	// Case A: Write to approved file -> Must Succeed
	content := []byte("// valid balance logic")
	if err := sfs.WriteFile("pkg/wallet/balance.go", content, 0644); err != nil {
		t.Fatalf("expected authorized write to succeed, got %v", err)
	}

	// Verify file is on disk
	actual, err := sfs.ReadFile("pkg/wallet/balance.go")
	if err != nil {
		t.Fatalf("failed reading authorized file: %v", err)
	}
	if string(actual) != string(content) {
		t.Fatalf("content mismatch")
	}

	// Case B: Write to unapproved file -> Must Fail at point of use
	err = sfs.WriteFile("pkg/wallet/backdoor.go", []byte("leak"), 0644)
	if !errors.Is(err, fsm.ErrOutOfScopeModification) {
		t.Fatalf("expected ErrOutOfScopeModification, got %v", err)
	}

	// Case C: Path Traversal Read outside repo -> Must Fail
	_, err = sfs.ReadFile("../../../etc/passwd")
	if !errors.Is(err, fsm.ErrPathEscapesRoot) {
		t.Fatalf("expected ErrPathEscapesRoot for traversal read, got %v", err)
	}
	_ = dir
}
