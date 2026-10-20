package tools_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/privora/privora/pkg/fsm"
	"github.com/privora/privora/pkg/tools"
)

func setupTestWorkspace(t *testing.T) (string, *fsm.StateMachine, ed25519.PublicKey, ed25519.PrivateKey, func()) {
	t.Helper()
	dir, err := os.MkdirTemp("", "privora-tools-test-*")
	if err != nil {
		t.Fatalf("failed creating temp dir: %v", err)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed generating keys: %v", err)
	}

	kr := fsm.NewKeyRegistry()
	_ = kr.RegisterApprover("lead@privora.io", pub, []string{fsm.RolePrincipalArchitect})

	sm, err := fsm.NewStateMachine(dir, kr)
	if err != nil {
		t.Fatalf("failed creating FSM: %v", err)
	}

	cleanup := func() {
		_ = os.RemoveAll(dir)
	}
	return dir, sm, pub, priv, cleanup
}

func TestStep1AndStep2MountZeroWriteTools(t *testing.T) {
	_, sm, _, _, cleanup := setupTestWorkspace(t)
	defer cleanup()

	registry := tools.NewRegistry(sm)

	// Step 1: Read Repository
	available := registry.GetAvailableTools()
	for _, tool := range available {
		if tool.Type == tools.TypeWrite {
			t.Fatalf("CRITICAL SECURITY VIOLATION: write tool %q is mounted in Step 1", tool.Name)
		}
		if tool.Type == tools.TypeExecution {
			t.Fatalf("CRITICAL SECURITY VIOLATION: execution tool %q is mounted in Step 1", tool.Name)
		}
	}

	// Attempting write_file in Step 1 must fail
	err := registry.ValidateToolCall("write_file", "main.go")
	if !errors.Is(err, fsm.ErrToolUnavailableForStage) {
		t.Fatalf("expected ErrToolUnavailableForStage for write_file in Step 1, got %v", err)
	}

	// Attempting actual ExecuteWriteFile in Step 1 must fail
	err = registry.ExecuteWriteFile("main.go", []byte("package main"))
	if !errors.Is(err, fsm.ErrToolUnavailableForStage) {
		t.Fatalf("expected ErrToolUnavailableForStage for ExecuteWriteFile in Step 1, got %v", err)
	}
}

func TestSEC06_PointOfUseFilesystemAuthorization(t *testing.T) {
	dir, sm, _, priv, cleanup := setupTestWorkspace(t)
	defer cleanup()

	registry := tools.NewRegistry(sm)

	_ = sm.Transition(fsm.StageUnderstandArch, nil, "mapped")
	_ = sm.Transition(fsm.StageDesignSolution, nil, "designed")

	// Set approved file manifest
	approvedRelPath := "internal/ledger/entry.go"
	_ = sm.SetApprovedManifest("Approved Design", []string{approvedRelPath})

	token := &fsm.ApprovalToken{
		TokenID:      "TOK-SEC06",
		SessionID:    sm.SessionID(),
		ApproverID:   "lead@privora.io",
		Role:         fsm.RolePrincipalArchitect,
		ArtifactHash: sm.DesignHash(),
		Timestamp:    time.Now().UTC(),
	}
	_ = fsm.SignToken(priv, token)
	_ = sm.Transition(fsm.StageImplementCode, token, "approved")

	// Case A: Write to an approved file -> Must succeed at point of use and create file on disk
	content := []byte("// authorized content")
	err := registry.ExecuteWriteFile(approvedRelPath, content)
	if err != nil {
		t.Fatalf("expected ExecuteWriteFile to succeed for approved file, got %v", err)
	}

	// Verify file was actually written to disk
	writtenPath := filepath.Join(dir, filepath.FromSlash(approvedRelPath))
	data, err := os.ReadFile(writtenPath)
	if err != nil {
		t.Fatalf("failed reading written file: %v", err)
	}
	if string(data) != string(content) {
		t.Fatalf("written file content mismatch")
	}

	// Case B: Write to an unapproved file -> Must fail at point of use!
	unapprovedRelPath := "internal/auth/secrets.go"
	err = registry.ExecuteWriteFile(unapprovedRelPath, []byte("leak"))
	if !errors.Is(err, fsm.ErrOutOfScopeModification) {
		t.Fatalf("expected ErrOutOfScopeModification, got %v", err)
	}

	// Verify unapproved file was NOT created on disk
	unapprovedPath := filepath.Join(dir, filepath.FromSlash(unapprovedRelPath))
	if _, err := os.Stat(unapprovedPath); !os.IsNotExist(err) {
		t.Fatalf("CRITICAL SECURITY FAILURE: unapproved file was created on disk!")
	}
}
