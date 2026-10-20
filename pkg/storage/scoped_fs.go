package storage

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/privora/privora/pkg/fsm"
)

// ScopedFileSystem guarantees point-of-use authorization on all filesystem operations.
type ScopedFileSystem struct {
	repoRoot string
	sm       *fsm.StateMachine
}

// NewScopedFileSystem creates an authorized filesystem wrapper anchored to a state machine.
func NewScopedFileSystem(sm *fsm.StateMachine) *ScopedFileSystem {
	return &ScopedFileSystem{
		repoRoot: sm.RepoRoot(),
		sm:       sm,
	}
}

// WriteFile performs point-of-use scope verification immediately before writing data to disk.
func (sfs *ScopedFileSystem) WriteFile(relPath string, data []byte, perm os.FileMode) error {
	// Point-of-use authorization check: Is this file in scope in the active stage?
	if !sfs.sm.IsFileInScope(relPath) {
		return fmt.Errorf("%w: unauthorized write to %q", fsm.ErrOutOfScopeModification, relPath)
	}

	fullPath := filepath.Join(sfs.repoRoot, filepath.FromSlash(relPath))
	dir := filepath.Dir(fullPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed creating parent directories: %w", err)
	}

	return os.WriteFile(fullPath, data, perm)
}

// ReadFile performs path traversal check and reads file contents.
func (sfs *ScopedFileSystem) ReadFile(relPath string) ([]byte, error) {
	pv, err := fsm.NewPathValidator(sfs.repoRoot)
	if err != nil {
		return nil, err
	}

	canonicalRel, err := pv.ValidateAndCanonicalize(relPath)
	if err != nil {
		return nil, fmt.Errorf("%w: read rejected: %v", fsm.ErrPathEscapesRoot, err)
	}

	fullPath := filepath.Join(sfs.repoRoot, filepath.FromSlash(canonicalRel))
	return os.ReadFile(fullPath)
}
