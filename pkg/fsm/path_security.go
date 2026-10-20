package fsm

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// PathValidator provides strict repository-anchored path validation and traversal prevention.
type PathValidator struct {
	canonicalRepoRoot string
}

// NewPathValidator initializes a path validator with an absolute, symlink-evaluated repository root.
func NewPathValidator(repoRoot string) (*PathValidator, error) {
	absRoot, err := filepath.Abs(repoRoot)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path of repo root: %w", err)
	}

	// Clean root path
	cleanRoot := filepath.Clean(absRoot)

	// If root exists, evaluate its symlinks
	canonicalRoot := cleanRoot
	if fi, err := os.Stat(cleanRoot); err == nil && fi.IsDir() {
		if eval, err := filepath.EvalSymlinks(cleanRoot); err == nil {
			canonicalRoot = eval
		}
	}

	return &PathValidator{
		canonicalRepoRoot: canonicalRoot,
	}, nil
}

// CanonicalRepoRoot returns the resolved, absolute repository root path.
func (pv *PathValidator) CanonicalRepoRoot() string {
	return pv.canonicalRepoRoot
}

// ValidateAndCanonicalize verifies that a target path resides strictly inside the repository root.
// It handles path traversal, existing/uncreated files, symlinks, and Windows case-insensitivity.
func (pv *PathValidator) ValidateAndCanonicalize(targetPath string) (string, error) {
	if strings.ContainsRune(targetPath, 0) {
		return "", fmt.Errorf("%w: path contains null byte", ErrPathEscapesRoot)
	}

	// Check for Windows alternate data streams (e.g. file.go::$DATA or file.go:stream)
	if runtime.GOOS == "windows" {
		vol := filepath.VolumeName(targetPath)
		pathWithoutVol := targetPath[len(vol):]
		if strings.Contains(pathWithoutVol, ":") {
			return "", fmt.Errorf("%w: alternate data stream access rejected", ErrPathEscapesRoot)
		}
	}

	var fullPath string
	if filepath.IsAbs(targetPath) {
		fullPath = filepath.Clean(targetPath)
	} else {
		fullPath = filepath.Clean(filepath.Join(pv.canonicalRepoRoot, targetPath))
	}

	// Ensure fullPath starts with canonicalRepoRoot (lexical check first)
	rel, err := filepath.Rel(pv.canonicalRepoRoot, fullPath)
	if err != nil || strings.HasPrefix(rel, "..") || rel == ".." {
		return "", fmt.Errorf("%w: path %q escapes repository root %q", ErrPathEscapesRoot, targetPath, pv.canonicalRepoRoot)
	}

	// Symlink evaluation & traversal check
	evalPath, err := pv.resolvePathSymlinks(fullPath)
	if err != nil {
		return "", err
	}

	// Verify that the symlink-evaluated path is strictly inside canonicalRepoRoot
	evalRel, err := filepath.Rel(pv.canonicalRepoRoot, evalPath)
	if err != nil || strings.HasPrefix(evalRel, "..") || evalRel == ".." {
		return "", fmt.Errorf("%w: symlinked path %q resolves to %q outside repo root", ErrSymlinkEscape, targetPath, evalPath)
	}

	// Normalize relative path representation (clean, forward-slash for internal manifest matching)
	cleanRel := filepath.Clean(evalRel)
	normalized := filepath.ToSlash(cleanRel)

	if runtime.GOOS == "windows" {
		normalized = strings.ToLower(normalized)
	}

	return normalized, nil
}

// resolvePathSymlinks resolves symlinks even if the leaf file does not exist yet (new file creation).
func (pv *PathValidator) resolvePathSymlinks(path string) (string, error) {
	// If the exact file/directory exists, evaluate it directly
	if _, err := os.Lstat(path); err == nil {
		eval, err := filepath.EvalSymlinks(path)
		if err != nil {
			return "", fmt.Errorf("symlink resolution failed: %w", err)
		}
		return eval, nil
	}

	// If file does not exist, walk up to find the closest existing ancestor directory
	current := path
	var uncreatedParts []string

	for {
		parent := filepath.Dir(current)
		if parent == current {
			// Hit filesystem root without finding existing dir
			break
		}
		uncreatedParts = append([]string{filepath.Base(current)}, uncreatedParts...)

		if fi, err := os.Lstat(parent); err == nil {
			if !fi.IsDir() && (fi.Mode()&os.ModeSymlink != 0) {
				// Parent is a symlink file, resolve it
				evalParent, err := filepath.EvalSymlinks(parent)
				if err != nil {
					return "", fmt.Errorf("failed resolving symlink parent: %w", err)
				}
				parent = evalParent
			} else if fi.IsDir() {
				evalParent, err := filepath.EvalSymlinks(parent)
				if err != nil {
					return "", fmt.Errorf("failed resolving symlink parent: %w", err)
				}
				parent = evalParent
			}
			// Reconstruct full path from resolved existing ancestor
			resolved := parent
			for _, part := range uncreatedParts {
				resolved = filepath.Join(resolved, part)
			}
			return resolved, nil
		}
		current = parent
	}

	return path, nil
}
