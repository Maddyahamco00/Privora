package fsm

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"sync"
	"time"
)

// MaxApprovalTokenAge defines the maximum validity duration for an approval token (15 minutes).
const MaxApprovalTokenAge = 15 * time.Minute

// ApprovalToken represents a cryptographically signed human authorization token.
type ApprovalToken struct {
	TokenID      string
	SessionID    string
	ApproverID   string
	Role         string
	ArtifactHash string
	Timestamp    time.Time
	Signature    []byte
}

// SignableBytes generates the deterministic canonical byte sequence for digital signature generation and verification.
func (t *ApprovalToken) SignableBytes() []byte {
	h := sha256.New()
	h.Write([]byte("PRIVORA_APPROVAL_TOKEN_V1:"))
	h.Write([]byte(t.TokenID))
	h.Write([]byte(":"))
	h.Write([]byte(t.SessionID))
	h.Write([]byte(":"))
	h.Write([]byte(t.ApproverID))
	h.Write([]byte(":"))
	h.Write([]byte(t.Role))
	h.Write([]byte(":"))
	h.Write([]byte(t.ArtifactHash))
	h.Write([]byte(":"))
	h.Write([]byte(strconv.FormatInt(t.Timestamp.Unix(), 10)))
	return h.Sum(nil)
}

// SignToken cryptographically signs an approval token using an Ed25519 private key.
func SignToken(privKey ed25519.PrivateKey, token *ApprovalToken) error {
	if len(privKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("invalid ed25519 private key size: %d", len(privKey))
	}
	token.Signature = ed25519.Sign(privKey, token.SignableBytes())
	return nil
}

// TransitionRecord stores an immutable audit log entry for every state transition.
type TransitionRecord struct {
	FromStage  Stage
	ToStage    Stage
	Timestamp  time.Time
	ApprovedBy string
	TokenID    string
	Reason     string
}

// StateMachine manages the deterministic, stage-gated lifecycle of a Privora task.
type StateMachine struct {
	mu               sync.RWMutex
	sessionID        string
	repoRoot         string
	pathValidator    *PathValidator
	keyRegistry      *KeyRegistry
	currentStage     Stage
	approvedManifest map[string]struct{}
	designHash       string
	usedTokens       map[string]struct{}
	history          []TransitionRecord
}

// NewStateMachine instantiates an FSM bound to an authorized repository root, session ID, and authoritative key registry.
func NewStateMachine(repoRoot string, keyRegistry *KeyRegistry) (*StateMachine, error) {
	pv, err := NewPathValidator(repoRoot)
	if err != nil {
		return nil, fmt.Errorf("failed initializing path validator: %w", err)
	}

	sessionBytes := make([]byte, 16)
	if _, err := rand.Read(sessionBytes); err != nil {
		return nil, fmt.Errorf("failed generating cryptographic session ID: %w", err)
	}
	sessionID := hex.EncodeToString(sessionBytes)

	if keyRegistry == nil {
		keyRegistry = NewKeyRegistry()
	}

	sm := &StateMachine{
		sessionID:        sessionID,
		repoRoot:         pv.CanonicalRepoRoot(),
		pathValidator:    pv,
		keyRegistry:      keyRegistry,
		currentStage:     StageReadRepo,
		approvedManifest: make(map[string]struct{}),
		usedTokens:       make(map[string]struct{}),
		history: []TransitionRecord{
			{
				FromStage:  StageUninitialized,
				ToStage:    StageReadRepo,
				Timestamp:  time.Now().UTC(),
				ApprovedBy: "SYSTEM_INIT",
				TokenID:    "INIT",
				Reason:     "Task initialized in read-only mode",
			},
		},
	}
	return sm, nil
}

// SessionID returns the unique session ID of this workflow execution.
func (sm *StateMachine) SessionID() string {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.sessionID
}

// RepoRoot returns the canonical repository root path.
func (sm *StateMachine) RepoRoot() string {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.repoRoot
}

// CurrentStage returns the current active workflow stage.
func (sm *StateMachine) CurrentStage() Stage {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.currentStage
}

// History returns an immutable copy of the transition audit trail.
func (sm *StateMachine) History() []TransitionRecord {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	copied := make([]TransitionRecord, len(sm.history))
	copy(copied, sm.history)
	return copied
}

// DesignHash returns the SHA-256 hash of the approved design document.
func (sm *StateMachine) DesignHash() string {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.designHash
}

// SetApprovedManifest registers the authorized file paths during Step 3 (Design).
// SEC-01 FIX: Rejects calls outside StageDesignSolution. Scope expansion requires design stage re-entry.
func (sm *StateMachine) SetApprovedManifest(designDoc string, files []string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if sm.currentStage != StageDesignSolution {
		return fmt.Errorf("%w: cannot set or mutate manifest while in %s",
			ErrUnauthorizedStageForManifestMutation, sm.currentStage)
	}

	if len(files) == 0 {
		return fmt.Errorf("%w: manifest must contain at least one file path", ErrEmptyManifest)
	}

	newManifest := make(map[string]struct{})
	for _, f := range files {
		canonicalRel, err := sm.pathValidator.ValidateAndCanonicalize(f)
		if err != nil {
			return fmt.Errorf("invalid manifest path %q: %w", f, err)
		}
		newManifest[canonicalRel] = struct{}{}
	}

	hash := sha256.Sum256([]byte(designDoc))
	sm.designHash = hex.EncodeToString(hash[:])
	sm.approvedManifest = newManifest
	return nil
}

// IsFileInScope checks whether a target file path is authorized for write operations.
// SEC-03 FIX: Path is strictly canonicalized, symlink-checked, and anchored relative to repoRoot.
func (sm *StateMachine) IsFileInScope(path string) bool {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	if sm.currentStage != StageImplementCode {
		return false
	}

	canonicalRel, err := sm.pathValidator.ValidateAndCanonicalize(path)
	if err != nil {
		return false
	}

	_, ok := sm.approvedManifest[canonicalRel]
	return ok
}

// ApprovedManifestList returns the list of canonical approved file paths.
func (sm *StateMachine) ApprovedManifestList() []string {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	list := make([]string, 0, len(sm.approvedManifest))
	for f := range sm.approvedManifest {
		list = append(list, f)
	}
	return list
}

// CanTransitionTo checks whether moving to the target stage is syntactically permitted from the current stage.
func (sm *StateMachine) CanTransitionTo(target Stage) bool {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.isValidTransition(sm.currentStage, target)
}

// isValidTransition contains the internal transition matrix, including approved loopbacks.
func (sm *StateMachine) isValidTransition(from, to Stage) bool {
	switch from {
	case StageReadRepo:
		return to == StageUnderstandArch || to == StageAborted

	case StageUnderstandArch:
		return to == StageDesignSolution || to == StageReadRepo || to == StageAborted

	case StageDesignSolution:
		// Gate 1: Transition to Step 4 requires cryptographic human approval.
		return to == StageImplementCode || to == StageUnderstandArch || to == StageAborted

	case StageImplementCode:
		// Proceed to verification, loopback to design for scope expansion, or abort.
		return to == StageVerifyResult || to == StageDesignSolution || to == StageAborted

	case StageVerifyResult:
		// Tests pass -> review; tests fail -> implement; design flaw -> design; abort.
		return to == StageReviewChanges || to == StageImplementCode || to == StageDesignSolution || to == StageAborted

	case StageReviewChanges:
		// Gate 2: Sign-off -> release preparation; changes requested -> implement or design.
		return to == StagePrepareRelease || to == StageImplementCode || to == StageDesignSolution || to == StageAborted

	case StagePrepareRelease:
		return to == StageDeploySafely || to == StageAborted

	case StageDeploySafely:
		return to == StageCompleted || to == StageAborted

	default:
		return false
	}
}

// verifyApprovalTokenLocked cryptographically validates an approval token against active session, design, and authoritative key registry.
// SEC-02 & SEC-05 FIX: Authoritative key registry, role enforcement, design hash binding, session binding, expiry & replay protection.
func (sm *StateMachine) verifyApprovalTokenLocked(token *ApprovalToken, expectedHash string, allowedRoles []string) error {
	if token == nil {
		return fmt.Errorf("%w: missing approval token", ErrApprovalRequired)
	}

	if token.ApproverID == "" || token.TokenID == "" {
		return fmt.Errorf("%w: approver ID and token ID cannot be empty", ErrInvalidApprovalToken)
	}

	// Session binding check
	if token.SessionID != sm.sessionID {
		return fmt.Errorf("%w: token session %q does not match active session %q",
			ErrSessionMismatch, token.SessionID, sm.sessionID)
	}

	// Artifact / Design hash binding check
	if token.ArtifactHash == "" || token.ArtifactHash != expectedHash {
		return fmt.Errorf("%w: token artifact hash %q does not match active design hash %q",
			ErrDesignHashMismatch, token.ArtifactHash, expectedHash)
	}

	// Replay protection check
	if _, used := sm.usedTokens[token.TokenID]; used {
		return fmt.Errorf("%w: token ID %q has already been consumed", ErrTokenReplayed, token.TokenID)
	}

	// Expiry & clock skew check
	now := time.Now().UTC()
	if now.Sub(token.Timestamp) > MaxApprovalTokenAge {
		return fmt.Errorf("%w: token created at %v exceeds maximum age %v",
			ErrTokenExpired, token.Timestamp, MaxApprovalTokenAge)
	}
	if token.Timestamp.After(now.Add(1 * time.Minute)) {
		return fmt.Errorf("%w: token timestamp is in the future", ErrInvalidApprovalToken)
	}

	// Authoritative Key Registry Lookup (SEC-02 FIX: Never trust caller-injected keys!)
	approver, err := sm.keyRegistry.GetApprover(token.ApproverID)
	if err != nil {
		return err // ErrUntrustedApproverKey or ErrRevokedApproverKey
	}

	// Role Verification: Check if approver is provisioned for token.Role
	if _, authorizedForRole := approver.Roles[token.Role]; !authorizedForRole {
		return fmt.Errorf("%w: approver %q is not provisioned for role %q",
			ErrUnauthorizedRole, token.ApproverID, token.Role)
	}

	// Role Verification: Check if token.Role is authorized for this specific stage gate
	rolePermittedForGate := false
	for _, reqRole := range allowedRoles {
		if token.Role == reqRole {
			rolePermittedForGate = true
			break
		}
	}
	if !rolePermittedForGate {
		return fmt.Errorf("%w: role %q is not authorized for this approval gate (requires one of %v)",
			ErrUnauthorizedRole, token.Role, allowedRoles)
	}

	// Cryptographic Ed25519 signature check against authoritative public key
	if len(approver.PublicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: invalid public key size in registry: %d", ErrInvalidSignature, len(approver.PublicKey))
	}
	if len(token.Signature) != ed25519.SignatureSize {
		return fmt.Errorf("%w: invalid signature size: %d", ErrInvalidSignature, len(token.Signature))
	}

	if !ed25519.Verify(approver.PublicKey, token.SignableBytes(), token.Signature) {
		return fmt.Errorf("%w: Ed25519 signature verification failed against provisioned key for %q",
			ErrInvalidSignature, token.ApproverID)
	}

	return nil
}

// Transition advances the state machine to the target stage, strictly enforcing approval gates.
func (sm *StateMachine) Transition(target Stage, token *ApprovalToken, reason string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if !sm.isValidTransition(sm.currentStage, target) {
		return fmt.Errorf("%w: cannot transition from %s to %s", ErrUnauthorizedTransition, sm.currentStage, target)
	}

	// Gate 1: Design -> Implement requires valid cryptographic human approval from an Architect or Lead.
	if sm.currentStage == StageDesignSolution && target == StageImplementCode {
		if len(sm.approvedManifest) == 0 {
			return fmt.Errorf("%w: cannot enter Step 4 with an empty approved file manifest", ErrEmptyManifest)
		}
		gate1Roles := []string{RolePrincipalArchitect, RoleEngineeringLead, RoleSecurityArchitect}
		if err := sm.verifyApprovalTokenLocked(token, sm.designHash, gate1Roles); err != nil {
			return err
		}
		// Atomic token consumption with state transition
		sm.usedTokens[token.TokenID] = struct{}{}
	}

	// Gate 2: Review -> PrepareRelease requires valid cryptographic human sign-off from Release Lead or Architect.
	if sm.currentStage == StageReviewChanges && target == StagePrepareRelease {
		gate2Roles := []string{RoleReleaseLead, RolePrincipalArchitect, RoleSecurityArchitect}
		if err := sm.verifyApprovalTokenLocked(token, sm.designHash, gate2Roles); err != nil {
			return err
		}
		// Atomic token consumption with state transition
		sm.usedTokens[token.TokenID] = struct{}{}
	}

	approverName := "SYSTEM"
	tokenID := "N/A"
	if token != nil {
		approverName = token.ApproverID
		tokenID = token.TokenID
	}

	sm.history = append(sm.history, TransitionRecord{
		FromStage:  sm.currentStage,
		ToStage:    target,
		Timestamp:  time.Now().UTC(),
		ApprovedBy: approverName,
		TokenID:    tokenID,
		Reason:     reason,
	})

	sm.currentStage = target
	return nil
}
