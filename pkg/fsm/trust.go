package fsm

import (
	"crypto/ed25519"
	"fmt"
	"sync"
)

// Standard privileged roles required for workflow approval gates.
const (
	RolePrincipalArchitect = "Principal Architect"
	RoleEngineeringLead    = "Engineering Lead"
	RoleSecurityArchitect  = "Security Architect"
	RoleReleaseLead        = "Release Lead"
)

// TrustedApprover represents an explicitly provisioned human authorization identity.
type TrustedApprover struct {
	ApproverID string
	PublicKey  ed25519.PublicKey
	Roles      map[string]struct{}
	Revoked    bool
}

// KeyRegistry acts as the authoritative trust store for approver public keys and assigned roles.
type KeyRegistry struct {
	mu        sync.RWMutex
	approvers map[string]*TrustedApprover
}

// NewKeyRegistry initializes an empty authoritative key registry.
// Production keys must be provisioned explicitly; no keys are trusted implicitly.
func NewKeyRegistry() *KeyRegistry {
	return &KeyRegistry{
		approvers: make(map[string]*TrustedApprover),
	}
}

// RegisterApprover provisions a public key, binding it to an approver identity and allowed roles.
func (kr *KeyRegistry) RegisterApprover(approverID string, pubKey ed25519.PublicKey, roles []string) error {
	kr.mu.Lock()
	defer kr.mu.Unlock()

	if approverID == "" {
		return fmt.Errorf("approverID cannot be empty")
	}
	if len(pubKey) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: invalid ed25519 public key size %d", ErrInvalidSignature, len(pubKey))
	}
	if len(roles) == 0 {
		return fmt.Errorf("at least one role must be assigned to approver %q", approverID)
	}

	roleMap := make(map[string]struct{})
	for _, r := range roles {
		roleMap[r] = struct{}{}
	}

	kr.approvers[approverID] = &TrustedApprover{
		ApproverID: approverID,
		PublicKey:  pubKey,
		Roles:      roleMap,
		Revoked:    false,
	}
	return nil
}

// RevokeApprover immediately invalidates all future approval tokens from this approver.
func (kr *KeyRegistry) RevokeApprover(approverID string) error {
	kr.mu.Lock()
	defer kr.mu.Unlock()

	approver, ok := kr.approvers[approverID]
	if !ok {
		return fmt.Errorf("%w: cannot revoke unknown approver %q", ErrUntrustedApproverKey, approverID)
	}
	approver.Revoked = true
	return nil
}

// GetApprover returns a copy of the trusted approver profile, or an error if untrusted or revoked.
func (kr *KeyRegistry) GetApprover(approverID string) (*TrustedApprover, error) {
	kr.mu.RLock()
	defer kr.mu.RUnlock()

	approver, ok := kr.approvers[approverID]
	if !ok {
		return nil, fmt.Errorf("%w: approver %q not provisioned in key registry", ErrUntrustedApproverKey, approverID)
	}
	if approver.Revoked {
		return nil, fmt.Errorf("%w: approver %q key has been revoked", ErrRevokedApproverKey, approverID)
	}

	// Return defensive copy
	rolesCopy := make(map[string]struct{}, len(approver.Roles))
	for r := range approver.Roles {
		rolesCopy[r] = struct{}{}
	}
	pubKeyCopy := make(ed25519.PublicKey, len(approver.PublicKey))
	copy(pubKeyCopy, approver.PublicKey)

	return &TrustedApprover{
		ApproverID: approver.ApproverID,
		PublicKey:  pubKeyCopy,
		Roles:      rolesCopy,
		Revoked:    approver.Revoked,
	}, nil
}

// HasRole checks whether an approver is provisioned and authorized for the specified role.
func (kr *KeyRegistry) HasRole(approverID string, role string) bool {
	kr.mu.RLock()
	defer kr.mu.RUnlock()

	approver, ok := kr.approvers[approverID]
	if !ok || approver.Revoked {
		return false
	}
	_, has := approver.Roles[role]
	return has
}
