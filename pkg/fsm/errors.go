package fsm

import "errors"

var (
	// ErrUnauthorizedTransition indicates an attempted state transition that violates the 8-step workflow sequence.
	ErrUnauthorizedTransition = errors.New("unauthorized workflow stage transition")

	// ErrApprovalRequired indicates a stage transition requires explicit human approval.
	ErrApprovalRequired = errors.New("transition blocked: explicit human approval token required")

	// ErrInvalidApprovalToken indicates an approval token is malformed, expired, or invalid.
	ErrInvalidApprovalToken = errors.New("invalid or unverified human approval token")

	// ErrToolUnavailableForStage indicates a tool call is prohibited in the current workflow stage.
	ErrToolUnavailableForStage = errors.New("tool unavailable for current workflow stage")

	// ErrOutOfScopeModification indicates an attempt to modify or create a file not included in the approved manifest.
	ErrOutOfScopeModification = errors.New("modification rejected: target file is outside the approved design manifest")

	// ErrTaintedDataEgressBlocked indicates an attempt to route confidential repository-derived data to an unapproved external destination.
	ErrTaintedDataEgressBlocked = errors.New("security violation: repository-tainted data cannot be routed to external destination")

	// ErrUnauthorizedStageForManifestMutation indicates an attempt to alter the approved manifest outside Step 3 (Design).
	ErrUnauthorizedStageForManifestMutation = errors.New("manifest mutation rejected: manifest can only be defined or updated during Step 3 (Design Solution)")

	// ErrDesignHashMismatch indicates the approval token artifact hash does not match the approved design hash.
	ErrDesignHashMismatch = errors.New("cryptographic verification failed: approval token artifact hash does not match active design hash")

	// ErrSessionMismatch indicates the approval token was created for a different workflow session.
	ErrSessionMismatch = errors.New("replay attack detected: approval token belongs to a different workflow session")

	// ErrTokenExpired indicates the approval token timestamp has exceeded the maximum allowable age.
	ErrTokenExpired = errors.New("approval token expired: timestamp exceeds maximum token validity window")

	// ErrTokenReplayed indicates the approval token has already been used to authorize a transition.
	ErrTokenReplayed = errors.New("replay attack detected: approval token has already been consumed")

	// ErrInvalidSignature indicates the cryptographic signature on the approval token failed verification.
	ErrInvalidSignature = errors.New("cryptographic verification failed: digital signature is invalid for the specified public key")

	// ErrPathEscapesRoot indicates an attempt to access or modify a file outside the repository root.
	ErrPathEscapesRoot = errors.New("path traversal rejected: target path resolves outside authorized repository root")

	// ErrSymlinkEscape indicates a path resolves through a symlink pointing outside the repository root.
	ErrSymlinkEscape = errors.New("symlink traversal rejected: target path traverses a symlink escaping repository root")

	// ErrEmptyManifest indicates an attempt to enter Step 4 with zero approved files.
	ErrEmptyManifest = errors.New("empty manifest rejected: cannot enter Step 4 without at least one approved file")

	// ErrUntrustedApproverKey indicates the approver is not registered in the authoritative key registry.
	ErrUntrustedApproverKey = errors.New("untrusted approver: public key is not registered in authoritative key registry")

	// ErrRevokedApproverKey indicates the approver's public key has been revoked.
	ErrRevokedApproverKey = errors.New("revoked approver: public key has been revoked")

	// ErrUnauthorizedRole indicates the approver does not hold an authorized role for this approval gate.
	ErrUnauthorizedRole = errors.New("role authorization failed: approver does not hold an authorized role for this stage")

	// ErrInsecureContainerConfig indicates a container configuration permits network access during isolated verification.
	ErrInsecureContainerConfig = errors.New("insecure container configuration: verification containers must have network set to 'none'")
)
