package fsm

import "fmt"

// Stage represents one of the mandatory eight stages in the Privora workflow.
type Stage int

const (
	StageUninitialized Stage = iota
	// Step 1: Read the existing repository (read-only).
	StageReadRepo
	// Step 2: Understand the architecture and business rules.
	StageUnderstandArch
	// Step 3: Design the solution and obtain human approval.
	StageDesignSolution
	// Step 4: Implement approved code changes within authorized boundaries.
	StageImplementCode
	// Step 5: Verify results via sandboxed tests, linters, builds, and security checks.
	StageVerifyResult
	// Step 6: Review diffs, evidence, and remaining risks; require human sign-off.
	StageReviewChanges
	// Step 7: Prepare for safe release (migrations, checklists, rollback plans).
	StagePrepareRelease
	// Step 8: Deploy safely through approved organizational release pipeline.
	StageDeploySafely
	// StageCompleted indicates the workflow reached terminal success.
	StageCompleted
	// StageAborted indicates the workflow was rejected or terminated.
	StageAborted
)

// String returns the canonical human-readable name of the stage.
func (s Stage) String() string {
	switch s {
	case StageUninitialized:
		return "Uninitialized"
	case StageReadRepo:
		return "Step 1: Read Existing Repository"
	case StageUnderstandArch:
		return "Step 2: Understand Architecture"
	case StageDesignSolution:
		return "Step 3: Design Solution"
	case StageImplementCode:
		return "Step 4: Implement Code"
	case StageVerifyResult:
		return "Step 5: Verify Result"
	case StageReviewChanges:
		return "Step 6: Review Changes"
	case StagePrepareRelease:
		return "Step 7: Prepare Safe Release"
	case StageDeploySafely:
		return "Step 8: Deploy Safely"
	case StageCompleted:
		return "Workflow Completed"
	case StageAborted:
		return "Workflow Aborted"
	default:
		return fmt.Sprintf("Unknown Stage (%d)", int(s))
	}
}

// StageNumber returns the formal 1-8 step index, or 0 if not a numbered stage.
func (s Stage) StageNumber() int {
	if s >= StageReadRepo && s <= StageDeploySafely {
		return int(s)
	}
	return 0
}

// IsReadOnly returns true if the stage strictly forbids write operations to repository files.
func (s Stage) IsReadOnly() bool {
	switch s {
	case StageReadRepo, StageUnderstandArch, StageDesignSolution, StageVerifyResult, StageReviewChanges, StagePrepareRelease, StageDeploySafely:
		return true
	case StageImplementCode:
		return false
	default:
		return true
	}
}

// RequiresHumanApproval returns true if transitioning to the next stage requires explicit human sign-off.
func (s Stage) RequiresHumanApproval() bool {
	return s == StageDesignSolution || s == StageReviewChanges
}
