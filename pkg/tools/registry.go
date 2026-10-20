package tools

import (
	"fmt"

	"github.com/privora/privora/pkg/fsm"
	"github.com/privora/privora/pkg/storage"
)

// ToolType categorizes the operational capability of a tool.
type ToolType string

const (
	TypeReadOnly  ToolType = "READ_ONLY"
	TypeWrite     ToolType = "WRITE"
	TypeExecution ToolType = "EXECUTION"
	TypeRelease   ToolType = "RELEASE"
)

// Tool defines an invokable agent tool and its operational constraints.
type Tool struct {
	Name        string
	Description string
	Type        ToolType
	Stages      []fsm.Stage
}

// DefaultTools returns the standard suite of Privora tools and their stage bindings.
func DefaultTools() []Tool {
	return []Tool{
		{
			Name:        "view_file",
			Description: "Read the contents of a file within the authorized repository bounds.",
			Type:        TypeReadOnly,
			Stages:      []fsm.Stage{fsm.StageReadRepo, fsm.StageUnderstandArch, fsm.StageDesignSolution, fsm.StageImplementCode, fsm.StageVerifyResult, fsm.StageReviewChanges, fsm.StagePrepareRelease},
		},
		{
			Name:        "list_symbols",
			Description: "Extract AST symbol signatures and declarations from a file.",
			Type:        TypeReadOnly,
			Stages:      []fsm.Stage{fsm.StageReadRepo, fsm.StageUnderstandArch, fsm.StageDesignSolution, fsm.StageImplementCode, fsm.StageVerifyResult, fsm.StageReviewChanges},
		},
		{
			Name:        "trace_call_graph",
			Description: "Trace callers and callees for a specified function or interface.",
			Type:        TypeReadOnly,
			Stages:      []fsm.Stage{fsm.StageUnderstandArch, fsm.StageDesignSolution},
		},
		{
			Name:        "draft_design_spec",
			Description: "Draft or update the architectural solution design document.",
			Type:        TypeReadOnly,
			Stages:      []fsm.Stage{fsm.StageDesignSolution},
		},
		{
			Name:        "write_file",
			Description: "Write content to a file strictly within the approved manifest.",
			Type:        TypeWrite,
			Stages:      []fsm.Stage{fsm.StageImplementCode},
		},
		{
			Name:        "patch_file",
			Description: "Apply a targeted diff patch to an approved file.",
			Type:        TypeWrite,
			Stages:      []fsm.Stage{fsm.StageImplementCode},
		},
		{
			Name:        "run_sandbox_command",
			Description: "Execute a command (test, lint, build) inside an isolated non-networked container.",
			Type:        TypeExecution,
			Stages:      []fsm.Stage{fsm.StageVerifyResult},
		},
		{
			Name:        "generate_release_checklist",
			Description: "Generate a safe rollback and deployment validation checklist.",
			Type:        TypeRelease,
			Stages:      []fsm.Stage{fsm.StagePrepareRelease},
		},
	}
}

// Registry manages tool availability, tool execution, and enforces point-of-use permissions.
type Registry struct {
	tools map[string]Tool
	sm    *fsm.StateMachine
	fs    *storage.ScopedFileSystem
}

// NewRegistry creates a new tool registry bound to the given state machine and authorized filesystem.
func NewRegistry(sm *fsm.StateMachine) *Registry {
	r := &Registry{
		tools: make(map[string]Tool),
		sm:    sm,
		fs:    storage.NewScopedFileSystem(sm),
	}
	for _, t := range DefaultTools() {
		r.tools[t.Name] = t
	}
	return r
}

// GetAvailableTools returns all tools permitted in the current workflow stage.
func (r *Registry) GetAvailableTools() []Tool {
	currentStage := r.sm.CurrentStage()
	var available []Tool
	for _, t := range r.tools {
		for _, s := range t.Stages {
			if s == currentStage {
				available = append(available, t)
				break
			}
		}
	}
	return available
}

// IsToolPermitted checks if a tool is allowed in the current stage.
func (r *Registry) IsToolPermitted(toolName string) bool {
	t, ok := r.tools[toolName]
	if !ok {
		return false
	}
	currentStage := r.sm.CurrentStage()
	for _, s := range t.Stages {
		if s == currentStage {
			return true
		}
	}
	return false
}

// ValidateToolCall enforces stage permissions and file scope boundaries before execution.
func (r *Registry) ValidateToolCall(toolName string, targetPath string) error {
	if !r.IsToolPermitted(toolName) {
		return fmt.Errorf("%w: tool %q is prohibited in stage %s", fsm.ErrToolUnavailableForStage, toolName, r.sm.CurrentStage())
	}

	tool := r.tools[toolName]

	// Pre-execution scope enforcement for write tools
	if tool.Type == TypeWrite {
		if targetPath == "" {
			return fmt.Errorf("%w: write tools require a target file path", fsm.ErrOutOfScopeModification)
		}
		if !r.sm.IsFileInScope(targetPath) {
			return fmt.Errorf("%w: cannot write to %q, not in approved manifest", fsm.ErrOutOfScopeModification, targetPath)
		}
	}

	return nil
}

// ExecuteWriteFile performs both stage validation AND point-of-use filesystem authorization.
func (r *Registry) ExecuteWriteFile(targetPath string, content []byte) error {
	if err := r.ValidateToolCall("write_file", targetPath); err != nil {
		return err
	}
	// SEC-06 FIX: Point-of-use authorization enforced inside ScopedFileSystem
	return r.fs.WriteFile(targetPath, content, 0644)
}
