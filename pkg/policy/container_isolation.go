package policy

import (
	"fmt"
	"strings"

	"github.com/privora/privora/pkg/fsm"
)

// ContainerNetworkMode defines the container network isolation configuration.
type ContainerNetworkMode string

const (
	// NetworkModeNone disables all container networking (loopback only). Mandatory for Step 5 (Verify).
	NetworkModeNone ContainerNetworkMode = "none"

	// NetworkModeHost shares host network stack (STRICTLY PROHIBITED for untrusted code execution).
	NetworkModeHost ContainerNetworkMode = "host"

	// NetworkModeBridge provides virtual bridge network (PROHIBITED for sensitive verification).
	NetworkModeBridge ContainerNetworkMode = "bridge"
)

// ContainerSecurityConfig specifies the isolation requirements for sandboxed tool and test execution.
type ContainerSecurityConfig struct {
	Image         string
	NetworkMode   ContainerNetworkMode
	BindMounts    []string
	ReadOnlyRoot  bool
	DropAllCaps   bool
	MemoryLimitMB int
}

// ValidateContainerSecurity validates that an execution container satisfies Privora's sandboxing policy.
func ValidateContainerSecurity(cfg ContainerSecurityConfig) error {
	if cfg.NetworkMode != NetworkModeNone {
		return fmt.Errorf("%w: container network mode %q rejected; Step 5 verification requires %q",
			fsm.ErrInsecureContainerConfig, cfg.NetworkMode, NetworkModeNone)
	}

	// Verify that sensitive host credential directories are never mounted into the container
	sensitivePaths := []string{".ssh", ".aws", ".gnupg", ".docker", "/etc/shadow", "/etc/passwd"}
	for _, mount := range cfg.BindMounts {
		lower := strings.ToLower(mount)
		for _, sensitive := range sensitivePaths {
			if strings.Contains(lower, sensitive) {
				return fmt.Errorf("insecure bind mount %q: access to sensitive host directory %q is prohibited",
					mount, sensitive)
			}
		}
	}

	return nil
}
