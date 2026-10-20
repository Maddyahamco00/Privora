package policy

import (
	"fmt"
	"github.com/privora/privora/pkg/fsm"
)

// ProvenanceTag categorizes the data classification and origin of an artifact.
type ProvenanceTag string

const (
	// ProvenanceTaintedRepo represents confidential, proprietary content derived from an authorized repository.
	ProvenanceTaintedRepo ProvenanceTag = "TAINTED_CONFIDENTIAL_REPO"

	// ProvenanceUntaintedSynthetic represents purely synthetic, non-repository general programming content.
	ProvenanceUntaintedSynthetic ProvenanceTag = "UNTAINTED_SYNTHETIC"
)

// Destination represents an inference target or network routing endpoint.
type Destination string

const (
	DestLocalInference  Destination = "LOCAL_INFERENCE_RUNTIME"
	DestEnterpriseVPC   Destination = "CUSTOMER_PRIVATE_VPC"
	DestExternalPublic  Destination = "EXTERNAL_PUBLIC_AI_PROVIDER"
)

// TaintedData encapsulates data with its security provenance classification.
type TaintedData struct {
	Source      string
	Description string
	Tag         ProvenanceTag
	Content     string
}

// NewRepoData creates a data payload explicitly marked as tainted confidential repository context.
func NewRepoData(source string, content string) TaintedData {
	return TaintedData{
		Source:  source,
		Tag:     ProvenanceTaintedRepo,
		Content: content,
	}
}

// ValidateEgress enforces the Zero-Leakage Policy: tainted repository data cannot be transmitted externally.
func ValidateEgress(data TaintedData, target Destination) error {
	if data.Tag == ProvenanceTaintedRepo {
		if target == DestExternalPublic {
			return fmt.Errorf("%w: attempt to transmit %s (%s) to %s blocked",
				fsm.ErrTaintedDataEgressBlocked, data.Source, data.Tag, target)
		}
	}
	return nil
}
