package report

import "fmt"

// Scan stages exposed in reports. Only ScanStageCompleted is evidence that a
// scan covered the requested source completely.
const (
	ScanStageCompleted = "completed"
	ScanStagePartial   = "partial"
)

// ScanMetadata is the scan-wide identity attached to findings when a report
// is written. It keeps HEAD, revision range, generation, source and completion
// stage together instead of allowing a report to combine values from different
// attempts.
type ScanMetadata struct {
	Head           string
	CommitRange    string
	ScanGeneration string
	ScanStage      string
	ScanComplete   bool
	ScanSource     string
}

// MetadataReporter is implemented by reporters that can attach scan metadata
// without changing the legacy Reporter contract.
type MetadataReporter interface {
	SetMetadata(metadata ScanMetadata)
}

// Apply stamps the scan-wide identity on a finding. Non-empty metadata wins
// over per-finding values so a report can never mix HEAD, range, generation or
// completion stage from different attempts.
func (m ScanMetadata) Apply(finding *Finding) {
	if finding == nil {
		return
	}
	if m.Head != "" {
		finding.Head = m.Head
	}
	if m.CommitRange != "" {
		finding.CommitRange = m.CommitRange
	}
	if m.ScanGeneration != "" {
		finding.ScanGeneration = m.ScanGeneration
	}
	if m.ScanStage != "" {
		finding.ScanStage = m.ScanStage
		finding.ScanComplete = m.ScanComplete
	} else if m.ScanComplete {
		finding.ScanComplete = true
	}
	if m.ScanSource != "" {
		finding.ScanSource = m.ScanSource
	}
}

// IsZero reports whether the metadata would leave the legacy report shape
// unchanged.
func (m ScanMetadata) IsZero() bool {
	return m.Head == "" &&
		m.CommitRange == "" &&
		m.ScanGeneration == "" &&
		m.ScanStage == "" &&
		!m.ScanComplete &&
		m.ScanSource == ""
}

func applyScanMetadata(findings []Finding, metadata ScanMetadata) []Finding {
	if metadata.IsZero() {
		return findings
	}

	out := make([]Finding, len(findings))
	for i, finding := range findings {
		metadata.Apply(&finding)
		out[i] = finding
	}
	return out
}

func validateScanMetadata(findings []Finding, metadata ScanMetadata) error {
	if metadata.ScanGeneration == "" {
		return nil
	}
	for _, finding := range findings {
		if finding.ScanGeneration != "" && finding.ScanGeneration != metadata.ScanGeneration {
			return fmt.Errorf("finding %q belongs to scan generation %q, not %q",
				finding.Fingerprint, finding.ScanGeneration, metadata.ScanGeneration)
		}
	}
	return nil
}
