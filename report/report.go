package report

import (
	"io"
)

const (
	// https://cwe.mitre.org/data/definitions/798.html
	CWE              = "CWE-798"
	CWE_DESCRIPTION  = "Use of Hard-coded Credentials"
	StdoutReportPath = "-"
)

type Reporter interface {
	Write(w io.WriteCloser, findings []Finding) error
}

// ScanMetadata identifies the complete configuration generation used for a
// scan. It is attached to report findings so a report can be tied back to the
// exact rules and allowlists that produced it.
type ScanMetadata struct {
	ConfigVersion    string
	ConfigPath       string
	ScanSource       string
	ConfigGeneration uint64
}

// MetadataReporter is implemented by reporters that can attach scan metadata
// without changing the legacy Reporter contract.
type MetadataReporter interface {
	SetMetadata(metadata ScanMetadata)
}

// Apply fills any unset metadata fields on a finding.
func (m ScanMetadata) Apply(finding *Finding) {
	if finding == nil {
		return
	}
	if finding.ConfigVersion == "" {
		finding.ConfigVersion = m.ConfigVersion
	}
	if finding.ConfigPath == "" {
		finding.ConfigPath = m.ConfigPath
	}
	if finding.ScanSource == "" {
		finding.ScanSource = m.ScanSource
	}
	if finding.ConfigGeneration == 0 {
		finding.ConfigGeneration = m.ConfigGeneration
	}
}
