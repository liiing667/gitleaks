package report

import (
	"fmt"
	"math"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/zricethezav/gitleaks/v8/sources"
)

// Finding contains a whole bunch of information about a secret finding.
// Plenty of real estate in this bad boy so fillerup as needed.
type Finding struct {
	// Rule is the name of the rule that was matched
	RuleID      string
	Description string

	StartLine   int
	EndLine     int
	StartColumn int
	EndColumn   int

	Line string `json:"-"`

	Match string

	// Captured secret
	Secret string

	// File is the name of the file containing the finding
	File        string
	SymlinkFile string
	Commit      string
	Link        string `json:",omitempty"`

	// Entropy is the shannon entropy of Value
	Entropy float32

	Author  string
	Email   string
	Date    string
	Message string
	Tags    []string

	// unique identifier
	Fingerprint string

	// Head is the repository HEAD captured when the scan started. It is
	// populated for Git scans so a finding can be attributed to the exact
	// history snapshot that produced it, even if HEAD moves later.
	Head string `json:",omitempty"`

	// CommitRange is the revision range the scan was admitted with. For a
	// normal `gitleaks git` scan this is typically "--all"; for --log-opts it
	// is the effective (possibly shallow-clone adjusted) revision range.
	CommitRange string `json:",omitempty"`

	// ScanGeneration identifies one scan attempt. All findings and the report
	// stage from a scan share this value.
	ScanGeneration string `json:",omitempty"`

	// ScanStage is "completed" only when the source was exhausted normally.
	// Interrupted scans use "partial" and must not be treated as coverage.
	ScanStage string `json:",omitempty"`

	// ScanComplete is true only for completed scan findings. It is omitted for
	// the legacy, unscoped report shape.
	ScanComplete bool `json:",omitempty"`

	// ScanSource identifies the scanned repository or directory when known.
	ScanSource string `json:",omitempty"`

	// Fragment used for multi-part rule checking, CEL filtering,
	// and eventually ML validation
	Fragment *sources.Fragment `json:",omitempty"`

	// TODO keeping private for now to during experimental phase
	requiredFindings []*RequiredFinding
}

// CompletionStage returns the stage recorded for the scan that produced the
// finding. Empty means the finding came from a legacy or unwrapped source.
func (f Finding) CompletionStage() string {
	return f.ScanStage
}

// ScanHead returns the HEAD recorded for the scan.
func (f Finding) ScanHead() string {
	return f.Head
}

// Generation returns the scan generation recorded for the finding.
func (f Finding) Generation() string {
	return f.ScanGeneration
}

// IsCompleteScan reports whether the finding is positively marked as belonging
// to a completed scan. Legacy findings (with no scan metadata) return false.
func (f Finding) IsCompleteScan() bool {
	if f.ScanStage == ScanStagePartial {
		return false
	}
	return f.ScanComplete || f.ScanStage == ScanStageCompleted
}

type RequiredFinding struct {
	// contains a subset of the Finding fields
	// only used for reporting
	RuleID      string
	StartLine   int
	EndLine     int
	StartColumn int
	EndColumn   int
	Line        string `json:"-"`
	Match       string
	Secret      string
}

func (f *Finding) AddRequiredFindings(afs []*RequiredFinding) {
	if f.requiredFindings == nil {
		f.requiredFindings = make([]*RequiredFinding, 0)
	}
	f.requiredFindings = append(f.requiredFindings, afs...)
}

// Redact removes sensitive information from a finding.
func (f *Finding) Redact(percent uint) {
	secret := maskSecret(f.Secret, percent)
	if percent >= 100 {
		secret = "REDACTED"
	}
	f.Line = strings.ReplaceAll(f.Line, f.Secret, secret)
	f.Match = strings.ReplaceAll(f.Match, f.Secret, secret)
	f.Secret = secret
}

func maskSecret(secret string, percent uint) string {
	if percent > 100 {
		percent = 100
	}
	len := float64(len(secret))
	if len <= 0 {
		return secret
	}
	prc := float64(100 - percent)
	lth := int64(math.RoundToEven(len * prc / float64(100)))

	return secret[:lth] + "..."
}

func (f *Finding) PrintRequiredFindings() {
	if len(f.requiredFindings) == 0 {
		return
	}

	fmt.Printf("%-12s ", "Required:")

	// Create orange style for secrets
	orangeStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#bf9478"))

	for i, aux := range f.requiredFindings {
		auxSecret := strings.TrimSpace(aux.Secret)
		// Truncate long secrets for readability
		if len(auxSecret) > 40 {
			auxSecret = auxSecret[:37] + "..."
		}

		// Format: rule-id:line:secret
		if i == 0 {
			fmt.Printf("%s:%d:%s\n", aux.RuleID, aux.StartLine, orangeStyle.Render(auxSecret))
		} else {
			fmt.Printf("%-12s %s:%d:%s\n", "", aux.RuleID, aux.StartLine, orangeStyle.Render(auxSecret))
		}
	}
}
