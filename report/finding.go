package report

import (
	"crypto/sha256"
	"encoding/hex"
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

	// SecretHash is a stable, non-reversible identity for the unredacted
	// secret. It is persisted with redacted findings so a baseline can tell an
	// unchanged secret from a rotated one without storing the plaintext value.
	SecretHash string `json:",omitempty"`

	// File is the name of the file containing the finding
	File        string
	SymlinkFile string
	Commit      string
	Link        string `json:",omitempty"`

	// PreviousFile is the path the file was renamed from in the scanned
	// generation. PreviousFilePath is kept as an alias for source adapters
	// that use path-oriented names.
	PreviousFile     string `json:",omitempty"`
	PreviousFilePath string `json:",omitempty"`

	// OriginalFile is the oldest known name of the source. It lets baseline
	// matching follow more than one rename without treating unrelated files as
	// the same source.
	OriginalFile string `json:",omitempty"`

	// SourceGeneration identifies the immutable source revision that produced
	// the finding. ScanGeneration is an alias used by scan-oriented callers.
	// SourceCommit records the revision separately from Commit for consumers
	// that need both the finding's commit and its source generation.
	SourceGeneration string `json:",omitempty"`
	ScanGeneration   string `json:",omitempty"`
	SourceCommit     string `json:",omitempty"`

	// Entropy is the shannon entropy of Value
	Entropy float32

	Author  string
	Email   string
	Date    string
	Message string
	Tags    []string

	// unique identifier
	Fingerprint string

	// Fragment used for multi-part rule checking, CEL filtering,
	// and eventually ML validation
	Fragment *sources.Fragment `json:",omitempty"`

	// TODO keeping private for now to during experimental phase
	requiredFindings []*RequiredFinding
}

// HashSecret returns the hexadecimal SHA-256 digest of a secret. An optional
// match context can be supplied to produce a context-bound digest for legacy
// baselines.
func HashSecret(secret string, match ...string) string {
	if secret == "" {
		return ""
	}

	hasher := sha256.New()
	_, _ = hasher.Write([]byte(secret))
	if len(match) > 0 && match[0] != "" {
		_, _ = hasher.Write([]byte{0})
		_, _ = hasher.Write([]byte(match[0]))
	}
	return hex.EncodeToString(hasher.Sum(nil))
}

// IsRedactedValue reports whether a persisted value was produced by one of
// gitleaks' redaction modes.
func IsRedactedValue(value string) bool {
	return value == "REDACTED" ||
		strings.HasSuffix(value, "...") ||
		(value != "" && strings.Trim(value, "*") == "")
}

// Generation returns the immutable source generation recorded for the
// finding. Older reports have no explicit generation and fall back to Commit.
func (f Finding) Generation() string {
	switch {
	case f.SourceGeneration != "":
		return f.SourceGeneration
	case f.ScanGeneration != "":
		return f.ScanGeneration
	case f.SourceCommit != "":
		return f.SourceCommit
	default:
		return f.Commit
	}
}

// RenamedFrom returns the path recorded as the previous name of the file.
func (f Finding) RenamedFrom() string {
	if f.PreviousFile != "" {
		return f.PreviousFile
	}
	if f.PreviousFilePath != "" {
		return f.PreviousFilePath
	}
	return f.OriginalFile
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
	if f.Secret != "" && IsRedactedValue(f.Secret) {
		return
	}
	if f.Secret != "" {
		f.SecretHash = HashSecret(f.Secret)
	}

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
