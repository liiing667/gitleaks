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
	// secret. It is populated when a finding is redacted so that a redacted
	// baseline can still distinguish the original value from a rotated value.
	SecretHash string `json:",omitempty"`

	// RedactionSource records that Secret, Match, and Line were produced by
	// gitleaks redaction. It is intentionally empty for unredacted findings.
	RedactionSource string `json:",omitempty"`

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

	// Fragment used for multi-part rule checking, CEL filtering,
	// and eventually ML validation
	Fragment *sources.Fragment `json:",omitempty"`

	// TODO keeping private for now to during experimental phase
	requiredFindings []*RequiredFinding
}

const (
	// RedactionSourceRedact identifies the built-in --redact path.
	RedactionSourceRedact = "redact"
)

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
	if percent == 0 || f == nil {
		return
	}

	// Redaction is one-way. Avoid re-masking an already redacted finding:
	// serializing the same finding again (or loading and re-emitting a
	// baseline) must not truncate the value a second time.
	if f.RedactionSource != "" {
		if percent >= 100 && f.Secret != "" && f.Secret != "REDACTED" {
			f.Line = replaceSecret(f.Line, f.Secret, "REDACTED")
			f.Match = replaceSecret(f.Match, f.Secret, "REDACTED")
			if f.Fragment != nil {
				f.Fragment.Raw = replaceSecret(f.Fragment.Raw, f.Secret, "REDACTED")
				if len(f.Fragment.Bytes) > 0 {
					f.Fragment.Bytes = []byte(replaceSecret(string(f.Fragment.Bytes), f.Secret, "REDACTED"))
				}
			}
			f.Secret = "REDACTED"
			for _, aux := range f.requiredFindings {
				if aux == nil || aux.Secret == "" {
					continue
				}
				aux.Line = replaceSecret(aux.Line, aux.Secret, "REDACTED")
				aux.Match = replaceSecret(aux.Match, aux.Secret, "REDACTED")
				aux.Secret = "REDACTED"
			}
		}
		return
	}

	rawSecret := f.Secret
	if rawSecret != "" && f.SecretHash == "" && !IsRedactedValue(rawSecret) {
		f.SecretHash = HashSecret(rawSecret)
	}

	secret := maskSecret(f.Secret, percent)
	if percent >= 100 {
		secret = "REDACTED"
	}
	if rawSecret != "" {
		f.Line = replaceSecret(f.Line, rawSecret, secret)
		f.Match = replaceSecret(f.Match, rawSecret, secret)
		if f.Fragment != nil {
			f.Fragment.Raw = replaceSecret(f.Fragment.Raw, rawSecret, secret)
			if len(f.Fragment.Bytes) > 0 {
				f.Fragment.Bytes = []byte(replaceSecret(string(f.Fragment.Bytes), rawSecret, secret))
			}
		}
	}
	f.Secret = secret

	redacted := rawSecret != ""
	for _, aux := range f.requiredFindings {
		if aux == nil || aux.Secret == "" {
			continue
		}
		auxSecret := maskSecret(aux.Secret, percent)
		if percent >= 100 {
			auxSecret = "REDACTED"
		}
		aux.Line = replaceSecret(aux.Line, aux.Secret, auxSecret)
		aux.Match = replaceSecret(aux.Match, aux.Secret, auxSecret)
		aux.Secret = auxSecret
		redacted = true
	}

	if redacted {
		f.RedactionSource = RedactionSourceRedact
	}
}

func replaceSecret(value, secret, redacted string) string {
	if value == "" || secret == "" {
		return value
	}
	return strings.ReplaceAll(value, secret, redacted)
}

// HashSecret returns the SHA-256 hex digest of a secret. The digest is stable
// across processes and hosts, which lets redacted findings and baselines use it
// as an identity without persisting the plaintext value.
//
// The optional match argument produces a context-bound digest for callers that
// need to distinguish identical secrets in different contexts. Findings use
// the plain secret digest so rule and match formatting changes do not change
// their identity.
func HashSecret(secret string, match ...string) string {
	if secret == "" {
		return ""
	}

	hasher := sha256.New()
	_, _ = hasher.Write([]byte(secret))
	if len(match) > 0 {
		_, _ = hasher.Write([]byte{0})
		_, _ = hasher.Write([]byte(match[0]))
	}
	return hex.EncodeToString(hasher.Sum(nil))
}

// IsRedactedValue reports whether a persisted value was produced by a
// gitleaks redaction mode, including legacy asterisk masks.
func IsRedactedValue(value string) bool {
	return value == "REDACTED" ||
		strings.HasSuffix(value, "...") ||
		(value != "" && strings.Trim(value, "*") == "")
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
