package report

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRedact(t *testing.T) {
	tests := []struct {
		findings []Finding
		redact   bool
	}{
		{
			redact: true,
			findings: []Finding{
				{
					Match:  "line containing secret",
					Secret: "secret",
				},
			}},
	}
	for _, test := range tests {
		for _, f := range test.findings {
			finding := f
			f.Redact(100)
			assert.Equal(t, "REDACTED", f.Secret)
			assert.Equal(t, "line containing REDACTED", f.Match)
			assert.NotEmpty(t, f.SecretHash)
			assert.NotContains(t, f.SecretHash, "secret")
			// Redact must not recompute an existing hash, which keeps the
			// value stable across repeated/partial redaction.
			existing := f.SecretHash
			finding.Redact(50)
			assert.Equal(t, existing, finding.SecretHash)
		}
	}
}

func TestHashSecret(t *testing.T) {
	first := HashSecret("secret", "line containing secret")
	second := HashSecret("secret", "line containing secret")

	assert.Equal(t, 64, len(first))
	assert.Equal(t, first, second)

	rotated := HashSecret("rotated", "line containing rotated")
	assert.NotEqual(t, first, rotated)

	// A different match context with the same secret also differs, so the
	// hash tracks the full redacted value pair, not only the captured secret.
	otherMatch := HashSecret("secret", "other context secret")
	assert.NotEqual(t, first, otherMatch)
}

func TestMask(t *testing.T) {

	tests := map[string]struct {
		finding Finding
		percent uint
		expect  Finding
	}{
		"normal secret": {
			finding: Finding{Match: "line containing secret", Secret: "secret"},
			expect:  Finding{Match: "line containing se...", Secret: "se..."},
			percent: 75,
		},
		"empty secret": {
			finding: Finding{Match: "line containing", Secret: ""},
			expect:  Finding{Match: "line containing", Secret: ""},
			percent: 75,
		},
		"short secret": {
			finding: Finding{Match: "line containing", Secret: "ss"},
			expect:  Finding{Match: "line containing", Secret: "..."},
			percent: 75,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			f := test.finding
			e := test.expect
			f.Redact(test.percent)
			assert.Equal(t, e.Secret, f.Secret)
			assert.Equal(t, e.Match, f.Match)
		})
	}
}

func TestMaskSecret(t *testing.T) {

	tests := map[string]struct {
		secret  string
		percent uint
		expect  string
	}{
		"normal masking":  {secret: "secret", percent: 75, expect: "se..."},
		"high masking":    {secret: "secret", percent: 90, expect: "s..."},
		"low masking":     {secret: "secret", percent: 10, expect: "secre..."},
		"invalid masking": {secret: "secret", percent: 1000, expect: "..."},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			got := maskSecret(test.secret, test.percent)
			assert.Equal(t, test.expect, got)
		})
	}
}
