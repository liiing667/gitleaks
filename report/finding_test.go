package report

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRedactSetsSecretHash(t *testing.T) {
	finding := Finding{
		Match:  "awsToken := \"AKIALALEMEL33243OLIA\"",
		Secret: "AKIALALEMEL33243OLIA",
		Line:   "awsToken := \"AKIALALEMEL33243OLIA\"",
	}

	finding.Redact(100)

	assert.Equal(t, "REDACTED", finding.Secret)
	assert.Equal(t, HashSecret("AKIALALEMEL33243OLIA"), finding.SecretHash)
	assert.Len(t, finding.SecretHash, 64)
	assert.NotContains(t, finding.SecretHash, "AKIALALEMEL33243OLIA")
	assert.NotContains(t, finding.Match, "AKIALALEMEL33243OLIA")
	assert.NotContains(t, finding.Line, "AKIALALEMEL33243OLIA")
}

func TestRedactPartialKeepsSecretHashStable(t *testing.T) {
	secret := "AKIALALEMEL33243OLIA"

	full := Finding{Secret: secret, Match: secret}
	full.Redact(100)

	partial := Finding{Secret: secret, Match: secret}
	partial.Redact(20)

	assert.Equal(t, full.SecretHash, partial.SecretHash)
	assert.True(t, strings.HasPrefix(partial.Secret, "AKIA"))
}

func TestRedactDoesNotOverwriteExistingHash(t *testing.T) {
	finding := Finding{
		Secret:     "AKIALALEMEL33243OLIA",
		Match:      "AKIALALEMEL33243OLIA",
		SecretHash: "existing-hash",
	}

	finding.Redact(100)

	assert.Equal(t, "existing-hash", finding.SecretHash)
}

func TestHashSecret(t *testing.T) {
	assert.Equal(t, "", HashSecret(""))

	first := HashSecret("AKIALALEMEL33243OLIA")
	second := HashSecret("AKIALALEMEL33243OLIA")
	rotated := HashSecret("AKIALALEMEL33243OKIA")

	assert.Equal(t, first, second)
	assert.NotEqual(t, first, rotated)
	assert.Len(t, first, 64)
}

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
			f.Redact(100)
			assert.Equal(t, "REDACTED", f.Secret)
			assert.Equal(t, "line containing REDACTED", f.Match)
		}
	}
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
