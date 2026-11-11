package detect

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/report"
	"github.com/zricethezav/gitleaks/v8/sources"
)

const redactBaselinePath = "../testdata/baseline/redact"

const (
	originalSecret = "AKIALALEMEL33243OLIA"
	rotatedSecret  = "AKIALALEMEL33243OKIA"
)

func newSimpleConfigDetector(t *testing.T) *Detector {
	t.Helper()
	viper.Reset()
	viper.AddConfigPath(configPath)
	viper.SetConfigName("simple")
	viper.SetConfigType("toml")
	require.NoError(t, viper.ReadInConfig())

	var vc config.ViperConfig
	require.NoError(t, viper.Unmarshal(&vc))
	cfg, err := vc.Translate()
	require.NoError(t, err)
	cfg.Path = filepath.Join(configPath, "simple.toml")

	return NewDetector(cfg)
}

func detectFile(t *testing.T, detector *Detector, name string) []report.Finding {
	t.Helper()
	paths, err := sources.DirectoryTargets(
		filepath.Join(redactBaselinePath, name),
		detector.Sema,
		true,
		detector.Config.Allowlists,
	)
	require.NoError(t, err)
	findings, err := detector.DetectFiles(paths)
	require.NoError(t, err)
	return findings
}

// TestRedactedBaselineSecretRotation exercises the full detect -> redact ->
// baseline pipeline against fixed fixtures. A redacted baseline stores a
// digest of the secret instead of its plaintext, so rotating the secret on
// the same rule/file/line must surface as a new finding while unchanged
// secrets continue to be ignored.
func TestRedactedBaselineSecretRotation(t *testing.T) {
	// 1. Generate the redacted baseline from the v1 fixture.
	baselineDetector := newSimpleConfigDetector(t)
	baselineDetector.Redact = 100
	baselineFindings := detectFile(t, baselineDetector, "secrets_v1.go")
	require.Len(t, baselineFindings, 1)

	baselineFinding := baselineFindings[0]
	assert.Equal(t, "REDACTED", baselineFinding.Secret)
	assert.Equal(t, "REDACTED", baselineFinding.Match)
	assert.Equal(t, report.HashSecret(originalSecret), baselineFinding.SecretHash)
	assert.NotContains(t, baselineFinding.Line, originalSecret)

	// The baseline written to disk must never contain the plaintext secret.
	baselineFile := filepath.Join(t.TempDir(), "baseline.json")
	bytes, err := json.Marshal(baselineFindings)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(baselineFile, bytes, 0o600))
	assert.NotContains(t, string(bytes), originalSecret)
	assert.Contains(t, string(bytes), report.HashSecret(originalSecret))

	loadBaseline := func() []report.Finding {
		findings, loadErr := LoadBaseline(baselineFile)
		require.NoError(t, loadErr)
		return findings
	}

	// 2. The unchanged fixture is still ignored by the redacted baseline.
	unchangedDetector := newSimpleConfigDetector(t)
	unchangedDetector.Redact = 100
	require.NoError(t, unchangedDetector.AddBaseline(baselineFile, t.TempDir()))
	assert.Empty(t, detectFile(t, unchangedDetector, "secrets_v1.go"))

	// 3. Rotating the secret on the same line is reported as new.
	rotatedDetector := newSimpleConfigDetector(t)
	rotatedDetector.Redact = 100
	require.NoError(t, rotatedDetector.AddBaseline(baselineFile, t.TempDir()))
	rotatedFindings := detectFile(t, rotatedDetector, "secrets_v2_rotated.go")
	require.Len(t, rotatedFindings, 1)
	assert.Equal(t, "REDACTED", rotatedFindings[0].Secret)
	assert.Equal(t, report.HashSecret(rotatedSecret), rotatedFindings[0].SecretHash)
	assert.NotEqual(t, report.HashSecret(originalSecret), rotatedFindings[0].SecretHash)

	// 4. A line move with the same secret keeps the legacy baseline behavior:
	// line numbers are part of the identity, so a moved finding is reported as
	// new while its digest still proves the secret value did not change.
	movedDetector := newSimpleConfigDetector(t)
	movedDetector.Redact = 100
	require.NoError(t, movedDetector.AddBaseline(baselineFile, t.TempDir()))
	movedFindings := detectFile(t, movedDetector, "secrets_v3_moved.go")
	require.Len(t, movedFindings, 1)
	assert.Equal(t, 4, movedFindings[0].StartLine)
	assert.Equal(t, report.HashSecret(originalSecret), movedFindings[0].SecretHash)
	assert.Equal(t, "REDACTED", movedFindings[0].Secret)

	// 5. The digest round-trips through the JSON baseline.
	assert.Equal(t, report.HashSecret(originalSecret), loadBaseline()[0].SecretHash)
}

// TestRedactedBaselineLegacyCompat makes sure baselines produced before the
// secret digest existed keep working: both old redacted baselines and plain
// text baselines retain the previous matching behavior.
func TestRedactedBaselineLegacyCompat(t *testing.T) {
	t.Run("legacy redacted baseline without digest", func(t *testing.T) {
		legacyBaseline := []report.Finding{
			{
				RuleID:      "aws-access-key",
				Description: "AWS Access Key",
				StartLine:   3,
				EndLine:     3,
				StartColumn: 18,
				EndColumn:   37,
				Match:       "REDACTED",
				Secret:      "REDACTED",
				File:        filepath.Join(redactBaselinePath, "secrets_v2_rotated.go"),
				Entropy:     3.1464393,
				Tags:        []string{"key", "AWS"},
			},
		}

		detector := newSimpleConfigDetector(t)
		detector.Redact = 100
		detector.baseline = legacyBaseline
		assert.Empty(t, detectFile(t, detector, "secrets_v2_rotated.go"))
	})

	t.Run("plaintext baseline still matches the same secret", func(t *testing.T) {
		plaintextBaseline := []report.Finding{
			{
				RuleID:      "aws-access-key",
				Description: "AWS Access Key",
				StartLine:   3,
				EndLine:     3,
				StartColumn: 18,
				EndColumn:   37,
				Match:       originalSecret,
				Secret:      originalSecret,
				File:        filepath.Join(redactBaselinePath, "secrets_v1.go"),
				Entropy:     3.0841837,
				Tags:        []string{"key", "AWS"},
			},
		}

		detector := newSimpleConfigDetector(t)
		detector.Redact = 100
		detector.baseline = plaintextBaseline
		assert.Empty(t, detectFile(t, detector, "secrets_v1.go"))
	})
}

// TestRedactedBaselineCarriageReturns guards against regressions in line and
// column handling for CRLF files (including a standalone carriage return in
// the body) when redaction and baselines are enabled.
func TestRedactedBaselineCarriageReturns(t *testing.T) {
	detector := newSimpleConfigDetector(t)
	detector.Redact = 100
	findings := detectFile(t, detector, "secrets_v4_crlf.go")
	require.Len(t, findings, 1)

	finding := findings[0]
	assert.Equal(t, 3, finding.StartLine)
	assert.Equal(t, 3, finding.EndLine)
	assert.Equal(t, 18, finding.StartColumn)
	assert.Equal(t, 37, finding.EndColumn)
	assert.Equal(t, "REDACTED", finding.Secret)
	assert.Equal(t, report.HashSecret(originalSecret), finding.SecretHash)
	assert.NotContains(t, finding.Match, "\r")
	assert.NotContains(t, finding.Line, originalSecret)
}
