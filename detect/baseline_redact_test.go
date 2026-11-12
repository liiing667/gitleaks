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

const redactBaselinePath = "../testdata/baseline/redact/"

// newRedactDetector builds a Detector using the fixed "simple" rules and the
// given redaction percentage.
func newRedactDetector(t *testing.T, redact uint) *Detector {
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

	detector := NewDetector(cfg)
	detector.Redact = redact
	return detector
}

func detectRedactFixture(t *testing.T, detector *Detector, name string) []report.Finding {
	t.Helper()

	target := filepath.Join(redactBaselinePath, name)
	paths, err := sources.DirectoryTargets(target, detector.Sema, true, detector.Config.Allowlists)
	require.NoError(t, err)

	findings, err := detector.DetectFiles(paths)
	require.NoError(t, err)
	return findings
}

// TestRedactedBaselineDetectsRotatedSecret verifies the core fix: a redacted
// baseline carrying a SecretHash still suppresses an unchanged secret, but a
// rotated secret at the same rule/file/line is reported as new even though
// every redacted field looks identical.
func TestRedactedBaselineDetectsRotatedSecret(t *testing.T) {

	originalHash := "d3f1fdd46da999d0cf69893e50e0b505c7f4db17b267f0767db992072e065470"
	rotatedHash := "0751d1d3b2f2e361293f7d3352838ed1b87222f215bad425da165ad0ab972e9c"

	t.Run("unchanged secret is suppressed by redacted baseline", func(t *testing.T) {
		detector := newRedactDetector(t, 100)
		baseline, err := LoadBaseline(filepath.Join(redactBaselinePath, "baseline_redacted.json"))
		require.NoError(t, err)
		detector.baseline = baseline

		findings := detectRedactFixture(t, detector, "secret.go")
		assert.Empty(t, findings)
	})

	t.Run("rotated secret is reported despite identical redacted fields", func(t *testing.T) {
		detector := newRedactDetector(t, 100)
		baseline, err := LoadBaseline(filepath.Join(redactBaselinePath, "baseline_rotated.json"))
		require.NoError(t, err)
		detector.baseline = baseline

		findings := detectRedactFixture(t, detector, "secret.go")
		require.Len(t, findings, 1)

		finding := findings[0]
		assert.Equal(t, "aws-access-key", finding.RuleID)
		assert.Equal(t, "REDACTED", finding.Secret)
		assert.Equal(t, "REDACTED", finding.Match)
		assert.Equal(t, originalHash, finding.SecretHash)
		assert.NotEqual(t, rotatedHash, finding.SecretHash)
		assert.Equal(t, 4, finding.StartLine)
		assert.Equal(t, 4, finding.EndLine)
		assert.Equal(t, 16, finding.StartColumn)
		assert.Equal(t, 35, finding.EndColumn)
	})
}

// TestRedactedBaselineCompatibility covers baselines produced before the
// SecretHash field existed as well as unredacted baselines.
func TestRedactedBaselineCompatibility(t *testing.T) {

	tests := map[string]struct {
		baselineFile string
		expectCount  int
	}{
		"legacy redacted baseline keeps permissive behaviour": {
			baselineFile: "baseline_legacy_redacted.json",
			expectCount:  0,
		},
		"unredacted baseline with same value suppresses finding": {
			baselineFile: "baseline_unredacted.json",
			expectCount:  0,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			detector := newRedactDetector(t, 100)
			baseline, err := LoadBaseline(filepath.Join(redactBaselinePath, tt.baselineFile))
			require.NoError(t, err)
			detector.baseline = baseline

			findings := detectRedactFixture(t, detector, "secret.go")
			assert.Len(t, findings, tt.expectCount)
		})
	}
}

// TestUnredactedBaselineStillComparesPlaintext ensures non-redacted scans
// keep comparing Match/Secret exactly and detect a rotated value.
func TestUnredactedBaselineStillComparesPlaintext(t *testing.T) {

	t.Run("same value suppressed without redaction", func(t *testing.T) {
		detector := newRedactDetector(t, 0)
		baseline, err := LoadBaseline(filepath.Join(redactBaselinePath, "baseline_unredacted.json"))
		require.NoError(t, err)
		detector.baseline = baseline

		findings := detectRedactFixture(t, detector, "secret.go")
		assert.Empty(t, findings)
	})

	t.Run("rotated value reported without redaction", func(t *testing.T) {
		detector := newRedactDetector(t, 0)
		baseline, err := LoadBaseline(filepath.Join(redactBaselinePath, "baseline_rotated.json"))
		require.NoError(t, err)
		detector.baseline = baseline

		findings := detectRedactFixture(t, detector, "secret.go")
		require.Len(t, findings, 1)
		assert.Equal(t, "AKIALALEMEL33243OLIA", findings[0].Secret)
		assert.Empty(t, findings[0].SecretHash)
	})
}

// TestRedactedBaselineLineMovement ensures line/column metadata remains part
// of the match: moving the secret to a different line must surface it even
// when the value hash is unchanged.
func TestRedactedBaselineLineMovement(t *testing.T) {

	t.Run("moved secret is not suppressed", func(t *testing.T) {
		detector := newRedactDetector(t, 100)
		baseline, err := LoadBaseline(filepath.Join(redactBaselinePath, "baseline_moved_line.json"))
		require.NoError(t, err)
		detector.baseline = baseline

		findings := detectRedactFixture(t, detector, "secret_moved.go")
		require.Len(t, findings, 1)
		assert.Equal(t, 5, findings[0].StartLine)
		assert.Equal(t, 16, findings[0].StartColumn)
		assert.Equal(t, 35, findings[0].EndColumn)
	})

	t.Run("unmoved secret keeps exact location", func(t *testing.T) {
		detector := newRedactDetector(t, 100)
		baseline, err := LoadBaseline(filepath.Join(redactBaselinePath, "baseline_redacted.json"))
		require.NoError(t, err)
		detector.baseline = baseline

		findings := detectRedactFixture(t, detector, "secret.go")
		assert.Empty(t, findings)
	})
}

// TestRedactedBaselineCRLF ensures CRLF input is scanned at the exact same
// line/column as LF input and that the redacted hash is stable across line
// endings, so CRLF handling does not regress.
func TestRedactedBaselineCRLF(t *testing.T) {

	detector := newRedactDetector(t, 100)
	baseline, err := LoadBaseline(filepath.Join(redactBaselinePath, "baseline_redacted.json"))
	require.NoError(t, err)
	detector.baseline = baseline

	findings := detectRedactFixture(t, detector, "secret_crlf.go")
	require.Len(t, findings, 1)

	finding := findings[0]
	assert.Equal(t, 4, finding.StartLine)
	assert.Equal(t, 4, finding.EndLine)
	assert.Equal(t, 16, finding.StartColumn)
	assert.Equal(t, 35, finding.EndColumn)
	assert.Equal(t, "d3f1fdd46da999d0cf69893e50e0b505c7f4db17b267f0767db992072e065470", finding.SecretHash)
	assert.NotContains(t, finding.Match, "\r")
	assert.Equal(t, "REDACTED", finding.Secret)
}

// TestRedactedReportContainsHashNotPlaintext serialises a redacted scan and
// asserts the baseline-ready JSON keeps the hash while never leaking the
// plaintext secret.
func TestRedactedReportContainsHashNotPlaintext(t *testing.T) {

	detector := newRedactDetector(t, 100)
	findings := detectRedactFixture(t, detector, "secret.go")
	require.Len(t, findings, 1)

	raw, err := json.Marshal(findings)
	require.NoError(t, err)

	serialized := string(raw)
	assert.Contains(t, serialized, `"SecretHash":"d3f1fdd46da999d0cf69893e50e0b505c7f4db17b267f0767db992072e065470"`)
	assert.Contains(t, serialized, `"Secret":"REDACTED"`)
	assert.NotContains(t, serialized, "AKIALALEMEL33243OLIA")
}

// TestUnredactedReportOmitsHash ensures non-redacted JSON output is
// unchanged and does not gain the new field.
func TestUnredactedReportOmitsHash(t *testing.T) {

	detector := newRedactDetector(t, 0)
	findings := detectRedactFixture(t, detector, "secret.go")
	require.Len(t, findings, 1)

	raw, err := json.Marshal(findings)
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "SecretHash")
	assert.Contains(t, string(raw), "AKIALALEMEL33243OLIA")

	// guard against accidental fixture deletion
	_, err = os.Stat(filepath.Join(redactBaselinePath, "secret_crlf.go"))
	require.NoError(t, err)
}
