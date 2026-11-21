package src

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/zricethezav/gitleaks/v8/report"
)

func TestLoadCoverageRoundTrip(t *testing.T) {
	reportPath := filepath.Join(t.TempDir(), "coverage.json")

	findings := []report.Finding{
		{
			RuleID:      "test-secret",
			Description: "test secret",
			File:        "archive.zip!inner.txt",
			Secret:      "s3cr3t",
			Match:       `secret = "s3cr3t"`,
			StartLine:   1,
			EndLine:     1,
		},
		{
			RuleID:      "test-secret",
			Description: "test secret",
			File:        "archive.zip!inner.txt",
			Secret:      "oth3r",
			Match:       `secret = "oth3r"`,
			StartLine:   2,
			EndLine:     2,
		},
		{
			RuleID:      "test-secret",
			Description: "test secret",
			File:        "plain.txt",
			Secret:      "s3cr3t",
			Match:       `secret = "s3cr3t"`,
			StartLine:   1,
			EndLine:     1,
		},
	}
	require.NoError(t, report.WriteFile(reportPath, &report.JsonReporter{}, findings))

	coverage, err := LoadCoverage(reportPath)
	require.NoError(t, err)

	// Member paths are surfaced exactly as users see them in the report.
	require.Equal(t, []string{"archive.zip!inner.txt", "plain.txt"}, coverage.Members())

	// A finding evidenced by the report is covered; a finding naming a
	// different member is not.
	require.True(t, coverage.Covers(findings[0]))
	require.False(t, coverage.Covers(report.Finding{
		RuleID:      "test-secret",
		Description: "test secret",
		File:        "archive.zip!other.txt",
		Secret:      "s3cr3t",
		Match:       `secret = "s3cr3t"`,
		StartLine:   1,
		EndLine:     1,
	}))
}

func TestLoadCoverageMissingReport(t *testing.T) {
	_, err := LoadCoverage(filepath.Join(t.TempDir(), "missing.json"))
	require.Error(t, err)
}

func TestLoadCoverageInvalidReport(t *testing.T) {
	reportPath := filepath.Join(t.TempDir(), "broken.json")
	require.NoError(t, os.WriteFile(reportPath, []byte("{not json"), 0o600))

	_, err := LoadCoverage(reportPath)
	require.Error(t, err)
}
