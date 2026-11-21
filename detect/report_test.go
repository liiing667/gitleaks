package detect

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zricethezav/gitleaks/v8/report"
)

// failingReporter always returns an error, simulating a report that cannot
// be written.
type failingReporter struct {
	err error
}

func (r failingReporter) Write(_ io.WriteCloser, _ []report.Finding) error {
	return r.err
}

func TestWriteReport(t *testing.T) {
	d, err := NewDetectorDefaultConfig()
	require.NoError(t, err)

	d.Reporter = &report.JsonReporter{}
	d.ReportPath = filepath.Join(t.TempDir(), "report.json")

	findings := []report.Finding{
		{
			RuleID: "test-rule",
			Secret: "a secret",
		},
	}
	require.NoError(t, d.WriteReport(findings))

	got, err := os.ReadFile(d.ReportPath)
	require.NoError(t, err)
	assert.Contains(t, string(got), `"RuleID": "test-rule"`)
}

func TestWriteReportEmptyFindings(t *testing.T) {
	// Zero findings must still produce a valid (empty) report.
	d, err := NewDetectorDefaultConfig()
	require.NoError(t, err)

	d.Reporter = &report.JsonReporter{}
	d.ReportPath = filepath.Join(t.TempDir(), "report.json")

	require.NoError(t, d.WriteReport([]report.Finding{}))

	got, err := os.ReadFile(d.ReportPath)
	require.NoError(t, err)
	assert.Equal(t, "[]\n", string(got))
}

func TestWriteReportError(t *testing.T) {
	d, err := NewDetectorDefaultConfig()
	require.NoError(t, err)

	dir := t.TempDir()
	d.Reporter = failingReporter{err: errors.New("cannot write report")}
	d.ReportPath = filepath.Join(dir, "report.json")

	// A report from a previous run must not be clobbered by a failed write.
	require.NoError(t, os.WriteFile(d.ReportPath, []byte("previous report"), 0o644))

	err = d.WriteReport([]report.Finding{{RuleID: "test-rule"}})
	require.Error(t, err)

	// The previous report is left untouched...
	got, err := os.ReadFile(d.ReportPath)
	require.NoError(t, err)
	assert.Equal(t, "previous report", string(got))

	// ...and no temporary files are left behind.
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "report.json", entries[0].Name())
}

func TestWriteReportNoReporter(t *testing.T) {
	// A detector without a configured reporter has nothing to write.
	d, err := NewDetectorDefaultConfig()
	require.NoError(t, err)

	require.NoError(t, d.WriteReport(nil))
}
