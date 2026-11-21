package report

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// partialThenFailReporter writes a partial payload and then fails, like a
// scan that dies halfway through writing its report.
type partialThenFailReporter struct {
	err error
}

func (r partialThenFailReporter) Write(w io.WriteCloser, _ []Finding) error {
	_, _ = w.Write([]byte(`[{"partial":`))
	return r.err
}

func dirEntryNames(t *testing.T, dir string) []string {
	t.Helper()

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)

	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names
}

func TestWriteFileCompleteReport(t *testing.T) {
	dir := t.TempDir()
	reportPath := filepath.Join(dir, "findings.json")

	findings := []Finding{
		{
			RuleID: "test-secret",
			File:   "archive.zip!inner.txt",
			Secret: "s3cr3t",
		},
	}
	require.NoError(t, WriteFile(reportPath, &JsonReporter{}, findings))

	data, err := os.ReadFile(reportPath)
	require.NoError(t, err)

	var decoded []Finding
	require.NoError(t, json.Unmarshal(data, &decoded))
	require.Len(t, decoded, 1)
	require.Equal(t, "archive.zip!inner.txt", decoded[0].File)

	// The fixed report path is the only artifact: no temporary files or
	// marker files are left behind.
	require.Equal(t, []string{"findings.json"}, dirEntryNames(t, dir))
}

func TestWriteFileFailureLeavesNoReport(t *testing.T) {
	dir := t.TempDir()
	reportPath := filepath.Join(dir, "findings.json")

	boom := errors.New("boom")
	err := WriteFile(reportPath, partialThenFailReporter{err: boom}, []Finding{{RuleID: "test-secret"}})
	require.ErrorIs(t, err, boom)

	// No report and no leftover temporary files: nothing that a later run
	// could mistake for completed coverage.
	_, statErr := os.Stat(reportPath)
	require.ErrorIs(t, statErr, os.ErrNotExist)
	require.Empty(t, dirEntryNames(t, dir))
}

func TestWriteFileUnwritableDestination(t *testing.T) {
	reportPath := filepath.Join(t.TempDir(), "missing", "findings.json")
	require.Error(t, WriteFile(reportPath, &JsonReporter{}, nil))
}
