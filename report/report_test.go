package report

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const expectPath = "../testdata/expected/"
const templatePath = "../testdata/report/"

func TestWriteStdout(t *testing.T) {
	// Arrange
	reporter := JsonReporter{}
	buf := testWriter{
		bytes.NewBuffer(nil),
	}
	findings := []Finding{
		{
			RuleID: "test-rule",
		},
	}

	// Act
	err := reporter.Write(buf, findings)
	require.NoError(t, err)
	got := buf.Bytes()

	// Assert
	assert.NotEmpty(t, got)
}

type testWriter struct {
	*bytes.Buffer
}

func (t testWriter) Close() error {
	return nil
}

// errorReporter always fails to write a report.
type errorReporter struct {
	err error
}

func (r errorReporter) Write(_ io.WriteCloser, _ []Finding) error {
	return r.err
}

// partialReporter writes some bytes and then fails, simulating a report that
// cannot be written completely.
type partialReporter struct {
	err error
}

func (r partialReporter) Write(w io.WriteCloser, _ []Finding) error {
	_, _ = io.WriteString(w, "this is not a complete report")
	return r.err
}

func TestWriteFile(t *testing.T) {
	tests := []struct {
		findings       []Finding
		testReportName string
		expected       string
	}{
		{
			testReportName: "simple",
			expected:       filepath.Join(expectPath, "report", "json_simple.json"),
			findings: []Finding{
				simpleFinding,
			}},
		{
			// Zero findings must produce the same report as before.
			testReportName: "empty",
			expected:       filepath.Join(expectPath, "report", "empty.json"),
			findings:       []Finding{}},
	}

	reporter := JsonReporter{}
	for _, test := range tests {
		t.Run(test.testReportName, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), test.testReportName+".json")

			err := WriteFile(path, &reporter, test.findings)
			require.NoError(t, err)
			assert.FileExists(t, path)

			got, err := os.ReadFile(path)
			require.NoError(t, err)

			want, err := os.ReadFile(test.expected)
			require.NoError(t, err)

			wantStr := lineEndingReplacer.Replace(string(want))
			gotStr := lineEndingReplacer.Replace(string(got))
			assert.Equal(t, wantStr, gotStr)
		})
	}
}

func TestWriteFileError(t *testing.T) {
	tests := map[string]struct {
		reporter Reporter
	}{
		// The report cannot be written at all.
		"write error": {reporter: errorReporter{err: errors.New("cannot write report")}},
		// The report is only partially written before failing.
		"partial write": {reporter: partialReporter{err: errors.New("disk full")}},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var (
				dir  = t.TempDir()
				path = filepath.Join(dir, "report.json")
			)

			// A report from a previous run must not be clobbered by a
			// failed write.
			require.NoError(t, os.WriteFile(path, []byte("previous report"), 0o644))

			err := WriteFile(path, test.reporter, []Finding{simpleFinding})
			require.Error(t, err)

			// The previous report is left untouched...
			got, readErr := os.ReadFile(path)
			require.NoError(t, readErr)
			assert.Equal(t, "previous report", string(got))

			// ...and no temporary files are left behind.
			entries, readErr := os.ReadDir(dir)
			require.NoError(t, readErr)
			require.Len(t, entries, 1)
			assert.Equal(t, "report.json", entries[0].Name())
		})
	}
}

func TestWriteFileErrorNoReport(t *testing.T) {
	// A failed write must not leave any report behind when there was no
	// previous report to begin with.
	dir := t.TempDir()
	path := filepath.Join(dir, "report.json")

	err := WriteFile(path, partialReporter{err: errors.New("disk full")}, []Finding{simpleFinding})
	require.Error(t, err)

	_, statErr := os.Stat(path)
	assert.True(t, os.IsNotExist(statErr))

	entries, readErr := os.ReadDir(dir)
	require.NoError(t, readErr)
	assert.Empty(t, entries)
}

func TestWriteFileInvalidPath(t *testing.T) {
	// The report directory does not exist.
	path := filepath.Join(t.TempDir(), "does-not-exist", "report.json")

	err := WriteFile(path, &JsonReporter{}, []Finding{simpleFinding})
	require.Error(t, err)
}

// lineEndingReplacer normalizes CRLF to LF so tests pass on Windows.
var lineEndingReplacer = strings.NewReplacer(
	"\\r\\n", "\\n",
	"\r", "",
	"\\r", "",
)
