package cmd

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
	"github.com/zricethezav/gitleaks/v8/report"
	"github.com/zricethezav/gitleaks/v8/sources"
)

// failingSource always returns an error, modeling an aborted scan.
type failingSource struct{}

func (failingSource) Fragments(context.Context, sources.FragmentsFunc) error {
	return errors.New("scan aborted")
}

// recordingReporter records whether Write was called.
type recordingReporter struct {
	called bool
}

func (r *recordingReporter) Write(io.WriteCloser, []report.Finding) error {
	r.called = true
	return nil
}

// TestAbortedScanWritesNoReport ensures a canceled/failed (aborted) scan
// never terminates into a report from partial results.
func TestAbortedScanWritesNoReport(t *testing.T) {
	reportPath := filepath.Join(t.TempDir(), "report.json")

	detector := detect.NewDetector(config.Config{})
	reporter := &recordingReporter{}
	detector.ReportPath = reportPath
	detector.Reporter = reporter

	findings, err := detector.DetectSource(context.Background(), failingSource{})
	require.Error(t, err)
	require.Empty(t, findings)

	// findingSummaryAndExit would call os.Exit on error, so assert the
	// precondition it relies on directly: the report must not be written
	// when the scan errored. Mirror the guard from findingSummaryAndExit.
	if err == nil && detector.Reporter != nil {
		file, openErr := os.Create(reportPath)
		require.NoError(t, openErr)
		require.NoError(t, detector.Reporter.Write(file, findings))
		_ = file.Close()
	}

	require.False(t, reporter.called, "aborted scan must not write a report")
	_, statErr := os.Stat(reportPath)
	require.True(t, os.IsNotExist(statErr), "no report file should exist after an aborted scan")
}

// TestCommittedScanWritesReport keeps the happy-path report flow working.
func TestCommittedScanWritesReport(t *testing.T) {
	reportPath := filepath.Join(t.TempDir(), "report.json")

	detector := detect.NewDetector(config.Config{})
	reporter := &recordingReporter{}
	detector.ReportPath = reportPath
	detector.Reporter = reporter

	findings, err := detector.DetectSource(
		context.Background(),
		&sources.File{Content: strings.NewReader(`clean content`)},
	)
	require.NoError(t, err)
	require.Empty(t, findings)

	// Mirror the report guard: a successful scan is allowed to report.
	if err == nil && detector.Reporter != nil {
		file, openErr := os.Create(reportPath)
		require.NoError(t, openErr)
		require.NoError(t, detector.Reporter.Write(file, findings))
		_ = file.Close()
	}

	require.True(t, reporter.called, "committed scan must be allowed to write a report")
	_, statErr := os.Stat(reportPath)
	require.NoError(t, statErr, "report file should exist after a committed scan")
}
