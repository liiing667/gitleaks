package src

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
	"github.com/zricethezav/gitleaks/v8/regexp"
	"github.com/zricethezav/gitleaks/v8/report"
	"github.com/zricethezav/gitleaks/v8/sources"
)

type tarEntry struct {
	name string
	body string
}

func makeTar(t *testing.T, entries []tarEntry) []byte {
	t.Helper()

	var buf bytes.Buffer
	writer := tar.NewWriter(&buf)
	for _, entry := range entries {
		require.NoError(t, writer.WriteHeader(&tar.Header{
			Name: entry.name,
			Mode: 0o600,
			Size: int64(len(entry.body)),
		}))
		_, err := writer.Write([]byte(entry.body))
		require.NoError(t, err)
	}
	require.NoError(t, writer.Close())
	return buf.Bytes()
}

// cancelAfterReader cancels the context once more than limit bytes have been
// read, simulating a scan that is interrupted halfway through an archive
// member.
type cancelAfterReader struct {
	r      io.Reader
	limit  int
	total  int
	cancel context.CancelFunc
}

func (c *cancelAfterReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.total += n
	if c.cancel != nil && c.total > c.limit {
		c.cancel()
		c.cancel = nil
	}
	return n, err
}

func newTestDetector() *detect.Detector {
	cfg := config.Config{
		Rules: map[string]config.Rule{
			"test-secret": {
				RuleID:      "test-secret",
				Description: "test secret",
				Regex:       regexp.MustCompile(`secret\s*=\s*"([^"]+)"`),
				SecretGroup: 1,
				Keywords:    []string{"secret"},
			},
		},
		Keywords: map[string]struct{}{"secret": {}},
	}
	return detect.NewDetector(cfg)
}

func TestScanCompleteExposesCoveredMembers(t *testing.T) {
	archive := makeTar(t, []tarEntry{
		{name: "first.txt", body: "secret = \"first-value\"\n"},
		{name: "second.txt", body: "secret = \"second-value\"\n"},
	})

	result, err := Scan(context.Background(), newTestDetector(), &sources.File{
		Content:         bytes.NewReader(archive),
		Path:            "bundle.tar",
		MaxArchiveDepth: 1,
	})
	require.NoError(t, err)
	require.True(t, result.Complete)
	require.Len(t, result.Findings, 2)

	// Members are named after the source file the user sees, joined with the
	// logical member path.
	names := []string{result.Findings[0].File, result.Findings[1].File}
	sort.Strings(names)
	require.Equal(t, []string{"bundle.tar!first.txt", "bundle.tar!second.txt"}, names)

	// A completed scan persists its report at the fixed report path.
	dir := t.TempDir()
	reportPath := filepath.Join(dir, "report.json")
	require.NoError(t, result.WriteReport(reportPath, &report.JsonReporter{}))

	// The fixed report is the coverage evidence, and it is the only
	// artifact left behind.
	coverage, err := LoadCoverage(reportPath)
	require.NoError(t, err)
	require.Equal(t, []string{"bundle.tar!first.txt", "bundle.tar!second.txt"}, coverage.Members())

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, entries, 1)
}

func TestScanInterruptedExposesNothing(t *testing.T) {
	// The first member is larger than the read buffer, so the interruption
	// lands halfway through it: the member starts being read but is never
	// completely covered.
	body := "secret = \"interrupt-me\"\n" + strings.Repeat("padding\n", 32*1000)
	archive := makeTar(t, []tarEntry{
		{name: "interrupted.txt", body: body},
		{name: "never-reached.txt", body: "secret = \"never-reached\"\n"},
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	result, err := Scan(ctx, newTestDetector(), &sources.File{
		Content:         &cancelAfterReader{r: bytes.NewReader(archive), limit: 120 * 1000, cancel: cancel},
		Path:            "bundle.tar",
		MaxArchiveDepth: 1,
	})
	require.Error(t, err)
	require.False(t, result.Complete)

	// The interrupted member is not exposed at all, even though a secret
	// was read from its first chunk before the scan was cancelled.
	require.Empty(t, result.Findings)

	// An interrupted scan must not leave a report behind: the fixed report
	// path stays untouched so nothing can mistake it for complete coverage.
	dir := t.TempDir()
	reportPath := filepath.Join(dir, "report.json")
	require.ErrorIs(t, result.WriteReport(reportPath, &report.JsonReporter{}), ErrIncompleteScan)

	_, statErr := os.Stat(reportPath)
	require.ErrorIs(t, statErr, os.ErrNotExist)
	entries, readErr := os.ReadDir(dir)
	require.NoError(t, readErr)
	require.Empty(t, entries)
}

func TestScanRecoveryIsAFreshScan(t *testing.T) {
	body := "secret = \"interrupt-me\"\n" + strings.Repeat("padding\n", 32*1000)
	archive := makeTar(t, []tarEntry{
		{name: "interrupted.txt", body: body},
		{name: "second.txt", body: "secret = \"second-value\"\n"},
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	interrupted, err := Scan(ctx, newTestDetector(), &sources.File{
		Content:         &cancelAfterReader{r: bytes.NewReader(archive), limit: 120 * 1000, cancel: cancel},
		Path:            "bundle.tar",
		MaxArchiveDepth: 1,
	})
	require.Error(t, err)
	require.False(t, interrupted.Complete)
	require.Empty(t, interrupted.Findings)

	// Recovery is a fresh scan of the same input: there is no leftover
	// state to resume from, so every member is covered again.
	recovered, err := Scan(context.Background(), newTestDetector(), &sources.File{
		Content:         bytes.NewReader(archive),
		Path:            "bundle.tar",
		MaxArchiveDepth: 1,
	})
	require.NoError(t, err)
	require.True(t, recovered.Complete)
	require.Len(t, recovered.Findings, 2)
}
