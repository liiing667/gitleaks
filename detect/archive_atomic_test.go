package detect

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"context"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/regexp"
	"github.com/zricethezav/gitleaks/v8/report"
	"github.com/zricethezav/gitleaks/v8/sources"
)

type atomicTarEntry struct {
	name string
	body string
}

func makeAtomicTar(t *testing.T, entries []atomicTarEntry) []byte {
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

// cancelMidMemberReader cancels the context once more than limit bytes have
// been read, simulating a scan that is interrupted halfway through an
// archive member.
type cancelMidMemberReader struct {
	r      io.Reader
	limit  int
	total  int
	cancel context.CancelFunc
}

func (c *cancelMidMemberReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.total += n
	if c.cancel != nil && c.total > c.limit {
		c.cancel()
		c.cancel = nil
	}
	return n, err
}

// streamOnly hides the Seek and ReadAt methods of the underlying reader so
// the code path that spools ZIP archives to a temporary file is exercised.
type streamOnly struct {
	r io.Reader
}

func (s streamOnly) Read(p []byte) (int, error) {
	return s.r.Read(p)
}

func newArchiveAtomicDetector(t *testing.T) *Detector {
	t.Helper()

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
	return NewDetector(cfg)
}

// A scan only exposes archive members it has completely covered: when the
// scan is interrupted halfway through a member, that member contributes no
// findings at all, even if a secret was already read from it.
func TestDetectSourceInterruptedArchiveExposesNothing(t *testing.T) {
	// The first member is larger than the read buffer, so the interruption
	// lands halfway through it.
	body := "secret = \"interrupt-me\"\n" + strings.Repeat("padding\n", 32*1000)
	archive := makeAtomicTar(t, []atomicTarEntry{
		{name: "interrupted.txt", body: body},
		{name: "never-reached.txt", body: "secret = \"never-reached\"\n"},
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	detector := newArchiveAtomicDetector(t)
	findings, err := detector.DetectSource(ctx, &sources.File{
		Content:         &cancelMidMemberReader{r: bytes.NewReader(archive), limit: 120 * 1000, cancel: cancel},
		Path:            "bundle.tar",
		MaxArchiveDepth: 1,
	})
	require.Error(t, err)
	require.Empty(t, findings)
}

// The same guarantee holds for nested archives: when the scan is
// interrupted halfway through a member of an inner archive, neither the
// inner member nor its outer archive contribute any findings.
func TestDetectSourceInterruptedNestedArchiveExposesNothing(t *testing.T) {
	inner := makeAtomicTar(t, []atomicTarEntry{
		{name: "secret.txt", body: "secret = \"nested-value\"\n" + strings.Repeat("padding\n", 32*1000)},
	})
	outer := makeAtomicTar(t, []atomicTarEntry{
		{name: "inner.tar", body: string(inner)},
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	detector := newArchiveAtomicDetector(t)
	findings, err := detector.DetectSource(ctx, &sources.File{
		Content:         &cancelMidMemberReader{r: bytes.NewReader(outer), limit: 120 * 1000, cancel: cancel},
		Path:            "outer.tar",
		MaxArchiveDepth: 2,
	})
	require.Error(t, err)
	require.Empty(t, findings)
}

// Members of a completely scanned archive are all exposed, named after the
// source file the user sees joined with the logical member path.
func TestDetectSourceCompleteArchiveExposesAllMembers(t *testing.T) {
	archive := makeAtomicTar(t, []atomicTarEntry{
		{name: "a.txt", body: "secret = \"value-a\"\n"},
		{name: "dir/b.txt", body: "secret = \"value-b\"\n"},
	})

	detector := newArchiveAtomicDetector(t)
	findings, err := detector.DetectSource(context.Background(), &sources.File{
		Content:         bytes.NewReader(archive),
		Path:            "bundle.tar",
		MaxArchiveDepth: 1,
	})
	require.NoError(t, err)
	require.Len(t, findings, 2)

	names := map[string]struct{}{}
	for _, finding := range findings {
		names[finding.File] = struct{}{}
	}
	require.Contains(t, names, "bundle.tar!a.txt")
	require.Contains(t, names, "bundle.tar!dir/b.txt")
}

// Even when a ZIP archive has to be spooled to a temporary file, the
// reported member name is derived from the source file the user sees, never
// from the temporary extraction path.
func TestDetectSourceZipMemberNamesMatchSourceFile(t *testing.T) {
	var buf bytes.Buffer
	writer := zip.NewWriter(&buf)
	file, err := writer.Create("nested/secret.txt")
	require.NoError(t, err)
	_, err = file.Write([]byte("secret = \"zip-value\"\n"))
	require.NoError(t, err)
	require.NoError(t, writer.Close())

	detector := newArchiveAtomicDetector(t)
	findings, err := detector.DetectSource(context.Background(), &sources.File{
		Content:         streamOnly{r: bytes.NewReader(buf.Bytes())},
		Path:            "archive.zip",
		MaxArchiveDepth: 1,
	})
	require.NoError(t, err)
	require.Len(t, findings, 1)
	require.Equal(t, "archive.zip!nested/secret.txt", findings[0].File)
}

// The report of a completed scan is the coverage evidence a later run
// reads: findings already evidenced by the fixed report are not reported
// again.
func TestDetectSourceReportServesAsCoverageEvidence(t *testing.T) {
	archive := makeAtomicTar(t, []atomicTarEntry{
		{name: "first.txt", body: "secret = \"first-value\"\n"},
	})

	detector := newArchiveAtomicDetector(t)
	findings, err := detector.DetectSource(context.Background(), &sources.File{
		Content:         bytes.NewReader(archive),
		Path:            "bundle.tar",
		MaxArchiveDepth: 1,
	})
	require.NoError(t, err)
	require.Len(t, findings, 1)

	// Persist the completed scan's report at the fixed report path.
	reportPath := filepath.Join(t.TempDir(), "report.json")
	require.NoError(t, report.WriteFile(reportPath, &report.JsonReporter{}, findings))

	// A later run reads its coverage evidence from the fixed report.
	baseline, err := LoadBaseline(reportPath)
	require.NoError(t, err)

	followUp := newArchiveAtomicDetector(t)
	followUp.baseline = baseline
	findings, err = followUp.DetectSource(context.Background(), &sources.File{
		Content:         bytes.NewReader(archive),
		Path:            "bundle.tar",
		MaxArchiveDepth: 1,
	})
	require.NoError(t, err)
	require.Empty(t, findings)
}
