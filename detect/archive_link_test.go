package detect

import (
	"archive/zip"
	"bytes"
	"context"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/regexp"
	"github.com/zricethezav/gitleaks/v8/sources"
)

const uid33179ArchiveSecret = "AKIALALEMEL33243OLIA"

func uid33179Archive(t *testing.T, members map[string]string) []byte {
	t.Helper()

	var buf bytes.Buffer
	writer := zip.NewWriter(&buf)
	for name, body := range members {
		fileWriter, err := writer.Create(name)
		require.NoError(t, err)
		_, err = fileWriter.Write([]byte(body))
		require.NoError(t, err)
	}
	require.NoError(t, writer.Close())
	return buf.Bytes()
}

func uid33179OrderedArchive(t *testing.T, names []string, bodies []string) []byte {
	t.Helper()
	require.Len(t, bodies, len(names))

	var buf bytes.Buffer
	writer := zip.NewWriter(&buf)
	for i, name := range names {
		fileWriter, err := writer.Create(name)
		require.NoError(t, err)
		_, err = fileWriter.Write([]byte(bodies[i]))
		require.NoError(t, err)
	}
	require.NoError(t, writer.Close())
	return buf.Bytes()
}

type uid33179CancelAfterFirstSource struct {
	file   *sources.File
	cancel context.CancelFunc
}

func (s *uid33179CancelAfterFirstSource) Fragments(ctx context.Context, yield sources.FragmentsFunc) error {
	canceled := false
	return s.file.Fragments(ctx, func(fragment sources.Fragment, err error) error {
		if err := yield(fragment, err); err != nil {
			return err
		}
		if !canceled {
			canceled = true
			s.cancel()
		}
		return nil
	})
}

func uid33179Config() config.Config {
	rule := config.Rule{
		RuleID:   "aws-access-key",
		Regex:    regexp.MustCompile(`AKIA[A-Z0-9]{16}`),
		Keywords: []string{"AKIA"},
	}
	return config.Config{
		Rules:    map[string]config.Rule{rule.RuleID: rule},
		Keywords: map[string]struct{}{"akia": {}},
	}
}

func TestUID33179ArchiveFindingUsesLogicalMemberPath(t *testing.T) {
	archive := uid33179Archive(t, map[string]string{
		"safe.txt":      "awsToken := \"" + uid33179ArchiveSecret + "\"\n",
		"../escape.txt": "awsToken := \"" + uid33179ArchiveSecret + "\"\n",
		"/absolute.txt": "awsToken := \"" + uid33179ArchiveSecret + "\"\n",
	})

	detector := NewDetector(uid33179Config())
	detector.MaxArchiveDepth = 2

	findings, err := detector.DetectSource(context.Background(), &sources.File{
		Content:         bytes.NewReader(archive),
		Path:            "bundle.zip",
		MaxArchiveDepth: 2,
	})
	require.NoError(t, err)
	require.Len(t, findings, 1)
	require.Equal(t, "bundle.zip!safe.txt", findings[0].File)
	require.Equal(t, "bundle.zip!safe.txt:aws-access-key:1", findings[0].Fingerprint)
	require.NotContains(t, findings[0].File, "gitleaks-archive-")
}

func TestUID33179SymlinkPathAllowlistIsApplied(t *testing.T) {
	allowlist := &config.Allowlist{
		Paths: []*regexp.Regexp{regexp.MustCompile(`link\.txt$`)},
	}
	require.NoError(t, allowlist.Validate())

	cfg := uid33179Config()
	cfg.Allowlists = []*config.Allowlist{allowlist}
	detector := NewDetector(cfg)

	findings := detector.Detect(Fragment{
		FilePath:    "real.txt",
		SymlinkFile: "link.txt",
		Raw:         "awsToken := \"" + uid33179ArchiveSecret + "\"\n",
	})
	require.Empty(t, findings)
}

func TestUID33179EscapingArchiveLinkIsNotOpened(t *testing.T) {
	var buf bytes.Buffer
	writer := zip.NewWriter(&buf)
	benign, err := writer.Create("benign.txt")
	require.NoError(t, err)
	_, err = benign.Write([]byte("benign\n"))
	require.NoError(t, err)

	linkHeader := &zip.FileHeader{Name: "innocent.txt"}
	linkHeader.SetMode(os.ModeSymlink | 0o777)
	link, err := writer.CreateHeader(linkHeader)
	require.NoError(t, err)
	// If the link payload were read as member content, this would be
	// reported at the safe member name instead of being quarantined.
	_, err = link.Write([]byte("../../" + uid33179ArchiveSecret))
	require.NoError(t, err)
	require.NoError(t, writer.Close())

	detector := NewDetector(uid33179Config())
	detector.MaxArchiveDepth = 1
	findings, err := detector.DetectSource(context.Background(), &sources.File{
		Content:         bytes.NewReader(buf.Bytes()),
		Path:            "links.zip",
		MaxArchiveDepth: 1,
	})
	require.NoError(t, err)
	require.Empty(t, findings)
}

func TestUID33179ArchiveRetryAfterCancelKeepsFindingIdentity(t *testing.T) {
	secretLine := "awsToken := \"" + uid33179ArchiveSecret + "\"\n"
	inner := uid33179OrderedArchive(t, []string{"inner.txt"}, []string{secretLine})
	outer := uid33179OrderedArchive(t, []string{"inner.zip", "top.txt"}, []string{string(inner), secretLine})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	detector := NewDetector(uid33179Config())
	detector.MaxArchiveDepth = 2
	findings, err := detector.DetectSource(ctx, &uid33179CancelAfterFirstSource{
		file: &sources.File{
			Content:         bytes.NewReader(outer),
			Path:            "bundle.zip",
			MaxArchiveDepth: 2,
		},
		cancel: cancel,
	})
	require.ErrorIs(t, err, context.Canceled)
	require.NotEmpty(t, findings)
	for _, finding := range findings {
		require.Equal(t, "bundle.zip!inner.zip!inner.txt", finding.File)
		require.NotContains(t, finding.File, "gitleaks-archive-")
		require.NotContains(t, finding.File, os.TempDir())
	}

	retryDetector := NewDetector(uid33179Config())
	retryDetector.MaxArchiveDepth = 2
	retry, err := retryDetector.DetectSource(context.Background(), &sources.File{
		Content:         bytes.NewReader(outer),
		Path:            "bundle.zip",
		MaxArchiveDepth: 2,
	})
	require.NoError(t, err)
	require.NotEmpty(t, retry)
	for _, finding := range retry {
		require.True(t, strings.HasPrefix(finding.File, "bundle.zip!"), finding.File)
		require.NotContains(t, finding.File, "gitleaks-archive-")
		require.NotContains(t, finding.File, os.TempDir())
	}
}
