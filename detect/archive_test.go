package detect

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/regexp"
	"github.com/zricethezav/gitleaks/v8/report"
	"github.com/zricethezav/gitleaks/v8/sources"
)

type archiveReportWriter struct {
	io.Writer
}

func (archiveReportWriter) Close() error {
	return nil
}

func makeArchiveZip(t *testing.T, entries map[string]string) []byte {
	t.Helper()

	var buf bytes.Buffer
	writer := zip.NewWriter(&buf)
	for name, body := range entries {
		file, err := writer.Create(name)
		require.NoError(t, err)
		_, err = file.Write([]byte(body))
		require.NoError(t, err)
	}
	require.NoError(t, writer.Close())
	return buf.Bytes()
}

func TestArchiveFindingReportIdentity(t *testing.T) {
	inner := makeArchiveZip(t, map[string]string{
		"nested/secret.txt": "secret = \"s3cr3t-value\"\n",
	})
	archive := makeArchiveZip(t, map[string]string{
		"inner.zip": string(inner),
	})
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

	detector := NewDetector(cfg)
	findings, err := detector.DetectSource(context.Background(), &sources.File{
		Content:         bytes.NewReader(archive),
		Path:            "archive.zip",
		MaxArchiveDepth: 2,
	})
	require.NoError(t, err)
	require.Len(t, findings, 1)

	const expectedFile = "archive.zip!inner.zip!nested/secret.txt"
	require.Equal(t, expectedFile, findings[0].File)
	require.Equal(t, expectedFile+":test-secret:1", findings[0].Fingerprint)

	var jsonBuf bytes.Buffer
	require.NoError(t, (&report.JsonReporter{}).Write(archiveReportWriter{Writer: &jsonBuf}, findings))
	var jsonFindings []report.Finding
	require.NoError(t, json.Unmarshal(jsonBuf.Bytes(), &jsonFindings))
	require.Len(t, jsonFindings, 1)
	require.Equal(t, expectedFile, jsonFindings[0].File)
	require.Equal(t, expectedFile+":test-secret:1", jsonFindings[0].Fingerprint)

	var sarifBuf bytes.Buffer
	reporter := report.SarifReporter{
		OrderedRules: []config.Rule{cfg.Rules["test-secret"]},
	}
	require.NoError(t, reporter.Write(archiveReportWriter{Writer: &sarifBuf}, findings))
	var sarif report.Sarif
	require.NoError(t, json.Unmarshal(sarifBuf.Bytes(), &sarif))
	require.Len(t, sarif.Runs, 1)
	require.Len(t, sarif.Runs[0].Results, 1)
	require.Len(t, sarif.Runs[0].Results[0].Locations, 1)
	require.Equal(
		t,
		expectedFile,
		sarif.Runs[0].Results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI,
	)

	var secondJSONBuf bytes.Buffer
	require.NoError(t, (&report.JsonReporter{}).Write(archiveReportWriter{Writer: &secondJSONBuf}, findings))
	require.Equal(t, jsonBuf.String(), secondJSONBuf.String())
}
