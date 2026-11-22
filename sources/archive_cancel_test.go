package sources

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fatih/semgroup"
	"github.com/stretchr/testify/require"

	"github.com/zricethezav/gitleaks/v8/config"
)

const archivesBasePath = "../testdata/archives/"

// countGitleaksArchiveTmp counts leftover temporary files created when zip
// and 7z archives have to be spooled to disk.
func countGitleaksArchiveTmp(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir(os.TempDir())
	require.NoError(t, err)

	n := 0
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "gitleaks-archive-") {
			n++
		}
	}
	return n
}

// TestCanceledArchiveScanCleansTempFiles ensures archive temporary files
// (and the readers that own them) are removed when a scan is canceled, so
// no temporary resource survives into a subsequent run.
func TestCanceledArchiveScanCleansTempFiles(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	source := &Files{
		Path:            filepath.Join(archivesBasePath, "files.zip"),
		Sema:            semgroup.NewGroup(context.Background(), 40),
		Config:          &config.Config{},
		MaxArchiveDepth: 8,
	}

	err := source.Fragments(ctx, func(Fragment, error) error { return nil })
	require.EqualError(t, err, "context canceled")

	require.Zero(t, countGitleaksArchiveTmp(t),
		"canceled archive scan left temporary files behind")
}

// TestNormalArchiveScanCleansTempFiles keeps ordinary archive scans clean.
func TestNormalArchiveScanCleansTempFiles(t *testing.T) {
	source := &Files{
		Path:            filepath.Join(archivesBasePath, "files.zip"),
		Sema:            semgroup.NewGroup(context.Background(), 40),
		Config:          &config.Config{},
		MaxArchiveDepth: 8,
	}

	err := source.Fragments(context.Background(), func(Fragment, error) error { return nil })
	require.NoError(t, err)

	require.Zero(t, countGitleaksArchiveTmp(t),
		"archive scan left temporary files behind")
}
