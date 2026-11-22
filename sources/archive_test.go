package sources

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fatih/semgroup"
	"github.com/stretchr/testify/require"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/regexp"
)

type uid33179ZipEntry struct {
	name string
	body string
	mode os.FileMode
}

func uid33179MakeZip(t *testing.T, entries []uid33179ZipEntry) []byte {
	t.Helper()

	var buf bytes.Buffer
	writer := zip.NewWriter(&buf)
	for _, entry := range entries {
		header := &zip.FileHeader{Name: entry.name, Method: zip.Deflate}
		if entry.mode != 0 {
			header.SetMode(entry.mode)
		}
		fileWriter, err := writer.CreateHeader(header)
		require.NoError(t, err)
		_, err = fileWriter.Write([]byte(entry.body))
		require.NoError(t, err)
	}
	require.NoError(t, writer.Close())
	return buf.Bytes()
}

func uid33179MakeTar(t *testing.T, files map[string]string, links map[string]string) []byte {
	t.Helper()

	var buf bytes.Buffer
	writer := tar.NewWriter(&buf)
	for name, body := range files {
		require.NoError(t, writer.WriteHeader(&tar.Header{
			Name:     name,
			Mode:     0o644,
			Size:     int64(len(body)),
			Typeflag: tar.TypeReg,
		}))
		_, err := writer.Write([]byte(body))
		require.NoError(t, err)
	}
	for name, target := range links {
		require.NoError(t, writer.WriteHeader(&tar.Header{
			Name:     name,
			Mode:     0o777,
			Typeflag: tar.TypeSymlink,
			Linkname: target,
		}))
	}
	require.NoError(t, writer.Close())
	return buf.Bytes()
}

func uid33179CollectPaths(t *testing.T, ctx context.Context, file *File) ([]string, error) {
	t.Helper()

	var paths []string
	err := file.Fragments(ctx, func(fragment Fragment, err error) error {
		if err != nil {
			return nil
		}
		paths = append(paths, fragment.FilePath)
		return nil
	})
	return paths, err
}

func TestUID33179SecureArchivePath(t *testing.T) {
	tests := map[string]struct {
		input   string
		want    string
		wantErr error
	}{
		"relative":                 {input: "files/api.go", want: "files/api.go"},
		"dot segments":             {input: "files/./api.go", want: "files/api.go"},
		"internal dot-dot":         {input: "files/sub/../api.go", want: "files/api.go"},
		"redundant separators":     {input: "files//api.go", want: "files/api.go"},
		"empty":                    {input: "", wantErr: errArchiveNameEmpty},
		"dot":                      {input: ".", wantErr: errArchiveNameReserved},
		"dot-dot":                  {input: "..", wantErr: errArchiveNameEscape},
		"parent traversal":         {input: "../secret.txt", wantErr: errArchiveNameEscape},
		"prefixed traversal":       {input: "files/../../secret.txt", wantErr: errArchiveNameEscape},
		"absolute":                 {input: "/etc/passwd", wantErr: errArchiveNameAbsolute},
		"inner separator":          {input: "outer!inner/secret.txt", wantErr: errArchiveNameSeparator},
		"backslash":                {input: `files\api.go`, wantErr: errArchiveNameBackslash},
		"windows drive":            {input: "C:secret.txt", wantErr: errArchiveNameWindowsDrive},
		"windows drive with slash": {input: "C:/secret.txt", wantErr: errArchiveNameWindowsDrive},
		"null byte":                {input: "files\x00/api.go", wantErr: errArchiveNameNull},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := secureArchivePath(test.input)
			if test.wantErr != nil {
				require.ErrorIs(t, err, test.wantErr)
				require.Empty(t, got)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.want, got)
			require.NotContains(t, got, "..")
			require.NotContains(t, got, InnerPathSeparator)
		})
	}
}

func TestUID33179ArchiveMemberContainment(t *testing.T) {
	archive := uid33179MakeZip(t, []uid33179ZipEntry{
		{name: "files/safe.txt", body: "safe\n"},
		{name: "files/./normal.txt", body: "normal\n"},
		{name: "../escape.txt", body: "escape\n"},
		{name: "/absolute.txt", body: "absolute\n"},
		{name: "files/../../escape2.txt", body: "escape\n"},
		{name: "bang!name.txt", body: "ambiguous\n"},
		{name: `..\windows.txt`, body: "escape\n"},
		{name: "dup.txt", body: "one\n"},
		{name: "x/../dup.txt", body: "two\n"},
	})

	file := &File{
		Content:         bytes.NewReader(archive),
		Path:            "payload.zip",
		MaxArchiveDepth: 1,
	}
	paths, err := uid33179CollectPaths(t, context.Background(), file)
	require.NoError(t, err)
	require.ElementsMatch(t, []string{
		"payload.zip!files/safe.txt",
		"payload.zip!files/normal.txt",
	}, paths)

	for _, path := range paths {
		require.NotContains(t, path, "..")
		require.NotContains(t, path, "gitleaks-archive-")
	}
}

func TestUID33179InMemoryArchiveUsesLogicalPathUnderRoot(t *testing.T) {
	archive := uid33179MakeZip(t, []uid33179ZipEntry{
		{name: "files/safe.txt", body: "safe\n"},
	})
	file := &File{
		Content:         bytes.NewReader(archive),
		Path:            "bundle.zip",
		Root:            t.TempDir(),
		MaxArchiveDepth: 1,
	}

	paths, err := uid33179CollectPaths(t, context.Background(), file)
	require.NoError(t, err)
	require.Equal(t, []string{"bundle.zip!files/safe.txt"}, paths)
}

func TestUID33179ArchiveSymlinkContainment(t *testing.T) {
	archive := uid33179MakeTar(t, map[string]string{
		"safe.txt":   "safe\n",
		"target.txt": "target\n",
	}, map[string]string{
		"good.txt":         "target.txt",
		"archive-link.zip": "target.txt",
		"escape.txt":       "../../outside.txt",
		"absolute.txt":     "/etc/passwd",
		"self.txt":         "self.txt",
		"cycle-a.txt":      "cycle-b.txt",
		"cycle-b.txt":      "cycle-a.txt",
		"missing.txt":      "missing.txt",
	})

	file := &File{
		Content:         bytes.NewReader(archive),
		Path:            "links.tar",
		MaxArchiveDepth: 1,
	}
	paths, err := uid33179CollectPaths(t, context.Background(), file)
	require.NoError(t, err)
	// Tar link entries have no payload. The legitimate link is accepted but
	// contributes no fragment; escaping and cyclic links are quarantined.
	require.ElementsMatch(t, []string{
		"links.tar!safe.txt",
		"links.tar!target.txt",
	}, paths)
}

func TestUID33179ArchivePathAllowlistStillApplies(t *testing.T) {
	allowlist := &config.Allowlist{
		Paths: []*regexp.Regexp{regexp.MustCompile(`\.env$`)},
	}
	require.NoError(t, allowlist.Validate())
	cfg := &config.Config{Allowlists: []*config.Allowlist{allowlist}}

	inner := uid33179MakeZip(t, []uid33179ZipEntry{
		{name: "nested.env", body: "password=hunter2\n"},
		{name: "nested.go", body: "package nested\n"},
	})
	archive := uid33179MakeZip(t, []uid33179ZipEntry{
		{name: "files/allowed.go", body: "allowed\n"},
		{name: "files/skipped.env", body: "password=hunter2\n"},
		{name: "../skipped-env.env", body: "password=hunter2\n"},
		{name: "inner.zip", body: string(inner)},
	})
	file := &File{
		Content:         bytes.NewReader(archive),
		Path:            "allowlist.zip",
		Config:          cfg,
		MaxArchiveDepth: 2,
	}

	paths, err := uid33179CollectPaths(t, context.Background(), file)
	require.NoError(t, err)
	require.ElementsMatch(t, []string{
		"allowlist.zip!files/allowed.go",
		"allowlist.zip!inner.zip!nested.go",
	}, paths)
}

func TestUID33179NestedArchiveRetryKeepsLogicalIdentity(t *testing.T) {
	inner := uid33179MakeZip(t, []uid33179ZipEntry{
		{name: "inner.txt", body: "inner\n"},
	})
	outer := uid33179MakeZip(t, []uid33179ZipEntry{
		{name: "top.txt", body: "top\n"},
		{name: "inner.zip", body: string(inner)},
	})

	expected := []string{
		"bundle.zip!top.txt",
		"bundle.zip!inner.zip!inner.txt",
	}

	first, err := uid33179CollectPaths(t, context.Background(), &File{
		Content:         bytes.NewReader(outer),
		Path:            "bundle.zip",
		MaxArchiveDepth: 2,
	})
	require.NoError(t, err)
	require.ElementsMatch(t, expected, first)

	// Cancellation must not leak a spool-file identity into a finding.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	retryFile := &File{
		Content:         bytes.NewReader(outer),
		Path:            "bundle.zip",
		MaxArchiveDepth: 2,
	}
	var canceledPaths []string
	err = retryFile.Fragments(ctx, func(fragment Fragment, err error) error {
		if err != nil {
			return nil
		}
		canceledPaths = append(canceledPaths, fragment.FilePath)
		cancel()
		return nil
	})
	require.ErrorIs(t, err, context.Canceled)
	for _, path := range canceledPaths {
		require.True(t, strings.HasPrefix(path, "bundle.zip!"), path)
		require.NotContains(t, path, "gitleaks-archive-")
		require.NotContains(t, path, os.TempDir())
	}

	// A retry after cancellation resolves from the logical archive chain
	// again, never from the previous temporary member.
	retry, err := uid33179CollectPaths(t, context.Background(), retryFile)
	require.NoError(t, err)
	require.ElementsMatch(t, expected, retry)
}

func TestUID33179FilesSymlinkContainment(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()

	realPath := filepath.Join(root, "real.txt")
	require.NoError(t, os.WriteFile(realPath, []byte("inside\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("outside\n"), 0o600))

	if err := os.Symlink("real.txt", filepath.Join(root, "good.txt")); err != nil {
		t.Skipf("symlinks not supported: %v", err)
	}
	require.NoError(t, os.Symlink(filepath.Join(outside, "secret.txt"), filepath.Join(root, "escape.txt")))
	require.NoError(t, os.Symlink("loop.txt", filepath.Join(root, "loop.txt")))
	require.NoError(t, os.Symlink(filepath.Join(root, "missing"), filepath.Join(root, "broken.txt")))

	files := &Files{
		Path:           root,
		FollowSymlinks: true,
		Sema:           semgroup.NewGroup(context.Background(), 4),
	}

	seen := make(map[string]struct{})
	err := files.Fragments(context.Background(), func(fragment Fragment, err error) error {
		if err == nil {
			seen[fragment.FilePath] = struct{}{}
		}
		return nil
	})
	require.NoError(t, err)
	require.Contains(t, seen, realPath)
	require.NotContains(t, seen, filepath.Join(outside, "secret.txt"))

	var targets []ScanTarget
	require.NoError(t, files.scanTargets(context.Background(), func(target ScanTarget, err error) error {
		targets = append(targets, target)
		return nil
	}))
	for _, target := range targets {
		require.NotEqual(t, filepath.Join(outside, "secret.txt"), target.Path)
		require.NotEmpty(t, target.Root)
	}

	// The deprecated channel API must freeze the same root for its consumers.
	group := semgroup.NewGroup(context.Background(), 4)
	targetsChannel, err := DirectoryTargets(root, group, true, nil)
	require.NoError(t, err)
	var fromDirectory []ScanTarget
	for target := range targetsChannel {
		fromDirectory = append(fromDirectory, target)
	}
	require.NoError(t, group.Wait())
	require.NotEmpty(t, fromDirectory)
	for _, target := range fromDirectory {
		require.NotEqual(t, filepath.Join(outside, "secret.txt"), target.Path)
		require.NotEmpty(t, target.Root)
	}
}

func TestUID33179EmptyDirectoryRemainsClean(t *testing.T) {
	files := &Files{
		Path: t.TempDir(),
		Sema: semgroup.NewGroup(context.Background(), 4),
	}

	var fragments int
	err := files.Fragments(context.Background(), func(fragment Fragment, err error) error {
		fragments++
		return nil
	})
	require.NoError(t, err)
	require.Zero(t, fragments)
}
