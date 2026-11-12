package sources

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/logging"
	"github.com/zricethezav/gitleaks/v8/regexp"
)

func TestSecureArchivePath(t *testing.T) {
	tests := map[string]struct {
		input   string
		want    string
		wantErr error
	}{
		"simple relative file": {
			input: "files/api.go",
			want:  "files/api.go",
		},
		"single file": {
			input: "api.go",
			want:  "api.go",
		},
		"collapses dot segments": {
			input: "files/./api.go",
			want:  "files/api.go",
		},
		"collapses inner dot-dot that stays inside root": {
			input: "files/sub/../api.go",
			want:  "files/api.go",
		},
		"keeps redundant slashes normalized": {
			input: "files//api.go",
			want:  "files/api.go",
		},
		"empty name": {
			input:   "",
			wantErr: errArchiveNameEmpty,
		},
		"dot only": {
			input:   ".",
			wantErr: errArchiveNameReserved,
		},
		"dot-dot only": {
			input:   "..",
			wantErr: errArchiveNameEscape,
		},
		"parent traversal": {
			input:   "../secret.txt",
			wantErr: errArchiveNameEscape,
		},
		"traversal after a valid prefix": {
			input:   "files/../../secret.txt",
			wantErr: errArchiveNameEscape,
		},
		"absolute path": {
			input:   "/etc/passwd",
			wantErr: errArchiveNameAbsolute,
		},
		"absolute path with traversal": {
			input:   "/../secret.txt",
			wantErr: errArchiveNameAbsolute,
		},
		"inner path separator": {
			input:   "outer!inner/secret.txt",
			wantErr: errArchiveNameSeparator,
		},
		"separator in file name only": {
			input:   "weird!name.go",
			wantErr: errArchiveNameSeparator,
		},
		"backslash": {
			input:   `files\api.go`,
			wantErr: errArchiveNameBackslash,
		},
		"windows drive letter": {
			input:   "C:secret.txt",
			wantErr: errArchiveNameWindowsDir,
		},
		"windows drive path": {
			input:   "C:/secret.txt",
			wantErr: errArchiveNameWindowsDir,
		},
		"null byte": {
			input:   "files\x00/api.go",
			wantErr: errArchiveNameNull,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := secureArchivePath(tc.input)
			if tc.wantErr != nil {
				assert.ErrorIs(t, err, tc.wantErr)
				assert.Empty(t, got)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
			// Invariants for every accepted path.
			assert.False(t, strings.HasPrefix(got, "/"))
			assert.NotContains(t, got, "!")
			assert.NotContains(t, got, "\\")
			assert.NotContains(t, got, "\x00")
			for _, segment := range strings.Split(got, "/") {
				assert.NotContains(t, []string{".", ".."}, segment)
			}
		})
	}
}

// collectFragments drains a File source and returns the logical file paths of
// every fragment that would be scanned.
func collectFragments(t *testing.T, file *File) []string {
	t.Helper()

	seen := make(map[string]struct{})
	err := file.Fragments(context.Background(), func(fragment Fragment, err error) error {
		require.NoError(t, err)
		seen[fragment.FilePath] = struct{}{}
		return nil
	})
	require.NoError(t, err)

	paths := make([]string, 0, len(seen))
	for p := range seen {
		paths = append(paths, p)
	}
	return paths
}

// captureLogs swaps the global logger output for a buffer and returns the
// buffer plus a restore function. The level is set explicitly so warnings are
// retained regardless of the process-wide default.
func captureLogs(t *testing.T, level zerolog.Level) (*bytes.Buffer, func()) {
	t.Helper()

	buf := new(bytes.Buffer)
	previous := logging.Logger
	logging.Logger = logging.Logger.Output(buf).Level(level)

	return buf, func() {
		logging.Logger = previous
	}
}

const safeArchiveContent = "awsToken := \"AKIALALEMEL33243OLIA\"\n"

// newZipArchive builds an in-memory ZIP with the given member names.
func newZipArchive(t *testing.T, members map[string]string) []byte {
	t.Helper()

	buf := new(bytes.Buffer)
	zw := zip.NewWriter(buf)
	for name, content := range members {
		writer, err := zw.Create(name)
		require.NoError(t, err)
		_, err = writer.Write([]byte(content))
		require.NoError(t, err)
	}
	require.NoError(t, zw.Close())
	return buf.Bytes()
}

// newTarArchive builds an in-memory TAR with the given member names.
func newTarArchive(t *testing.T, members map[string]string) []byte {
	t.Helper()

	buf := new(bytes.Buffer)
	tw := tar.NewWriter(buf)
	for name, content := range members {
		require.NoError(t, tw.WriteHeader(&tar.Header{
			Name: name,
			Mode: 0o644,
			Size: int64(len(content)),
		}))
		_, err := tw.Write([]byte(content))
		require.NoError(t, err)
	}
	require.NoError(t, tw.Close())
	return buf.Bytes()
}

func TestFileFragments_ZipSkipsUnsafeMembers(t *testing.T) {
	members := map[string]string{
		"files/safe.go":           safeArchiveContent,
		"../escape.go":            safeArchiveContent,
		"/absolute.go":            safeArchiveContent,
		"bang!name.go":            safeArchiveContent,
		"nested/../still-safe.go": safeArchiveContent,
	}

	logs, restore := captureLogs(t, zerolog.WarnLevel)
	defer restore()

	file := &File{
		Content:         bytes.NewReader(newZipArchive(t, members)),
		Path:            "payload.zip",
		Config:          &config.Config{},
		MaxArchiveDepth: 1,
	}

	paths := collectFragments(t, file)

	assert.ElementsMatch(t, []string{
		"payload.zip!files/safe.go",
		"payload.zip!still-safe.go",
	}, paths)

	logOutput := logs.String()
	for _, member := range []string{"../escape.go", "/absolute.go", "bang!name.go"} {
		assert.Contains(t, logOutput, member)
		assert.Contains(t, logOutput, "skipping archive member: unsafe path")
	}
}

func TestFileFragments_TarSkipsUnsafeMembers(t *testing.T) {
	members := map[string]string{
		"files/safe.go": safeArchiveContent,
		"../../evil.go": safeArchiveContent,
		"/etc/hosts":    safeArchiveContent,
		"a!b/secret.go": safeArchiveContent,
	}

	logs, restore := captureLogs(t, zerolog.WarnLevel)
	defer restore()

	file := &File{
		Content:         bytes.NewReader(newTarArchive(t, members)),
		Path:            "payload.tar",
		Config:          &config.Config{},
		MaxArchiveDepth: 1,
	}

	paths := collectFragments(t, file)

	assert.ElementsMatch(t, []string{
		"payload.tar!files/safe.go",
	}, paths)

	logOutput := logs.String()
	for _, member := range []string{"../../evil.go", "/etc/hosts", "a!b/secret.go"} {
		assert.Contains(t, logOutput, member)
	}
}

func TestFileFragments_AllowlistStillAppliesToSafeMembers(t *testing.T) {
	members := map[string]string{
		"files/allowed.go":   safeArchiveContent,
		"files/skipped.env":  "password=hunter2\n",
		"../skipped-env.env": "password=hunter2\n",
	}

	cfg := &config.Config{
		Allowlists: []*config.Allowlist{
			{
				Paths: []*regexp.Regexp{regexp.MustCompile(`\.env$`)},
			},
		},
	}
	require.NoError(t, cfg.Allowlists[0].Validate())

	file := &File{
		Content:         bytes.NewReader(newZipArchive(t, members)),
		Path:            "payload.zip",
		Config:          cfg,
		MaxArchiveDepth: 1,
	}

	paths := collectFragments(t, file)

	// The traversal member is dropped for being unsafe, and the in-archive
	// .env member is dropped by the allowlist; only the safe Go file remains.
	assert.ElementsMatch(t, []string{
		"payload.zip!files/allowed.go",
	}, paths)
}

func TestFileFragments_NestedArchiveDepthAndDeterministicIdentity(t *testing.T) {
	// Inner ZIP: one safe member plus an unsafe one that must be dropped.
	innerZip := newZipArchive(t, map[string]string{
		"deep/secret.go": safeArchiveContent,
		"../evil.go":     safeArchiveContent,
	})

	// Outer TAR wrapping the inner ZIP alongside a regular file.
	outerTar := newTarArchive(t, map[string]string{
		"archives/inner.zip": string(innerZip),
		"top-level.txt":      "plain text\n",
	})

	logs, restore := captureLogs(t, zerolog.WarnLevel)
	defer restore()

	file := &File{
		Content:         bytes.NewReader(outerTar),
		Path:            "outer.tar",
		Config:          &config.Config{},
		MaxArchiveDepth: 2,
	}

	paths := collectFragments(t, file)

	expected := []string{
		"outer.tar!archives/inner.zip!deep/secret.go",
		"outer.tar!top-level.txt",
	}
	assert.ElementsMatch(t, expected, paths)

	// Running twice yields identical identities (deterministic fingerprints).
	assert.ElementsMatch(t, expected, collectFragments(t, &File{
		Content:         bytes.NewReader(outerTar),
		Path:            "outer.tar",
		Config:          &config.Config{},
		MaxArchiveDepth: 2,
	}))

	assert.Contains(t, logs.String(), "../evil.go")
}

func TestFileFragments_RespectsMaxArchiveDepth(t *testing.T) {
	innerZip := newZipArchive(t, map[string]string{
		"deep/secret.go": safeArchiveContent,
	})
	outerTar := newTarArchive(t, map[string]string{
		"archives/inner.zip": string(innerZip),
	})

	// Depth 1 allows the outer TAR but not the nested ZIP.
	file := &File{
		Content:         bytes.NewReader(outerTar),
		Path:            "outer.tar",
		Config:          &config.Config{},
		MaxArchiveDepth: 1,
	}

	paths := collectFragments(t, file)

	// The inner archive is treated as a binary blob and yields no fragments;
	// the nested secret must not appear.
	for _, p := range paths {
		assert.NotContains(t, p, "deep/secret.go")
	}
}
