package sources

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/zricethezav/gitleaks/v8/logging"
)

type archiveTestEntry struct {
	name string
	body []byte
}

type archiveTestFragment struct {
	path string
	raw  string
	err  error
}

func makeZip(t *testing.T, entries []archiveTestEntry) []byte {
	t.Helper()

	var buf bytes.Buffer
	writer := zip.NewWriter(&buf)
	for _, entry := range entries {
		file, err := writer.Create(entry.name)
		require.NoError(t, err)
		_, err = file.Write(entry.body)
		require.NoError(t, err)
	}
	require.NoError(t, writer.Close())
	return buf.Bytes()
}

func makeTar(t *testing.T, entries []archiveTestEntry) []byte {
	t.Helper()

	var buf bytes.Buffer
	writer := tar.NewWriter(&buf)
	for _, entry := range entries {
		header := &tar.Header{
			Name: entry.name,
			Mode: 0o600,
			Size: int64(len(entry.body)),
		}
		require.NoError(t, writer.WriteHeader(header))
		_, err := writer.Write(entry.body)
		require.NoError(t, err)
	}
	require.NoError(t, writer.Close())
	return buf.Bytes()
}

func collectArchiveFragments(t *testing.T, file *File) []archiveTestFragment {
	t.Helper()

	var fragments []archiveTestFragment
	err := file.Fragments(context.Background(), func(fragment Fragment, err error) error {
		fragments = append(fragments, archiveTestFragment{
			path: fragment.FilePath,
			raw:  fragment.Raw,
			err:  err,
		})
		return nil
	})
	require.NoError(t, err)
	return fragments
}

func TestArchiveEntryPath(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr error
	}{
		{name: "relative", input: "dir/file.txt", want: "dir/file.txt"},
		{name: "dot prefix", input: "./dir/file.txt", want: "dir/file.txt"},
		{name: "safe parent", input: "dir/../file.txt", want: "file.txt"},
		{name: "backslash", input: `dir\file.txt`, want: "dir/file.txt"},
		{name: "escaping dotdot", input: "../file.txt", wantErr: errEscapingArchivePath},
		{name: "escaping nested dotdot", input: "dir/../../file.txt", wantErr: errEscapingArchivePath},
		{name: "escaping backslash", input: `..\..\file.txt`, wantErr: errEscapingArchivePath},
		{name: "absolute", input: "/etc/passwd", wantErr: errAbsoluteArchivePath},
		{name: "windows absolute", input: `C:\Windows\System32\config`, wantErr: errAbsoluteArchivePath},
		{name: "windows absolute slash", input: "C:/Windows/System32/config", wantErr: errAbsoluteArchivePath},
		{name: "windows drive relative", input: `C:relative\file.txt`, wantErr: errAbsoluteArchivePath},
		{name: "unc absolute", input: `\\server\share\file.txt`, wantErr: errAbsoluteArchivePath},
		{name: "reserved separator", input: "dir/file!name.txt", wantErr: errAmbiguousArchivePath},
		{name: "empty", input: "", wantErr: errEmptyArchivePath},
		{name: "dot", input: ".", wantErr: errEmptyArchivePath},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := archiveEntryPath(test.input)
			if test.wantErr != nil {
				require.ErrorIs(t, err, test.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.want, got)
		})
	}
}

func TestArchiveFragmentsRejectUnsafeMemberPaths(t *testing.T) {
	entries := []archiveTestEntry{
		{name: "safe/dir/file.txt", body: []byte("safe secret\n")},
		{name: "./safe/../safe/normalized.txt", body: []byte("normalized secret\n")},
		{name: "../escape.txt", body: []byte("escaped secret\n")},
		{name: "dir/../../escape.txt", body: []byte("escaped secret\n")},
		{name: `/absolute.txt`, body: []byte("absolute secret\n")},
		{name: `..\escape.txt`, body: []byte("escaped secret\n")},
		{name: "C:/windows.txt", body: []byte("windows secret\n")},
		{name: "dir/file!name.txt", body: []byte("ambiguous secret\n")},
	}

	builders := map[string]func(*testing.T, []archiveTestEntry) []byte{
		"zip": makeZip,
		"tar": makeTar,
	}
	for name, build := range builders {
		t.Run(name, func(t *testing.T) {
			fragments := collectArchiveFragments(t, &File{
				Content:         bytes.NewReader(build(t, entries)),
				Path:            "test." + name,
				MaxArchiveDepth: 1,
			})

			require.Len(t, fragments, 2)
			require.Equal(t, "test."+name+"!safe/dir/file.txt", fragments[0].path)
			require.Equal(t, "safe secret\n", fragments[0].raw)
			require.Equal(t, "test."+name+"!safe/normalized.txt", fragments[1].path)
			require.Equal(t, "normalized secret\n", fragments[1].raw)
		})
	}
}

func TestArchiveFragmentsNested(t *testing.T) {
	innerZip := makeZip(t, []archiveTestEntry{
		{name: "nested/zip-secret.txt", body: []byte("zip secret\n")},
	})
	innerTar := makeTar(t, []archiveTestEntry{
		{name: "nested/tar-secret.txt", body: []byte("tar secret\n")},
	})
	outerZip := makeZip(t, []archiveTestEntry{
		{name: "inner.zip", body: innerZip},
		{name: "inner.tar", body: innerTar},
		{name: "plain.txt", body: []byte("plain secret\n")},
	})
	outerTar := makeTar(t, []archiveTestEntry{
		{name: "inner.zip", body: innerZip},
		{name: "inner.tar", body: innerTar},
		{name: "plain.txt", body: []byte("plain secret\n")},
	})

	tests := []struct {
		name string
		path string
		body []byte
		want []string
	}{
		{
			name: "zip",
			path: "outer.zip",
			body: outerZip,
			want: []string{
				"outer.zip!inner.zip!nested/zip-secret.txt",
				"outer.zip!inner.tar!nested/tar-secret.txt",
				"outer.zip!plain.txt",
			},
		},
		{
			name: "tar",
			path: "outer.tar",
			body: outerTar,
			want: []string{
				"outer.tar!inner.zip!nested/zip-secret.txt",
				"outer.tar!inner.tar!nested/tar-secret.txt",
				"outer.tar!plain.txt",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fragments := collectArchiveFragments(t, &File{
				Content:         bytes.NewReader(test.body),
				Path:            test.path,
				MaxArchiveDepth: 2,
			})

			var got []string
			for _, fragment := range fragments {
				got = append(got, fragment.path)
			}
			require.ElementsMatch(t, test.want, got)
		})
	}
}

func TestArchiveFragmentsRespectsDepth(t *testing.T) {
	inner := makeZip(t, []archiveTestEntry{
		{name: "secret.txt", body: []byte("nested secret\n")},
	})
	outer := makeZip(t, []archiveTestEntry{
		{name: "inner.zip", body: inner},
		{name: "plain.txt", body: []byte("plain secret\n")},
	})

	tests := []struct {
		name  string
		depth int
		want  []string
	}{
		{name: "disabled", depth: 0, want: nil},
		{name: "outer only", depth: 1, want: []string{"outer.zip!plain.txt"}},
		{name: "nested", depth: 2, want: []string{"outer.zip!plain.txt", "outer.zip!inner.zip!secret.txt"}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fragments := collectArchiveFragments(t, &File{
				Content:         bytes.NewReader(outer),
				Path:            "outer.zip",
				MaxArchiveDepth: test.depth,
			})

			var got []string
			for _, fragment := range fragments {
				got = append(got, fragment.path)
			}
			require.ElementsMatch(t, test.want, got)
		})
	}
}

func TestArchiveFragmentsLogsUnsafePathDiagnostics(t *testing.T) {
	var logs bytes.Buffer
	previousLogger := logging.Logger
	logging.Logger = zerolog.New(&logs).Level(zerolog.WarnLevel)
	t.Cleanup(func() {
		logging.Logger = previousLogger
	})

	archive := makeZip(t, []archiveTestEntry{
		{name: "../escape.txt", body: []byte("escaped secret\n")},
		{name: `/absolute.txt`, body: []byte("absolute secret\n")},
		{name: "dir/file!name.txt", body: []byte("ambiguous secret\n")},
	})
	_ = collectArchiveFragments(t, &File{
		Content:         bytes.NewReader(archive),
		Path:            "diagnostics.zip",
		MaxArchiveDepth: 1,
	})

	var diagnostics []map[string]interface{}
	decoder := json.NewDecoder(&logs)
	for {
		var diagnostic map[string]interface{}
		err := decoder.Decode(&diagnostic)
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		diagnostics = append(diagnostics, diagnostic)
	}

	require.Len(t, diagnostics, 3)
	for _, diagnostic := range diagnostics {
		require.Equal(t, "diagnostics.zip", diagnostic["path"])
		require.NotEmpty(t, diagnostic["archive_entry"])
		require.NotEmpty(t, diagnostic["reason"])
		require.Equal(t, "skipping archive path: unsafe or ambiguous", diagnostic["message"])
	}
}

func TestArchiveFragmentsRejectsAmbiguousContainerPath(t *testing.T) {
	archive := makeZip(t, []archiveTestEntry{
		{name: "secret.txt", body: []byte("secret\n")},
	})

	fragments := collectArchiveFragments(t, &File{
		Content:         bytes.NewReader(archive),
		Path:            "not!an-archive.zip",
		MaxArchiveDepth: 1,
	})
	require.Empty(t, fragments)
}
