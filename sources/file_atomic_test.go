package sources

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
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

// interruptReader cancels the context once more than limit bytes have been
// read, simulating a scan that is interrupted halfway through an archive
// member.
type interruptReader struct {
	r      io.Reader
	limit  int
	total  int
	cancel context.CancelFunc
}

func (c *interruptReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.total += n
	if c.cancel != nil && c.total > c.limit {
		c.cancel()
		c.cancel = nil
	}
	return n, err
}

func collectFragments(t *testing.T, file *File) ([]Fragment, error) {
	t.Helper()

	var fragments []Fragment
	err := file.Fragments(context.Background(), func(fragment Fragment, err error) error {
		fragments = append(fragments, fragment)
		return nil
	})
	return fragments, err
}

// A member is only exposed once it has been completely covered: when the
// scan is interrupted halfway through a member, none of the member's
// fragments are published downstream.
func TestArchiveMemberExposedOnlyWhenFullyCovered(t *testing.T) {
	archive := makeAtomicTar(t, []atomicTarEntry{
		{name: "first.txt", body: "first chunk\n"},
		{name: "big.txt", body: strings.Repeat("padding\n", 50*1000)},
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	file := &File{
		Content:         &interruptReader{r: bytes.NewReader(archive), limit: 150 * 1000, cancel: cancel},
		Path:            "bundle.tar",
		MaxArchiveDepth: 1,
	}

	var fragments []Fragment
	err := file.Fragments(ctx, func(fragment Fragment, err error) error {
		fragments = append(fragments, fragment)
		return nil
	})
	require.Error(t, err)

	// Only the fully covered first member was exposed; the interrupted
	// member did not leak a single fragment.
	require.Len(t, fragments, 1)
	require.Equal(t, "bundle.tar!first.txt", fragments[0].FilePath)
}

// A completely scanned archive exposes every member, in order.
func TestArchiveCompleteMembersAllExposed(t *testing.T) {
	archive := makeAtomicTar(t, []atomicTarEntry{
		{name: "first.txt", body: "first chunk\n"},
		{name: "second.txt", body: "second chunk\n"},
	})

	fragments, err := collectFragments(t, &File{
		Content:         bytes.NewReader(archive),
		Path:            "bundle.tar",
		MaxArchiveDepth: 1,
	})
	require.NoError(t, err)
	require.Len(t, fragments, 2)
	require.Equal(t, "bundle.tar!first.txt", fragments[0].FilePath)
	require.Equal(t, "bundle.tar!second.txt", fragments[1].FilePath)
}
