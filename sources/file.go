package sources

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/h2non/filetype"
	"github.com/mholt/archives"
	"github.com/rs/zerolog"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/logging"
)

const defaultBufferSize = 100 * 1_000 // 100kb
const InnerPathSeparator = "!"

type seekReaderAt interface {
	io.Reader
	io.ReaderAt
	io.Seeker
}

// File is a source for yielding fragments from a file or other reader
type File struct {
	// Content provides a reader to the file's content
	Content io.Reader
	// Path is the logical path of the file. For archive members it is the
	// sanitized path relative to the archive root, never a temporary path.
	Path string
	// Symlink represents a symlink to the file if that's how it was discovered
	Symlink string
	// Root is the controlled scan root frozen when the source was discovered.
	// Archive members inherit it, and it is never replaced by a temporary
	// extraction path.
	Root string
	// Buffer is used for reading the content in chunks
	Buffer []byte
	// Config is the gitleaks config used for shouldSkipPath. If not set, then
	// shouldSkipPath is ignored
	Config *config.Config
	// outerPaths is the list of container paths (e.g. archives) that lead to
	// this file
	outerPaths []string
	// MaxArchiveDepth limits how deep the sources will explore nested archives
	MaxArchiveDepth int
	// archiveDepth is the current archive nesting depth
	archiveDepth int
	// link indicates Content is the declaration of an archive link rather
	// than the target's bytes. Link declarations must never be interpreted as
	// nested archives.
	link bool
	// chainValidated records that the parent already validated the frozen
	// logical container chain before opening this member.
	chainValidated bool
}

// Fragments yields fragments for the this source
func (s *File) Fragments(ctx context.Context, yield FragmentsFunc) error {
	if !s.withinControlledRoot() {
		logging.Warn().
			Str("path", s.FullPath()).
			Str("root", s.Root).
			Str("stage", "source_discovery").
			Msg("skipping source: outside controlled root")
		return nil
	}
	if len(s.outerPaths) > 0 && !s.chainValidated {
		if err := s.validateArchiveContainer(); err != nil {
			logging.Warn().
				Str("path", s.FullPath()).
				Str("stage", "archive_containment").
				Str("reason", err.Error()).
				Msg("skipping archive member: unsafe or ambiguous container path")
			return nil
		}
	}
	if s.link {
		return s.fileFragments(ctx, bufio.NewReader(s.Content), yield)
	}

	format, _, err := archives.Identify(ctx, s.Path, nil)
	// Process the file as an archive if there's no error && Identify returns
	// a format; but if there's an error or no format, just swallow the error
	// and fall back on treating it like a normal file and let fileFragments
	// decide what to do with it.
	if err == nil && format != nil {
		if s.archiveDepth+1 > s.MaxArchiveDepth {
			var event *zerolog.Event

			// Warn if the feature is enabled; else emit a trace log.
			if s.MaxArchiveDepth != 0 {
				event = logging.Warn()
			} else {
				event = logging.Trace()
			}

			event.Str(
				"path", s.FullPath(),
			).Int(
				"max_archive_depth", s.MaxArchiveDepth,
			).Msg("skipping archive: exceeds max archive depth")

			return nil
		}
		if len(s.outerPaths) == 0 {
			if err := s.validateArchiveContainer(); err != nil {
				logging.Warn().
					Str("path", s.FullPath()).
					Str("stage", "archive_containment").
					Str("reason", err.Error()).
					Msg("skipping archive: unsafe or ambiguous container path")
				return nil
			}
		}
		if extractor, ok := format.(archives.Extractor); ok {
			return s.extractorFragments(ctx, extractor, s.Content, yield)
		}
		if decompressor, ok := format.(archives.Decompressor); ok {
			return s.decompressorFragments(ctx, decompressor, s.Content, yield)
		}
		logging.Warn().Str("path", s.FullPath()).Msg("skipping unknown archive type")
	}

	return s.fileFragments(ctx, bufio.NewReader(s.Content), yield)
}

// extractorFragments recursively crawls archives and yields fragments
func (s *File) extractorFragments(ctx context.Context, extractor archives.Extractor, reader io.Reader, yield FragmentsFunc) error {
	// Archive inspection and extraction both operate on the same immutable,
	// seekable reader. If the caller supplied a stream, spool it first. The
	// temporary file is only a byte source: it never contributes to a
	// member's logical identity or finding path.
	archiveReader, cleanup, err := archiveReaderFor(reader)
	if err != nil {
		logging.Error().Err(err).Str("path", s.FullPath()).Msg("could not prepare archive reader")
		return nil
	}
	defer cleanup()

	plan, err := s.planArchive(ctx, extractor, archiveReader)
	if err != nil {
		logging.Error().Err(err).Str("path", s.FullPath()).Msg("could not inspect archive")
		return err
	}
	if err := rewindArchiveReader(archiveReader); err != nil {
		logging.Error().Err(err).Str("path", s.FullPath()).Msg("could not rewind archive reader")
		return nil
	}

	outerPaths := s.outerPathsWithSelf()
	return extractor.Extract(ctx, archiveReader, func(_ context.Context, d archives.FileInfo) error {
		if d.IsDir() {
			return nil
		}

		// Validate the declared member identity and quarantine unsafe,
		// ambiguous, or cyclic members before opening their content or
		// applying path allowlists.
		member, err := secureArchivePath(d.NameInArchive)
		if err != nil {
			s.logArchiveMemberSkipped(d.NameInArchive, err)
			return nil
		}
		if reason, isolated := plan.isolatedReason(member); isolated {
			s.logArchiveMemberSkipped(d.NameInArchive, reason)
			return nil
		}

		if s.Config != nil && shouldSkipPath(s.Config, member) {
			logging.Debug().
				Str("path", s.FullPath()).
				Str("archive_member", member).
				Msg("skipping file: global allowlist")
			return nil
		}

		if d.LinkTarget != "" {
			target, err := secureArchiveLinkTarget(member, d.LinkTarget)
			if err != nil {
				s.logArchiveMemberSkipped(d.NameInArchive, err)
				return nil
			}
			if reason, isolated := plan.isolatedReason(target); isolated {
				s.logArchiveMemberSkipped(d.NameInArchive, reason)
				return nil
			}
			if _, isDir := plan.dirs[target]; isDir {
				s.logArchiveMemberSkipped(d.NameInArchive, errArchiveLinkDirectory)
				return nil
			}
			if _, exists := plan.members[target]; !exists {
				s.logArchiveMemberSkipped(d.NameInArchive, errArchiveLinkMissing)
				return nil
			}
			if s.Config != nil && shouldSkipPath(s.Config, target) {
				logging.Debug().
					Str("path", s.FullPath()).
					Str("archive_member", member).
					Str("archive_link_target", target).
					Msg("skipping file: global allowlist")
				return nil
			}
		}

		file := &File{
			Path:            member,
			Symlink:         s.Symlink,
			Root:            s.Root,
			Config:          s.Config,
			outerPaths:      outerPaths,
			MaxArchiveDepth: s.MaxArchiveDepth,
			archiveDepth:    s.archiveDepth + 1,
			link:            d.LinkTarget != "",
			// The parent validated its frozen chain and the member path was
			// sanitized above, before any content is opened.
			chainValidated: true,
		}

		innerReader, err := d.Open()
		if err != nil {
			logging.Error().
				Err(err).
				Str("path", s.FullPath()).
				Str("archive_member", d.NameInArchive).
				Msg("could not open archive inner file")
			return nil
		}
		file.Content = innerReader

		memberErr := file.Fragments(ctx, yield)
		closeErr := innerReader.Close()
		if memberErr != nil {
			return memberErr
		}
		if closeErr != nil {
			logging.Debug().
				Err(closeErr).
				Str("path", s.FullPath()).
				Str("archive_member", d.NameInArchive).
				Msg("could not close archive inner file")
		}

		return nil
	})
}

// archiveReaderFor returns a seekable reader for an archive. A non-seekable
// stream is spooled to a private temporary file and cleaned up by the returned
// function. The temporary name is deliberately not exposed through File.Path
// or FullPath.
func archiveReaderFor(reader io.Reader) (seekReaderAt, func(), error) {
	if seekable, ok := reader.(seekReaderAt); ok {
		// A type can implement the interfaces while the underlying stream is
		// not actually seekable. Verify before relying on a rewind.
		if _, err := seekable.Seek(0, io.SeekCurrent); err == nil {
			return seekable, func() {}, nil
		}
	}

	tmpfile, err := os.CreateTemp("", "gitleaks-archive-")
	if err != nil {
		return nil, nil, err
	}
	cleanup := func() {
		_ = tmpfile.Close()
		_ = os.Remove(tmpfile.Name())
	}

	if _, err := io.Copy(tmpfile, reader); err != nil {
		cleanup()
		return nil, nil, err
	}
	if _, err := tmpfile.Seek(0, io.SeekStart); err != nil {
		cleanup()
		return nil, nil, err
	}

	return tmpfile, cleanup, nil
}

func rewindArchiveReader(reader seekReaderAt) error {
	_, err := reader.Seek(0, io.SeekStart)
	return err
}

// withinControlledRoot reports whether the File was discovered under Root.
// Archive members are validated through their container chain instead.
func (s *File) withinControlledRoot() bool {
	if s.Root == "" || s.Path == "" || len(s.outerPaths) > 0 {
		return true
	}
	if !logicalFileWithinRoot(s.Root, s.Path) {
		return false
	}
	if resolved, err := filepath.EvalSymlinks(s.Path); err == nil && !WithinRoot(s.Root, resolved) {
		return false
	}
	return true
}

// validateArchiveContainer ensures that a logical archive chain is
// unambiguous and that the outermost container came from the controlled root.
func (s *File) validateArchiveContainer() error {
	parts := s.outerPathsWithSelf()
	for i, part := range parts {
		if strings.ContainsRune(part, 0) {
			return errArchiveContainerNull
		}
		if strings.Contains(part, InnerPathSeparator) {
			return errArchiveContainerSeparator
		}
		if i == 0 {
			if s.Root != "" {
				if !logicalFileWithinRoot(s.Root, part) {
					return errArchiveContainerOutsideRoot
				}
				if resolved, err := filepath.EvalSymlinks(part); err == nil && !WithinRoot(s.Root, resolved) {
					return errArchiveContainerOutsideRoot
				}
			}
			continue
		}
		if _, err := secureArchivePath(part); err != nil {
			return err
		}
	}

	return nil
}

// outerPathsWithSelf returns a frozen copy of the logical container chain.
// Copying also avoids slice aliasing between sibling archive members.
func (s *File) outerPathsWithSelf() []string {
	outerPaths := make([]string, len(s.outerPaths)+1)
	copy(outerPaths, s.outerPaths)
	outerPaths[len(s.outerPaths)] = filepath.ToSlash(s.Path)
	return outerPaths
}

func (s *File) logArchiveMemberSkipped(rawName string, err error) {
	logging.Warn().
		Str("path", s.FullPath()).
		Str("archive_member", rawName).
		Str("stage", "archive_containment").
		Str("reason", err.Error()).
		Msg("skipping archive member: unsafe path")
}

// decompressorFragments recursively crawls archives and yields fragments
func (s *File) decompressorFragments(ctx context.Context, decompressor archives.Decompressor, reader io.Reader, yield FragmentsFunc) error {
	innerReader, err := decompressor.OpenReader(reader)
	if err != nil {
		logging.Error().Str("path", s.FullPath()).Msg("could read compressed file")
		return nil
	}

	if err := s.fileFragments(ctx, bufio.NewReader(innerReader), yield); err != nil {
		_ = innerReader.Close()
		return err
	}

	_ = innerReader.Close()
	return nil
}

// fileFragments reads the file into fragments to yield
func (s *File) fileFragments(ctx context.Context, reader *bufio.Reader, yield FragmentsFunc) error {
	// Create a buffer if the caller hasn't provided one
	if s.Buffer == nil {
		s.Buffer = make([]byte, defaultBufferSize)
	}

	totalLines := 0
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			fragment := Fragment{
				FilePath: s.FullPath(),
			}

			n, err := reader.Read(s.Buffer)
			if n == 0 {
				if err != nil && err != io.EOF {
					return yield(fragment, fmt.Errorf("could not read file: %w", err))
				}

				return nil
			}

			// Only check the filetype at the start of file.
			if totalLines == 0 {
				// TODO: could other optimizations be introduced here?
				if mimetype, err := filetype.Match(s.Buffer[:n]); err != nil {
					return yield(
						fragment,
						fmt.Errorf("could not read file: could not determine type: %w", err),
					)
				} else if mimetype.MIME.Type == "application" {
					logging.Debug().
						Str("mime_type", mimetype.MIME.Value).
						Str("path", s.FullPath()).
						Msgf("skipping binary file")

					return nil
				}
			}

			// Try to split chunks across large areas of whitespace, if possible.
			peekBuf := bytes.NewBuffer(s.Buffer[:n])
			if err := readUntilSafeBoundary(reader, n, maxPeekSize, peekBuf); err != nil {
				return yield(
					fragment,
					fmt.Errorf("could not read file: could not read until safe boundary: %w", err),
				)
			}

			fragment.Raw = peekBuf.String()
			fragment.Bytes = peekBuf.Bytes()
			fragment.StartLine = totalLines + 1

			// Count the number of newlines in this chunk
			totalLines += strings.Count(fragment.Raw, "\n")

			if len(s.Symlink) > 0 {
				fragment.SymlinkFile = s.Symlink
			}

			if isWindows {
				fragment.FilePath = filepath.ToSlash(fragment.FilePath)
				fragment.SymlinkFile = filepath.ToSlash(s.Symlink)
				fragment.WindowsFilePath = s.FullPath()
			}

			// log errors but continue since there's content
			if err != nil && err != io.EOF {
				logging.Warn().Err(err).Msgf("issue reading file")
			}

			// Done with the file!
			if err == io.EOF {
				return yield(fragment, nil)
			}

			if err := yield(fragment, err); err != nil {
				return err
			}
		}
	}
}

// FullPath returns the File.Path with any preceding outer paths
func (s *File) FullPath() string {
	if len(s.outerPaths) > 0 {
		parts := make([]string, len(s.outerPaths)+1)
		// outerPaths have already been normalized to slash
		copy(parts, s.outerPaths)
		parts[len(s.outerPaths)] = s.Path
		return strings.Join(parts, InnerPathSeparator)
	}

	return s.Path
}
