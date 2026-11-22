package sources

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/mholt/archives"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/logging"
)

const maxPeekSize = 25 * 1_000 // 10kb
var isWhitespace [256]bool
var isWindows = runtime.GOOS == "windows"

// ErrPathOutsideRoot is returned when a source path resolves outside the
// controlled scan root that was frozen when the source was discovered.
var ErrPathOutsideRoot = errors.New("path resolves outside the controlled root")

func init() {
	// define whitespace characters
	isWhitespace[' '] = true
	isWhitespace['\t'] = true
	isWhitespace['\n'] = true
	isWhitespace['\r'] = true
}

// WithinRoot reports whether candidate is inside root. It first compares
// cleaned absolute paths and, when that fails, compares resolved paths so a
// symlinked ancestor does not split one logical root into two identities.
// Callers that admit filesystem objects must still resolve the candidate
// immediately before opening it (see OpenControlled).
func WithinRoot(root, candidate string) bool {
	if root == "" {
		return true
	}
	if candidate == "" {
		return false
	}

	absRoot, err := filepath.Abs(root)
	if err != nil {
		return false
	}
	absCandidate, err := filepath.Abs(candidate)
	if err != nil {
		return false
	}

	if withinLexicalRoot(absRoot, absCandidate) {
		return true
	}

	// A source path may itself contain a symlinked directory (for example a
	// temp directory under /var on some platforms). Fall back to comparing
	// resolved paths before rejecting the candidate.
	resolvedRoot, err := filepath.EvalSymlinks(absRoot)
	if err != nil {
		return false
	}
	resolvedCandidate, err := filepath.EvalSymlinks(absCandidate)
	if err != nil {
		return false
	}
	return withinLexicalRoot(resolvedRoot, resolvedCandidate)
}

func withinLexicalRoot(absRoot, absCandidate string) bool {
	rel, err := filepath.Rel(absRoot, absCandidate)
	if err != nil || filepath.IsAbs(rel) {
		return false
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return false
	}

	return true
}

// logicalFileWithinRoot is like WithinRoot but treats a non-existent relative
// path as a logical path rooted at root. This keeps in-memory sources (which
// provide Content directly) usable while still rejecting real paths outside
// the controlled root.
func logicalFileWithinRoot(root, path string) bool {
	if root == "" || path == "" {
		return true
	}
	if WithinRoot(root, path) {
		return true
	}
	if filepath.IsAbs(path) {
		return false
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		return false
	}
	return WithinRoot(root, filepath.Join(root, path))
}

// controlledRootFor freezes a containment root for a discovered source. When
// the source is inside a git worktree, the worktree root is used so existing
// repository-relative links keep working. Otherwise the source directory is
// the root. A source outside any worktree cannot pull a sibling directory into
// the scan through a link.
func controlledRootFor(sourcePath string) string {
	absSource, err := filepath.Abs(sourcePath)
	if err != nil {
		absSource = filepath.Clean(sourcePath)
	}
	if resolved, err := filepath.EvalSymlinks(absSource); err == nil {
		absSource = resolved
	}

	if info, err := os.Stat(absSource); err == nil && info.IsDir() {
		if root := findGitRoot(absSource); root != "" {
			return root
		}
		return absSource
	}

	if root := findGitRoot(absSource); root != "" {
		return root
	}
	return filepath.Dir(absSource)
}

func findGitRoot(absPath string) string {
	dir := absPath
	if info, err := os.Stat(dir); err == nil && !info.IsDir() {
		dir = filepath.Dir(dir)
	}

	for {
		if isGitWorktree(dir) {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

// isGitWorktree distinguishes a real worktree from an empty or stale ".git"
// directory. This prevents an unrelated parent directory from widening the
// controlled root for temp-directory scans.
func isGitWorktree(dir string) bool {
	gitPath := filepath.Join(dir, ".git")
	info, err := os.Stat(gitPath)
	if err != nil {
		return false
	}
	if info.IsDir() {
		_, err := os.Stat(filepath.Join(gitPath, "HEAD"))
		return err == nil
	}

	data, err := os.ReadFile(gitPath)
	if err != nil {
		return false
	}
	const prefix = "gitdir:"
	line := strings.TrimSpace(string(data))
	if len(line) < len(prefix) || !strings.EqualFold(line[:len(prefix)], prefix) {
		return false
	}
	target := strings.TrimSpace(line[len(prefix):])
	if !filepath.IsAbs(target) {
		target = filepath.Join(dir, target)
	}
	_, err = os.Stat(target)
	return err == nil
}

// OpenControlled opens path only after resolving symlinks and checking that
// the resolved target is still inside root. It keeps the "quarantine before
// read" boundary for both source discovery and later consumers.
func OpenControlled(root, path string) (*os.File, error) {
	if root != "" {
		if absRoot, err := filepath.Abs(root); err == nil {
			root = absRoot
		}
		if resolvedRoot, err := filepath.EvalSymlinks(root); err == nil {
			root = resolvedRoot
		}
		resolved, err := filepath.EvalSymlinks(path)
		if err != nil {
			return nil, err
		}
		if !WithinRoot(root, resolved) {
			return nil, ErrPathOutsideRoot
		}
	}

	return os.Open(path)
}

// isArchive does a light check to see if the provided path is an archive or
// compressed file. The File source already does this, so this exists mainly
// to avoid expensive calls before sending things to the File source
func isArchive(ctx context.Context, path string) bool {
	format, _, err := archives.Identify(ctx, path, nil)
	return err == nil && format != nil
}

// shouldSkipPath checks a path against all the allowlists to see if it can
// be skipped
func shouldSkipPath(cfg *config.Config, path string) bool {
	if cfg == nil {
		logging.Trace().Str("path", path).Msg("not skipping path because config is nil")
		return false
	}

	for _, a := range cfg.Allowlists {
		if a.PathAllowed(path) ||
			// TODO: Remove this in v9.
			// This is an awkward hack to mitigate https://github.com/gitleaks/gitleaks/issues/1641.
			(isWindows && a.PathAllowed(filepath.ToSlash(path))) {
			return true
		}
	}

	return false
}

// readUntilSafeBoundary consumes |f| until it finds two consecutive `\n` characters, up to |maxPeekSize|.
// This hopefully avoids splitting. (https://github.com/gitleaks/gitleaks/issues/1651)
func readUntilSafeBoundary(r *bufio.Reader, n int, maxPeekSize int, peekBuf *bytes.Buffer) error {
	if peekBuf.Len() == 0 {
		return nil
	}

	// Does the buffer end in consecutive newlines?
	var (
		data         = peekBuf.Bytes()
		lastChar     = data[len(data)-1]
		newlineCount = 0 // Tracks consecutive newlines
	)

	if isWhitespace[lastChar] {
		for i := len(data) - 1; i >= 0; i-- {
			lastChar = data[i]
			if lastChar == '\n' {
				newlineCount++

				// Stop if two consecutive newlines are found
				if newlineCount >= 2 {
					return nil
				}
			} else if isWhitespace[lastChar] {
				// The presence of other whitespace characters (`\r`, ` `, `\t`) shouldn't reset the count.
				// (Intentionally do nothing.)
			} else {
				break
			}
		}
	}

	// If not, read ahead until we (hopefully) find some.
	newlineCount = 0
	for {
		data = peekBuf.Bytes()
		// Check if the last character is a newline.
		lastChar = data[len(data)-1]
		if lastChar == '\n' {
			newlineCount++

			// Stop if two consecutive newlines are found
			if newlineCount >= 2 {
				break
			}
		} else if isWhitespace[lastChar] {
			// The presence of other whitespace characters (`\r`, ` `, `\t`) shouldn't reset the count.
			// (Intentionally do nothing.)
		} else {
			newlineCount = 0 // Reset if a non-newline character is found
		}

		// Stop growing the buffer if it reaches maxSize
		if (peekBuf.Len() - n) >= maxPeekSize {
			break
		}

		// Read additional data into a temporary buffer
		b, err := r.ReadByte()
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		peekBuf.WriteByte(b)
	}
	return nil
}
