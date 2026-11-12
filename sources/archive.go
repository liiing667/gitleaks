package sources

import (
	"errors"
	"path"
	"strings"
)

// Errors returned when an archive member name cannot be mapped to a safe
// logical path. They are only used to build structured diagnostics; callers
// skip the offending member instead of failing the whole scan.
var (
	errArchiveNameEmpty      = errors.New("archive member name is empty")
	errArchiveNameAbsolute   = errors.New("archive member name is absolute")
	errArchiveNameEscape     = errors.New("archive member name escapes the archive root")
	errArchiveNameSeparator  = errors.New("archive member name contains the inner path separator")
	errArchiveNameBackslash  = errors.New("archive member name contains a backslash")
	errArchiveNameNull       = errors.New("archive member name contains a null byte")
	errArchiveNameWindowsDir = errors.New("archive member name is a Windows drive or UNC path")
	errArchiveNameReserved   = errors.New("archive member name resolves to the archive root")
)

// secureArchivePath converts a raw archive member name (for example a ZIP or
// TAR header value) into a deterministic, non-escaping logical path.
//
// The returned path always uses forward slashes, is relative to the archive
// root, contains no "." or ".." segments and never contains the
// InnerPathSeparator ("!"), which is reserved for joining outer and inner
// paths in FullPath/fingerprints. This keeps path allowlists and fingerprints
// unambiguous: two members from different archives can never collapse onto
// the same identity, and a member can never match an allowlist by pretending
// to live outside the archive.
//
// A non-nil error means the name is unsafe or undecidable. The caller must
// skip the member and record a structured diagnostic rather than guessing a
// path. Names that are absolute, that escape the archive root ("..") or that
// contain the inner-path separator ("!") are all rejected.
func secureArchivePath(name string) (string, error) {
	if name == "" {
		return "", errArchiveNameEmpty
	}

	// NUL bytes are never legal in a logical path and would truncate the name
	// when passed to OS-level APIs.
	if strings.ContainsRune(name, 0) {
		return "", errArchiveNameNull
	}

	// Backslashes are path separators on Windows but literal characters on
	// POSIX. Treating them as separators would make the logical path platform
	// dependent, so reject the name instead of guessing.
	if strings.ContainsRune(name, '\\') {
		return "", errArchiveNameBackslash
	}

	// "!" is reserved as the outer!inner separator in FullPath/fingerprints.
	if strings.Contains(name, InnerPathSeparator) {
		return "", errArchiveNameSeparator
	}

	// Reject Windows drive letters (C:foo) and UNC paths (\\host\share).
	if isWindowsRooted(name) {
		return "", errArchiveNameWindowsDir
	}

	// Reject absolute paths outright: an archive member is always relative to
	// the archive root, and a leading slash would otherwise leak into both the
	// path allowlist and the outer!inner fingerprint.
	if strings.HasPrefix(name, "/") {
		return "", errArchiveNameAbsolute
	}

	cleaned := path.Clean(name)

	// Reject anything that resolves to the archive root (".", empty, ...).
	if cleaned == "." || cleaned == "" {
		return "", errArchiveNameReserved
	}

	// After cleaning, a ".." segment can only remain when the name walks above
	// the archive root; path.Clean would otherwise have folded inner ".."s.
	if cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", errArchiveNameEscape
	}

	return cleaned, nil
}

// isWindowsRooted reports whether name looks like a Windows drive-relative or
// UNC path (e.g. "C:foo", "C:/foo"). UNC names are already covered by the
// backslash check, but drive letters with forward slashes need their own.
func isWindowsRooted(name string) bool {
	if len(name) < 2 {
		return false
	}
	first := name[0]
	if (first >= 'a' && first <= 'z') || (first >= 'A' && first <= 'Z') {
		return name[1] == ':'
	}
	return false
}
