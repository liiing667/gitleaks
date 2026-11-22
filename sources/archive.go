package sources

import (
	"context"
	"errors"
	"path"
	"strings"

	"github.com/mholt/archives"
)

// Archive member names and link targets are attacker controlled. They are
// treated as logical paths relative to the archive root, never as host paths.
// Rejecting undecidable names keeps path allowlists, fingerprints, and report
// consumers from disagreeing about which object a finding refers to.
var (
	errArchiveNameEmpty        = errors.New("archive member name is empty")
	errArchiveNameAbsolute     = errors.New("archive member name is absolute")
	errArchiveNameEscape       = errors.New("archive member name escapes the archive root")
	errArchiveNameSeparator    = errors.New("archive member name contains the inner path separator")
	errArchiveNameBackslash    = errors.New("archive member name contains a backslash")
	errArchiveNameNull         = errors.New("archive member name contains a null byte")
	errArchiveNameWindowsDrive = errors.New("archive member name is a Windows drive path")
	errArchiveNameReserved     = errors.New("archive member name resolves to the archive root")
	errArchiveNameDuplicate    = errors.New("archive member name collides with another member")

	errArchiveLinkEmpty        = errors.New("archive link target is empty")
	errArchiveLinkAbsolute     = errors.New("archive link target is absolute")
	errArchiveLinkEscape       = errors.New("archive link target escapes the archive root")
	errArchiveLinkSeparator    = errors.New("archive link target contains the inner path separator")
	errArchiveLinkBackslash    = errors.New("archive link target contains a backslash")
	errArchiveLinkNull         = errors.New("archive link target contains a null byte")
	errArchiveLinkWindowsDrive = errors.New("archive link target is a Windows drive path")
	errArchiveLinkReserved     = errors.New("archive link target resolves to the archive root")
	errArchiveLinkCycle        = errors.New("archive link cycle")
	errArchiveLinkTooDeep      = errors.New("archive link chain is too deep")
	errArchiveLinkMissing      = errors.New("archive link target is missing")
	errArchiveLinkDirectory    = errors.New("archive link target is a directory")
	errArchiveLinkIsolated     = errors.New("archive link target is isolated")

	errArchiveContainerOutsideRoot = errors.New("archive container is outside the controlled root")
	errArchiveContainerSeparator   = errors.New("archive container path contains the inner path separator")
	errArchiveContainerNull        = errors.New("archive container path contains a null byte")
)

// secureArchivePath converts a raw archive member name into a deterministic
// logical path relative to the archive root.
//
// The result always uses forward slashes and never contains "." or ".."
// segments, a leading separator, a Windows drive prefix, a NUL byte, a
// backslash, or the InnerPathSeparator ("!"). A non-nil error means the name
// is unsafe or ambiguous and the member must be skipped before it is opened.
func secureArchivePath(name string) (string, error) {
	if name == "" {
		return "", errArchiveNameEmpty
	}
	if strings.ContainsRune(name, 0) {
		return "", errArchiveNameNull
	}
	// Backslashes are separators on Windows and literal characters on POSIX.
	// Treating them as either would make the logical identity platform
	// dependent, so reject them instead of guessing.
	if strings.ContainsRune(name, '\\') {
		return "", errArchiveNameBackslash
	}
	if strings.Contains(name, InnerPathSeparator) {
		return "", errArchiveNameSeparator
	}
	if isWindowsDrivePath(name) {
		return "", errArchiveNameWindowsDrive
	}
	if path.IsAbs(name) {
		return "", errArchiveNameAbsolute
	}

	clean := path.Clean(name)
	if clean == "" || clean == "." {
		return "", errArchiveNameReserved
	}
	if clean == ".." || strings.HasPrefix(clean, "../") {
		return "", errArchiveNameEscape
	}
	// path.Clean cannot introduce an absolute prefix for a relative input,
	// but keep this as a final invariant in case the implementation changes.
	if path.IsAbs(clean) || isWindowsDrivePath(clean) {
		return "", errArchiveNameAbsolute
	}

	return clean, nil
}

// secureArchiveLinkTarget resolves a link target declared by an archive
// member against that member's logical location and verifies that the
// resolved target stays inside the archive root.
func secureArchiveLinkTarget(memberPath, target string) (string, error) {
	cleanMember, err := secureArchivePath(memberPath)
	if err != nil {
		return "", err
	}
	memberPath = cleanMember
	if target == "" {
		return "", errArchiveLinkEmpty
	}
	if strings.ContainsRune(target, 0) {
		return "", errArchiveLinkNull
	}
	if strings.ContainsRune(target, '\\') {
		return "", errArchiveLinkBackslash
	}
	if strings.Contains(target, InnerPathSeparator) {
		return "", errArchiveLinkSeparator
	}
	if isWindowsDrivePath(target) {
		return "", errArchiveLinkWindowsDrive
	}
	if path.IsAbs(target) {
		return "", errArchiveLinkAbsolute
	}

	cleanTarget := path.Clean(target)
	if cleanTarget == "" || cleanTarget == "." {
		return "", errArchiveLinkReserved
	}

	resolved := path.Clean(path.Join(path.Dir(memberPath), cleanTarget))
	if resolved == "" || resolved == "." {
		return "", errArchiveLinkReserved
	}
	if resolved == ".." || strings.HasPrefix(resolved, "../") {
		return "", errArchiveLinkEscape
	}
	if path.IsAbs(resolved) || isWindowsDrivePath(resolved) {
		return "", errArchiveLinkAbsolute
	}

	return resolved, nil
}

// isWindowsDrivePath reports whether p starts with a Windows drive prefix
// (for example "C:" or "C:/file"). path.Clean is intentionally
// platform-independent, so this check has to be explicit.
func isWindowsDrivePath(p string) bool {
	if len(p) < 2 || p[1] != ':' {
		return false
	}
	c := p[0]
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// archivePlan is a metadata-only view of one archive. It is built before any
// member content is opened so escaping links and cycles can be quarantined
// before a reader is handed to the detector.
type archivePlan struct {
	members  map[string]int
	dirs     map[string]struct{}
	links    map[string]string
	isolated map[string]error
}

func newArchivePlan() *archivePlan {
	return &archivePlan{
		members:  make(map[string]int),
		dirs:     make(map[string]struct{}),
		links:    make(map[string]string),
		isolated: make(map[string]error),
	}
}

func (p *archivePlan) observe(d archives.FileInfo) {
	member, err := secureArchivePath(d.NameInArchive)
	if err != nil {
		// The extraction pass reports the raw name and reason. There is no
		// safe logical identity to record here.
		return
	}
	if d.IsDir() {
		p.dirs[member] = struct{}{}
		return
	}

	p.members[member]++
	if d.LinkTarget == "" {
		return
	}

	target, err := secureArchiveLinkTarget(member, d.LinkTarget)
	if err != nil {
		p.isolate(member, err)
		return
	}
	p.links[member] = target
}

func (p *archivePlan) isolate(member string, reason error) {
	if _, exists := p.isolated[member]; !exists {
		p.isolated[member] = reason
	}
}

func (p *archivePlan) isolatedReason(member string) (error, bool) {
	reason, ok := p.isolated[member]
	return reason, ok
}

// finalize rejects ambiguous member identities and links whose target is
// missing, a directory, or part of a loop. A link to an isolated member is
// isolated as well so the decision does not depend on extraction order.
func (p *archivePlan) finalize() {
	for member, count := range p.members {
		if count > 1 {
			p.isolate(member, errArchiveNameDuplicate)
		}
	}

	for link := range p.links {
		if _, isolated := p.isolated[link]; isolated {
			continue
		}
		resolved, err := p.resolve(link)
		if err != nil {
			p.isolate(link, err)
			continue
		}
		if _, isDir := p.dirs[resolved]; isDir {
			p.isolate(link, errArchiveLinkDirectory)
			continue
		}
		if _, exists := p.members[resolved]; !exists {
			p.isolate(link, errArchiveLinkMissing)
		}
	}

	for changed := true; changed; {
		changed = false
		for link := range p.links {
			if _, isolated := p.isolated[link]; isolated {
				continue
			}
			resolved, err := p.resolve(link)
			if err != nil {
				p.isolate(link, err)
				changed = true
				continue
			}
			if _, isolated := p.isolated[resolved]; isolated {
				p.isolate(link, errArchiveLinkIsolated)
				changed = true
			}
		}
	}
}

func (p *archivePlan) resolve(start string) (string, error) {
	seen := make(map[string]struct{}, len(p.links))
	current := start
	for {
		if _, ok := seen[current]; ok {
			return "", errArchiveLinkCycle
		}
		seen[current] = struct{}{}
		// The chain may contain every link plus one final non-link member.
		if len(seen) > len(p.links)+1 {
			return "", errArchiveLinkTooDeep
		}

		target, isLink := p.links[current]
		if !isLink {
			return current, nil
		}
		current = target
	}
}

// planArchive builds the metadata plan for one extractor. The reader must be
// seekable so the same immutable archive can be inspected and then scanned
// without deriving any identity from a temporary spool file.
func (s *File) planArchive(ctx context.Context, extractor archives.Extractor, reader seekReaderAt) (*archivePlan, error) {
	if err := rewindArchiveReader(reader); err != nil {
		return nil, err
	}

	plan := newArchivePlan()
	if err := extractor.Extract(ctx, reader, func(_ context.Context, d archives.FileInfo) error {
		plan.observe(d)
		return nil
	}); err != nil {
		return nil, err
	}
	plan.finalize()
	return plan, nil
}
