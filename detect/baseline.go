package detect

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/zricethezav/gitleaks/v8/report"
)

func IsNew(finding report.Finding, redact uint, baseline []report.Finding) bool {
	for _, b := range baseline {
		if baselineFindingCovers(finding, b, redact) {
			return false
		}
	}
	return true
}

func baselineFindingCovers(finding, baseline report.Finding, redact uint) bool {
	if finding.RuleID != baseline.RuleID {
		return false
	}

	// A fingerprint that belongs to a different commit is stale. Ignoring it
	// would let an old baseline entry suppress a leak found in a newer source
	// generation.
	if !report.FingerprintFitsGeneration(baseline) {
		return false
	}

	secretMatches, secretKnown := compareBaselineSecrets(finding, baseline, redact)
	if !secretMatches {
		return false
	}

	if isRenameMatch(finding, baseline) {
		// A rename is allowed to change the path, line, commit metadata, and
		// fingerprint. The secret and rule still have to identify the same
		// finding, which keeps a rotated secret visible.
		return true
	}

	if !report.FingerprintFitsGeneration(finding) {
		return false
	}
	if secretKnown && inferredRenameMatch(finding, baseline) {
		return true
	}
	if generationMismatch(finding, baseline) {
		return false
	}

	return baselineMetadataMatches(finding, baseline)
}

// baselineMetadataMatches compares the non-secret properties that describe a
// finding's location and provenance. Fingerprint is intentionally omitted:
// the fingerprint is derived from these fields and older/legacy formats must
// remain readable.
func baselineMetadataMatches(finding, baseline report.Finding) bool {
	return finding.Description == baseline.Description &&
		finding.StartLine == baseline.StartLine &&
		finding.EndLine == baseline.EndLine &&
		finding.StartColumn == baseline.StartColumn &&
		finding.EndColumn == baseline.EndColumn &&
		samePath(finding.File, baseline.File) &&
		finding.Author == baseline.Author &&
		finding.Email == baseline.Email &&
		finding.Date == baseline.Date &&
		finding.Message == baseline.Message &&
		finding.Entropy == baseline.Entropy
}

func generationMismatch(finding, baseline report.Finding) bool {
	return reportGeneration(finding) != reportGeneration(baseline)
}

func reportGeneration(finding report.Finding) string {
	if generation := finding.Generation(); generation != "" {
		return generation
	}
	if commit, ok := report.FingerprintCommit(finding.Fingerprint); ok {
		return commit
	}
	return ""
}

func compareBaselineSecrets(finding, baseline report.Finding, redact uint) (matches, known bool) {
	findingHashes := secretHashCandidates(finding)
	baselineHashes := secretHashCandidates(baseline)
	if len(findingHashes) > 0 && len(baselineHashes) > 0 {
		for hash := range findingHashes {
			if _, ok := baselineHashes[hash]; ok {
				return true, true
			}
		}
		return false, true
	}

	// Path-only rules and metadata-only baselines have no secret identity to
	// compare. Their location/commit fields continue to decide the match.
	if finding.Secret == "" && baseline.Secret == "" {
		return true, false
	}

	findingRedacted := report.IsRedactedValue(finding.Secret)
	baselineRedacted := report.IsRedactedValue(baseline.Secret)
	if redact == 0 || (!findingRedacted && !baselineRedacted) {
		return finding.Match == baseline.Match && finding.Secret == baseline.Secret, true
	}

	// A legacy baseline (or a caller using the old redacted report format) has
	// no digest with which to compare values. Preserve the historical
	// behaviour for those entries rather than turning every redacted report
	// into a false positive.
	return true, false
}

func secretHashCandidates(finding report.Finding) map[string]struct{} {
	hashes := make(map[string]struct{})
	if finding.Secret != "" && !report.IsRedactedValue(finding.Secret) {
		hashes[report.HashSecret(finding.Secret)] = struct{}{}
		// Support baselines produced by earlier implementations that bound
		// the digest to both the secret and its containing match.
		hashes[report.HashSecret(finding.Secret, finding.Match)] = struct{}{}
		return hashes
	}
	if finding.SecretHash != "" {
		hashes[strings.ToLower(finding.SecretHash)] = struct{}{}
	}
	return hashes
}

func isRenameMatch(finding, baseline report.Finding) bool {
	findingPrevious := finding.RenamedFrom()
	baselinePrevious := baseline.RenamedFrom()

	if renamedPathMatches(findingPrevious, baseline.File) ||
		renamedPathMatches(finding.PreviousFile, baseline.File) ||
		renamedPathMatches(finding.PreviousFilePath, baseline.File) ||
		renamedPathMatches(baselinePrevious, finding.File) ||
		renamedPathMatches(baseline.PreviousFile, finding.File) ||
		renamedPathMatches(baseline.PreviousFilePath, finding.File) {
		return true
	}

	// Follow rename chains even when the persisted baseline names an older
	// path than the immediate previous name. A secret-less (path-only) rule is
	// excluded because its identity is the path itself.
	if (finding.RenamedFrom() != "" || baseline.RenamedFrom() != "") &&
		(len(secretHashCandidates(finding)) > 0 || len(secretHashCandidates(baseline)) > 0) {
		return true
	}

	return finding.OriginalFile != "" &&
		baseline.OriginalFile != "" &&
		finding.File != baseline.File &&
		samePath(finding.OriginalFile, baseline.OriginalFile)
}

func renamedPathMatches(previous, current string) bool {
	return previous != "" && current != "" && samePath(previous, current)
}

// inferredRenameMatch handles sources that do not expose rename metadata,
// such as a directory scan before and after a move or a rewritten branch whose
// rename diff is no longer available. The secret and rule have already been
// matched, so a different path identifies the same logical leak. Same-path
// findings still have to agree on the source generation, which keeps an old
// baseline entry from hiding a different commit at the same location.
func inferredRenameMatch(finding, baseline report.Finding) bool {
	return !samePath(finding.File, baseline.File)
}

func samePath(a, b string) bool {
	return normalizePath(a) == normalizePath(b)
}

func normalizePath(value string) string {
	if value == "" {
		return ""
	}
	value = strings.ReplaceAll(value, "\\", "/")
	for strings.HasPrefix(value, "./") {
		value = strings.TrimPrefix(value, "./")
	}
	return filepath.Clean(value)
}

func LoadBaseline(baselinePath string) ([]report.Finding, error) {
	bytes, err := os.ReadFile(baselinePath)
	if err != nil {
		return nil, fmt.Errorf("could not open %s", baselinePath)
	}

	previousFindings, err := report.DecodeFindings(bytes)
	if err != nil {
		return nil, fmt.Errorf("the format of the file %s is not supported", baselinePath)
	}

	return normalizeBaseline(previousFindings), nil
}

func (d *Detector) AddBaseline(baselinePath string, source string) error {
	// A rejected baseline must not leave an older baseline active.
	d.baseline = nil
	d.baselinePath = ""

	if baselinePath != "" {
		absoluteSource, err := filepath.Abs(source)
		if err != nil {
			return err
		}

		absoluteBaseline, err := filepath.Abs(baselinePath)
		if err != nil {
			return err
		}

		relativeBaseline, err := filepath.Rel(absoluteSource, absoluteBaseline)
		if err != nil {
			return err
		}

		baseline, err := LoadBaseline(baselinePath)
		if err != nil {
			return err
		}

		d.baseline = baseline
		baselinePath = relativeBaseline

	}

	d.baselinePath = baselinePath
	return nil
}

// SetBaseline installs an in-memory baseline. It is primarily useful to
// library callers and tests that already decoded a report.
func (d *Detector) SetBaseline(baseline []report.Finding) error {
	normalized := normalizeBaseline(baseline)
	d.baseline = normalized
	d.baselinePath = ""
	return nil
}

// Baseline returns a copy of the findings currently used as a baseline.
func (d *Detector) Baseline() []report.Finding {
	return append([]report.Finding(nil), d.baseline...)
}

func normalizeBaseline(baseline []report.Finding) []report.Finding {
	normalized := make([]report.Finding, len(baseline))
	copy(normalized, baseline)
	for i := range normalized {
		finding := &normalized[i]
		if finding.SecretHash == "" && finding.Secret != "" && !report.IsRedactedValue(finding.Secret) {
			finding.SecretHash = report.HashSecret(finding.Secret)
		}
		if finding.Fingerprint == "" && finding.File != "" && finding.RuleID != "" {
			finding.Fingerprint = report.FindingFingerprint(*finding)
		}
	}
	return normalized
}
