package report

import (
	"fmt"
	"strconv"
	"strings"
)

// FindingFingerprint returns the canonical fingerprint for a finding. It is
// the single source used by detection, baseline entries, and report writers so
// all of them describe the same finding.
func FindingFingerprint(f Finding) string {
	if f.Commit != "" {
		return fmt.Sprintf("%s:%s:%s:%d", f.Commit, f.File, f.RuleID, f.StartLine)
	}
	if generation := explicitSourceGeneration(f); generation != "" {
		return fmt.Sprintf("%s:%s:%s:%d", generation, f.File, f.RuleID, f.StartLine)
	}
	return GlobalFingerprint(f)
}

// GlobalFingerprint returns the commit-independent fingerprint used by
// .gitleaksignore and by scans that do not have a commit.
func GlobalFingerprint(f Finding) string {
	return fmt.Sprintf("%s:%s:%d", f.File, f.RuleID, f.StartLine)
}

// FingerprintCommit extracts the commit prefix from a commit-scoped
// fingerprint. The boolean is false for legacy/global fingerprints or values
// that are not valid gitleaks fingerprints.
func FingerprintCommit(fingerprint string) (string, bool) {
	parts := strings.Split(fingerprint, ":")
	if len(parts) < 4 {
		return "", false
	}
	if _, err := strconv.Atoi(parts[len(parts)-1]); err != nil {
		return "", false
	}

	commit := parts[0]
	if !looksLikeCommit(commit) {
		return "", false
	}
	return commit, true
}

// FingerprintFitsGeneration reports whether a persisted fingerprint was made
// for the finding's current source generation. Empty, legacy, and malformed
// fingerprints are accepted for compatibility; a well-formed fingerprint for
// another commit is stale and must not be used to suppress a finding.
func FingerprintFitsGeneration(f Finding) bool {
	commit, ok := FingerprintCommit(f.Fingerprint)
	if !ok {
		return true
	}

	for _, generation := range []string{f.SourceCommit, f.Commit} {
		if generation != "" && generation != commit {
			return false
		}
	}
	for _, generation := range []string{f.SourceGeneration, f.ScanGeneration} {
		if looksLikeCommit(generation) && generation != commit {
			return false
		}
	}
	return true
}

func explicitSourceGeneration(f Finding) string {
	switch {
	case f.SourceGeneration != "":
		return f.SourceGeneration
	case f.ScanGeneration != "":
		return f.ScanGeneration
	default:
		return f.SourceCommit
	}
}

func looksLikeCommit(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for _, r := range value {
		if r == '/' || r == '\\' || r == '.' || r == ' ' || r == '\t' {
			return false
		}
	}
	return true
}
