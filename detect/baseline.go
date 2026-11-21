package detect

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/zricethezav/gitleaks/v8/report"
)

func IsNew(finding report.Finding, redact uint, baseline []report.Finding) bool {
	findingHashes := secretHashCandidates(finding)
	for _, b := range baseline {
		if baselineMatches(finding, b, redact, findingHashes) {
			return false
		}
	}
	return true
}

func baselineMatches(finding, baseline report.Finding, redact uint, findingHashes map[string]struct{}) bool {
	baselineHashes := secretHashCandidates(baseline)

	// Preserve the historical comparison whenever it can prove the finding is
	// the same. This keeps older baselines behaving exactly as before.
	if baselineMetadataMatches(finding, baseline) &&
		baselineSecretMatches(finding, baseline, redact, findingHashes, baselineHashes) {
		return true
	}

	// Description and entropy are derived from the active configuration. A
	// rule description change should not turn an otherwise identical finding
	// into a new one. Use the stable identity whenever both sides have a
	// comparable secret, including plaintext-only baselines.
	if len(findingHashes) == 0 || len(baselineHashes) == 0 {
		return false
	}
	return stableIdentityMatches(finding, baseline) &&
		secretHashesOverlap(findingHashes, baselineHashes)
}

func baselineMetadataMatches(finding, baseline report.Finding) bool {
	return stableIdentityMatches(finding, baseline) &&
		finding.Description == baseline.Description &&
		finding.Entropy == baseline.Entropy
}

func stableIdentityMatches(finding, baseline report.Finding) bool {
	// Fingerprint is intentionally omitted. Its format is an output detail; a
	// format change must not make existing baseline entries stop matching.
	return finding.RuleID == baseline.RuleID &&
		finding.StartLine == baseline.StartLine &&
		finding.EndLine == baseline.EndLine &&
		finding.StartColumn == baseline.StartColumn &&
		finding.EndColumn == baseline.EndColumn &&
		finding.File == baseline.File &&
		finding.Commit == baseline.Commit &&
		finding.Author == baseline.Author &&
		finding.Email == baseline.Email &&
		finding.Date == baseline.Date &&
		finding.Message == baseline.Message
}

func baselineSecretMatches(
	finding, baseline report.Finding,
	redact uint,
	findingHashes, baselineHashes map[string]struct{},
) bool {
	if (hasSecretHashIdentity(finding) || hasSecretHashIdentity(baseline)) &&
		len(findingHashes) > 0 && len(baselineHashes) > 0 {
		return secretHashesOverlap(findingHashes, baselineHashes)
	}

	if redact == 0 {
		return finding.Match == baseline.Match && finding.Secret == baseline.Secret
	}

	// A legacy redacted baseline has no digest. There is no value left to
	// compare, so retain the historical behavior for those entries. A finding
	// with an empty secret (for example a path-only rule) also has no secret
	// identity and is covered by the non-secret metadata checks.
	if report.IsRedactedValue(finding.Secret) || report.IsRedactedValue(baseline.Secret) {
		return true
	}
	if finding.Secret == "" && baseline.Secret == "" {
		return true
	}
	return finding.Match == baseline.Match && finding.Secret == baseline.Secret
}

func hasSecretHashIdentity(finding report.Finding) bool {
	return finding.SecretHash != ""
}

func secretHashesOverlap(findingHashes, baselineHashes map[string]struct{}) bool {
	for hash := range findingHashes {
		if _, ok := baselineHashes[hash]; ok {
			return true
		}
	}
	return false
}

func secretHashCandidates(finding report.Finding) map[string]struct{} {
	hashes := make(map[string]struct{})
	if finding.SecretHash != "" {
		hashes[strings.ToLower(finding.SecretHash)] = struct{}{}
	}
	if finding.Secret != "" && !report.IsRedactedValue(finding.Secret) {
		hashes[report.HashSecret(finding.Secret)] = struct{}{}
		// Support baselines produced by earlier redaction implementations
		// which bound the digest to both Secret and Match.
		hashes[report.HashSecret(finding.Secret, finding.Match)] = struct{}{}
	}
	return hashes
}

func LoadBaseline(baselinePath string) ([]report.Finding, error) {
	bytes, err := os.ReadFile(baselinePath)
	if err != nil {
		return nil, fmt.Errorf("could not open %s", baselinePath)
	}

	var previousFindings []report.Finding
	err = json.Unmarshal(bytes, &previousFindings)
	if err != nil {
		return nil, fmt.Errorf("the format of the file %s is not supported", baselinePath)
	}

	return previousFindings, nil
}

func (d *Detector) AddBaseline(baselinePath string, source string) error {
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
