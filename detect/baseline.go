package detect

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/zricethezav/gitleaks/v8/report"
)

// ErrIncompleteBaseline is returned when a baseline contains findings from a
// scan that did not complete. Such a baseline is not coverage evidence: using
// it would let findings from the unscanned part of the history be mistaken
// for findings that were already accepted.
var ErrIncompleteBaseline = errors.New("baseline was produced by an incomplete scan")

func IsNew(finding report.Finding, redact uint, baseline []report.Finding) bool {
	// Explicitly testing each property as it gives significantly better performance in comparison to cmp.Equal(). Drawback is that
	// the code requires maintenance if/when the Finding struct changes
	for _, b := range baseline {
		if finding.RuleID == b.RuleID &&
			finding.Description == b.Description &&
			finding.StartLine == b.StartLine &&
			finding.EndLine == b.EndLine &&
			finding.StartColumn == b.StartColumn &&
			finding.EndColumn == b.EndColumn &&
			(redact > 0 || (finding.Match == b.Match && finding.Secret == b.Secret)) &&
			finding.File == b.File &&
			finding.Commit == b.Commit &&
			finding.Author == b.Author &&
			finding.Email == b.Email &&
			finding.Date == b.Date &&
			finding.Message == b.Message &&
			// Omit checking finding.Fingerprint - if the format of the fingerprint changes, the users will see unexpected behaviour
			finding.Entropy == b.Entropy {
			return false
		}
	}
	return true
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
	if stage, ok := incompleteBaselineStage(previousFindings); !ok {
		return nil, fmt.Errorf("%w (stage %q)", ErrIncompleteBaseline, stage)
	}

	return previousFindings, nil
}

func (d *Detector) AddBaseline(baselinePath string, source string) error {
	// A failed or rejected baseline must not leave an older baseline active.
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
		if stage, ok := incompleteBaselineStage(baseline); !ok {
			return fmt.Errorf("%w (stage %q)", ErrIncompleteBaseline, stage)
		}

		d.baseline = baseline
		baselinePath = relativeBaseline

	}

	d.baselinePath = baselinePath
	return nil
}

// SetBaseline applies findings as a baseline without reading a file. It uses
// the same completion validation as AddBaseline.
func (d *Detector) SetBaseline(baseline []report.Finding) error {
	d.baseline = nil
	d.baselinePath = ""
	if stage, ok := incompleteBaselineStage(baseline); !ok {
		return fmt.Errorf("%w (stage %q)", ErrIncompleteBaseline, stage)
	}
	d.baseline = baseline
	return nil
}

func incompleteBaselineStage(baseline []report.Finding) (string, bool) {
	for _, finding := range baseline {
		stage := strings.ToLower(strings.TrimSpace(finding.ScanStage))
		switch stage {
		case "", report.ScanStageCompleted, "complete":
			// Empty is the legacy JSON shape. Treating it as complete keeps
			// baselines produced by older gitleaks versions readable.
			continue
		default:
			if finding.ScanComplete && stage != report.ScanStagePartial {
				continue
			}
			return stage, false
		}
	}
	return "", true
}
