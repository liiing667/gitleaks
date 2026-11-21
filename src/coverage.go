package src

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"github.com/zricethezav/gitleaks/v8/detect"
	"github.com/zricethezav/gitleaks/v8/report"
)

// Coverage is the set of findings evidenced by a fixed report. It is the
// only record a later run consults to learn what a previous scan covered:
// no marker files, extraction directories or other leftover state are ever
// taken into account.
type Coverage struct {
	findings []report.Finding
}

// LoadCoverage reads coverage evidence from a fixed gitleaks JSON report,
// for example one produced by Result.WriteReport. Because reports are
// written atomically and only for completed scans, a readable report always
// represents complete coverage of the members it names.
func LoadCoverage(reportPath string) (Coverage, error) {
	data, err := os.ReadFile(reportPath)
	if err != nil {
		return Coverage{}, fmt.Errorf("could not read coverage report %s: %w", reportPath, err)
	}

	var findings []report.Finding
	if err := json.Unmarshal(data, &findings); err != nil {
		return Coverage{}, fmt.Errorf("could not parse coverage report %s: %w", reportPath, err)
	}

	return Coverage{findings: findings}, nil
}

// Covers reports whether the coverage evidence already contains the
// finding, using the same comparison as a gitleaks baseline.
func (c Coverage) Covers(finding report.Finding) bool {
	return !detect.IsNew(finding, 0, c.findings)
}

// Members returns the sorted, de-duplicated member paths named by the
// coverage evidence, exactly as they appear to users in the report (for
// example "archive.zip!inner.txt").
func (c Coverage) Members() []string {
	seen := make(map[string]struct{}, len(c.findings))
	for _, f := range c.findings {
		seen[f.File] = struct{}{}
	}

	members := make([]string, 0, len(seen))
	for member := range seen {
		members = append(members, member)
	}
	sort.Strings(members)
	return members
}
