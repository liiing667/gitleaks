// Package src ties a scan's source, detector and report together so that a
// single scan only exposes results it has completely covered, and so that an
// interrupted scan leaves nothing behind that a later run could mistake for
// completed coverage.
//
// The first rule is atomic exposure: archive members are only exposed once
// they have been read to completion. When a scan is cancelled halfway
// through a nested member, the partially read member contributes nothing to
// the findings. (This is enforced by the sources package; Scan surfaces the
// outcome.)
//
// The second rule is that there are no misusable completion markers. The
// only evidence of what a scan covered is the report at the fixed report
// path. It is written atomically, and only once the scan has completed;
// interrupted scans leave behind no report, no temporary files and no
// marker files. Recovery is simply running the scan again, and coverage
// evidence is always read back from the fixed report (see LoadCoverage).
package src

import (
	"context"
	"errors"

	"github.com/zricethezav/gitleaks/v8/detect"
	"github.com/zricethezav/gitleaks/v8/report"
	"github.com/zricethezav/gitleaks/v8/sources"
)

// ErrIncompleteScan is returned when a report is requested for a scan that
// did not run to completion. The report is withheld so the partial results
// cannot be mistaken for complete coverage evidence.
var ErrIncompleteScan = errors.New("scan did not complete: withholding report")

// Result is the outcome of a single scan.
type Result struct {
	// Findings exposed by the scan. Because members are only exposed once
	// they have been completely covered, an interrupted scan contains no
	// partially covered members.
	Findings []report.Finding

	// Complete reports whether the scan ran to completion. Only complete
	// results may be persisted as coverage evidence.
	Complete bool
}

// Scan runs the detector over the source until the source is exhausted or
// the scan is interrupted (for example by context cancellation). The
// returned error is the scan's error, if any; Result.Complete reports
// whether the scan ran to completion.
func Scan(ctx context.Context, detector *detect.Detector, source sources.Source) (Result, error) {
	findings, err := detector.DetectSource(ctx, source)
	return Result{Findings: findings, Complete: err == nil}, err
}

// WriteReport persists the findings of a completed scan to the fixed report
// path. The report is written atomically (see report.WriteFile), so the
// fixed path only ever contains a complete report. WriteReport returns
// ErrIncompleteScan for interrupted scans and leaves the fixed report path
// untouched: no partial report, temporary file or marker file is left
// behind that a later run could mistake for completed coverage.
func (r Result) WriteReport(reportPath string, reporter report.Reporter) error {
	if !r.Complete {
		return ErrIncompleteScan
	}
	return report.WriteFile(reportPath, reporter, r.Findings)
}
