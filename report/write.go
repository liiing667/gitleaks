package report

import (
	"fmt"
	"os"
	"path/filepath"
)

// WriteFile writes findings to the report path using the given reporter.
//
// The report is first written to a temporary file in the same directory and
// then atomically renamed into place. The fixed report path therefore only
// ever observes a complete report: a scan that is cancelled or fails halfway
// through writing never leaves a half-written report behind, and no
// temporary or marker files remain that a later run could mistake for
// evidence of completed coverage.
func WriteFile(reportPath string, reporter Reporter, findings []Finding) (err error) {
	// stdout reports are streamed directly; they leave no on-disk state
	// behind that could be misread as a completion marker.
	if reportPath == StdoutReportPath {
		return reporter.Write(os.Stdout, findings)
	}

	dir := filepath.Dir(reportPath)
	tmp, err := os.CreateTemp(dir, ".gitleaks-report-*")
	if err != nil {
		return fmt.Errorf("could not create temporary report file: %w", err)
	}
	tmpPath := tmp.Name()

	// Whatever happens below, the temporary file must not linger: on
	// success it is renamed away, on failure it is removed.
	defer func() {
		_ = tmp.Close()
		if err != nil {
			_ = os.Remove(tmpPath)
		}
	}()

	if err = reporter.Write(tmp, findings); err != nil {
		return fmt.Errorf("could not write report: %w", err)
	}
	if err = tmp.Sync(); err != nil {
		return fmt.Errorf("could not flush report: %w", err)
	}
	if err = tmp.Close(); err != nil {
		return fmt.Errorf("could not close report: %w", err)
	}
	if err = os.Rename(tmpPath, reportPath); err != nil {
		return fmt.Errorf("could not move report into place: %w", err)
	}
	return nil
}
