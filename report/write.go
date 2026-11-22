package report

import (
	"fmt"
	"os"
	"path/filepath"
)

// WriteFile writes findings to path using reporter.
//
// The report is built in a temporary file in the destination directory and
// renamed into place only after the reporter has flushed it. A failed or
// interrupted write therefore cannot leave a partial report that a later scan
// could consume as a completed baseline.
func WriteFile(path string, reporter Reporter, findings []Finding) (err error) {
	if path == StdoutReportPath {
		return reporter.Write(os.Stdout, findings)
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), ".gitleaks-report-*")
	if err != nil {
		return fmt.Errorf("could not create temporary report file: %w", err)
	}
	tmpPath := tmp.Name()
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
	// Preserve the permissions users get from os.Create for reports.
	_ = tmp.Chmod(0o644)
	if err = os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("could not move report into place: %w", err)
	}
	return nil
}
