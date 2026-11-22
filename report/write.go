package report

import (
	"fmt"
	"os"
	"path/filepath"
)

// WriteFile writes findings to path using reporter.
//
// The report is first built in a temporary file in the destination directory
// and renamed into place only after the reporter has flushed it. A failed or
// interrupted write therefore leaves any previous complete report untouched
// and never exposes a partial report as a usable baseline.
func WriteFile(path string, reporter Reporter, findings []Finding) (err error) {
	if path == StdoutReportPath {
		return reporter.Write(os.Stdout, findings)
	}
	if path == "" {
		return fmt.Errorf("report path is empty")
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("could not create temporary report file: %w", err)
	}
	tmpPath := tmp.Name()
	removeTemp := true
	defer func() {
		_ = tmp.Close()
		if removeTemp {
			_ = os.Remove(tmpPath)
		}
	}()

	if err = reporter.Write(tmp, findings); err != nil {
		return fmt.Errorf("could not write report: %w", err)
	}
	if err = tmp.Sync(); err != nil {
		return fmt.Errorf("could not flush report: %w", err)
	}
	if err = tmp.Chmod(0o644); err != nil {
		return fmt.Errorf("could not set report permissions: %w", err)
	}
	if err = tmp.Close(); err != nil {
		return fmt.Errorf("could not close report: %w", err)
	}
	if err = os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("could not move report into place: %w", err)
	}
	removeTemp = false
	return nil
}
