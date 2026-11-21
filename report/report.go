package report

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const (
	// https://cwe.mitre.org/data/definitions/798.html
	CWE              = "CWE-798"
	CWE_DESCRIPTION  = "Use of Hard-coded Credentials"
	StdoutReportPath = "-"
)

type Reporter interface {
	Write(w io.WriteCloser, findings []Finding) error
}

// WriteFile writes the findings report to the file at path using reporter.
//
// The report is first written to a temporary file in the same directory and
// then atomically renamed into place. This keeps the report consistent with
// the scan that produced it: if anything goes wrong, an error is returned and
// any previous report is left untouched, instead of leaving a partial or
// corrupted report behind for a later run to pick up.
func WriteFile(path string, reporter Reporter, findings []Finding) error {
	// Write to a temporary file in the same directory so that the final
	// rename is atomic.
	tmp, err := os.CreateTemp(filepath.Dir(path), ".gitleaks-report-*.tmp")
	if err != nil {
		return fmt.Errorf("could not create temporary report file: %w", err)
	}
	tmpName := tmp.Name()
	// If anything below fails, make sure the temporary file does not stick
	// around. Once the rename succeeds this is a no-op.
	defer func() {
		_ = os.Remove(tmpName)
	}()

	if err = reporter.Write(tmp, findings); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("could not write report: %w", err)
	}

	// A successful Write does not guarantee the report reached the disk:
	// buffered data (e.g. the single document produced by the JSON and SARIF
	// reporters) can still be lost to a flush error, which only surfaces when
	// the file is closed. This error must not be silently dropped.
	if err = tmp.Close(); err != nil {
		return fmt.Errorf("could not flush report: %w", err)
	}

	// Match the permissions of a file created with os.Create.
	_ = tmp.Chmod(0o644)

	if err = os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("could not move report into place: %w", err)
	}
	return nil
}
