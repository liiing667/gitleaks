package report

import (
	"encoding/json"
	"fmt"
	"io"
)

type JsonReporter struct {
	Metadata ScanMetadata
}

var _ Reporter = (*JsonReporter)(nil)
var _ MetadataReporter = (*JsonReporter)(nil)

func (t *JsonReporter) SetMetadata(metadata ScanMetadata) {
	t.Metadata = metadata
}

func (t *JsonReporter) Write(w io.WriteCloser, findings []Finding) error {
	if err := validateScanMetadata(findings, t.Metadata); err != nil {
		return err
	}
	findings = applyScanMetadata(findings, t.Metadata)
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", " ")
	return encoder.Encode(findings)
}

// DecodeFindings reads findings from both the legacy top-level JSON array
// format and report envelopes that carry scan metadata alongside a findings
// list. Baselines produced by older gitleaks versions therefore remain
// readable without weakening the new completion checks.
func DecodeFindings(data []byte) ([]Finding, error) {
	var findings []Finding
	if err := json.Unmarshal(data, &findings); err == nil {
		return findings, nil
	}

	var envelope struct {
		Findings []Finding `json:"findings"`
		Results  []Finding `json:"results"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return nil, err
	}
	if envelope.Findings == nil && envelope.Results == nil {
		return nil, fmt.Errorf("report does not contain findings")
	}
	if envelope.Findings != nil {
		return envelope.Findings, nil
	}
	return envelope.Results, nil
}
