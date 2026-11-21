package report

import (
	"encoding/json"
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
	findings = applyMetadata(findings, t.Metadata)
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", " ")
	return encoder.Encode(findings)
}

func applyMetadata(findings []Finding, metadata ScanMetadata) []Finding {
	if metadata.ConfigVersion == "" &&
		metadata.ConfigPath == "" &&
		metadata.ScanSource == "" &&
		metadata.ConfigGeneration == 0 {
		return findings
	}

	out := make([]Finding, len(findings))
	for i, finding := range findings {
		metadata.Apply(&finding)
		out[i] = finding
	}
	return out
}
