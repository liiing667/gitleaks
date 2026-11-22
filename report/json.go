package report

import (
	"encoding/json"
	"fmt"
	"io"
)

type JsonReporter struct {
}

var _ Reporter = (*JsonReporter)(nil)

func (t *JsonReporter) Write(w io.WriteCloser, findings []Finding) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", " ")
	return encoder.Encode(findings)
}

// DecodeFindings reads the legacy top-level findings array as well as report
// envelopes that keep findings and their source generation together. Baseline
// files produced by older gitleaks versions therefore remain readable.
func DecodeFindings(data []byte) ([]Finding, error) {
	var findings []Finding
	if err := json.Unmarshal(data, &findings); err == nil {
		return findings, nil
	}

	var envelope struct {
		Findings         []Finding `json:"findings"`
		Results          []Finding `json:"results"`
		Baseline         []Finding `json:"baseline"`
		SourceGeneration string    `json:"sourceGeneration"`
		ScanGeneration   string    `json:"scanGeneration"`
		Generation       string    `json:"generation"`
		Scan             struct {
			Generation       string `json:"generation"`
			SourceGeneration string `json:"sourceGeneration"`
			ScanGeneration   string `json:"scanGeneration"`
		} `json:"scan"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return nil, err
	}

	switch {
	case envelope.Findings != nil:
		findings = envelope.Findings
	case envelope.Results != nil:
		findings = envelope.Results
	case envelope.Baseline != nil:
		findings = envelope.Baseline
	default:
		return nil, fmt.Errorf("report does not contain findings")
	}

	generation := envelope.SourceGeneration
	if generation == "" {
		generation = envelope.ScanGeneration
	}
	if generation == "" {
		generation = envelope.Generation
	}
	if generation == "" {
		generation = envelope.Scan.Generation
	}
	if generation == "" {
		generation = envelope.Scan.SourceGeneration
	}
	if generation == "" {
		generation = envelope.Scan.ScanGeneration
	}
	if generation != "" {
		for i := range findings {
			if findings[i].SourceGeneration == "" &&
				findings[i].ScanGeneration == "" &&
				findings[i].SourceCommit == "" {
				findings[i].SourceGeneration = generation
			}
		}
	}
	return findings, nil
}
