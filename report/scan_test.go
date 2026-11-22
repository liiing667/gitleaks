package report

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestJsonReporterAppliesOneScanIdentity(t *testing.T) {
	buf := testWriter{bytes.NewBuffer(nil)}
	reporter := JsonReporter{
		Metadata: ScanMetadata{
			Head:           "head",
			CommitRange:    "head~1..head",
			ScanGeneration: "generation",
			ScanStage:      ScanStageCompleted,
			ScanComplete:   true,
			ScanSource:     "/repo",
		},
	}

	require.NoError(t, reporter.Write(buf, []Finding{{RuleID: "rule", Head: "stale"}}))

	var got []Finding
	require.NoError(t, json.Unmarshal(buf.Bytes(), &got))
	require.Len(t, got, 1)
	require.Equal(t, "head", got[0].Head)
	require.Equal(t, "head~1..head", got[0].CommitRange)
	require.Equal(t, "generation", got[0].ScanGeneration)
	require.Equal(t, ScanStageCompleted, got[0].ScanStage)
	require.True(t, got[0].ScanComplete)
}

func TestDecodeFindingsSupportsLegacyAndEnvelope(t *testing.T) {
	legacy, err := DecodeFindings([]byte(`[{"RuleID":"legacy"}]`))
	require.NoError(t, err)
	require.Len(t, legacy, 1)
	require.Equal(t, "legacy", legacy[0].RuleID)

	envelope, err := DecodeFindings([]byte(`{"scan":{"stage":"completed"},"findings":[{"RuleID":"new"}]}`))
	require.NoError(t, err)
	require.Len(t, envelope, 1)
	require.Equal(t, "new", envelope[0].RuleID)
}
