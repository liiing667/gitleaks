package report

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zricethezav/gitleaks/v8/config"
)

// TestSarifRedactedLocation verifies SARIF region coordinates come straight
// from the finding and that a redacted finding never leaks plaintext into the
// snippet.
func TestSarifRedactedLocation(t *testing.T) {
	t.Parallel()

	findings := []Finding{
		{
			RuleID:      "aws-access-key",
			Description: "AWS Access Key",
			StartLine:   4,
			EndLine:     4,
			StartColumn: 16,
			EndColumn:   35,
			Match:       "REDACTED",
			Secret:      "REDACTED",
			SecretHash:  "d3f1fdd46da999d0cf69893e50e0b505c7f4db17b267f0767db992072e065470",
			File:        "secret.go",
			Tags:        []string{"key", "AWS"},
		},
	}

	reporter := SarifReporter{
		OrderedRules: []config.Rule{
			{RuleID: "aws-access-key", Description: "AWS Access Key"},
		},
	}

	buf := testWriter{bytes.NewBuffer(nil)}
	require.NoError(t, reporter.Write(buf, findings))

	var sarif struct {
		Runs []struct {
			Results []struct {
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
						Region struct {
							StartLine   int `json:"startLine"`
							StartColumn int `json:"startColumn"`
							EndLine     int `json:"endLine"`
							EndColumn   int `json:"endColumn"`
							Snippet     struct {
								Text string `json:"text"`
							} `json:"snippet"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	require.NoError(t, json.Unmarshal(buf.Bytes(), &sarif))

	require.Len(t, sarif.Runs, 1)
	require.Len(t, sarif.Runs[0].Results, 1)
	require.Len(t, sarif.Runs[0].Results[0].Locations, 1)

	region := sarif.Runs[0].Results[0].Locations[0].PhysicalLocation
	assert.Equal(t, "secret.go", region.ArtifactLocation.URI)
	assert.Equal(t, 4, region.Region.StartLine)
	assert.Equal(t, 4, region.Region.EndLine)
	assert.Equal(t, 16, region.Region.StartColumn)
	assert.Equal(t, 35, region.Region.EndColumn)
	assert.Equal(t, "REDACTED", region.Region.Snippet.Text)

	assert.NotContains(t, buf.String(), "AKIALALEMEL33243OLIA")
	assert.NotContains(t, buf.String(), "SecretHash")
}
