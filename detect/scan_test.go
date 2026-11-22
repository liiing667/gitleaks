package detect

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/regexp"
	"github.com/zricethezav/gitleaks/v8/report"
	"github.com/zricethezav/gitleaks/v8/sources"
)

type scanTestSource struct {
	info      sources.GitScanInfo
	fragments []sources.Fragment
	err       error
}

func (s *scanTestSource) ScanInfo() sources.GitScanInfo {
	return s.info
}

func (s *scanTestSource) Fragments(_ context.Context, yield sources.FragmentsFunc) error {
	for _, fragment := range s.fragments {
		if err := yield(fragment, nil); err != nil {
			return err
		}
	}
	return s.err
}

func TestScanGenerationIsPerAttempt(t *testing.T) {
	cfg := config.Config{
		Rules: map[string]config.Rule{
			"scan-test": {
				RuleID:   "scan-test",
				Regex:    regexp.MustCompile(`SCAN_SECRET_[A-Z]+`),
				Keywords: []string{"scan_secret_"},
			},
		},
		Keywords: map[string]struct{}{"scan_secret_": {}},
	}
	detector := NewDetector(cfg)

	partialSource := &scanTestSource{
		info: sources.GitScanInfo{
			Repository:  "/repo",
			Head:        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			CommitRange: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
		fragments: []sources.Fragment{{
			CommitSHA: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			FilePath:  "first.txt",
			Raw:       "SCAN_SECRET_ONE",
		}},
		err: context.Canceled,
	}
	first, err := detector.DetectSource(context.Background(), partialSource)
	require.ErrorIs(t, err, context.Canceled)
	require.Len(t, first, 1)
	require.Equal(t, report.ScanStagePartial, first[0].ScanStage)
	require.False(t, detector.ScanComplete())
	firstGeneration := detector.ScanGeneration()
	require.NotEmpty(t, firstGeneration)

	retrySource := &scanTestSource{
		info: sources.GitScanInfo{
			Repository:  "/repo",
			Head:        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			CommitRange: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		},
		fragments: []sources.Fragment{{
			CommitSHA: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			FilePath:  "second.txt",
			Raw:       "SCAN_SECRET_TWO",
		}},
	}
	retry, err := detector.DetectSource(context.Background(), retrySource)
	require.NoError(t, err)
	require.Len(t, retry, 1)
	require.Equal(t, "SCAN_SECRET_TWO", retry[0].Secret)
	require.Equal(t, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", retry[0].Head)
	require.Equal(t, report.ScanStageCompleted, retry[0].ScanStage)
	require.True(t, retry[0].ScanComplete)
	require.True(t, detector.ScanComplete())
	require.NotEqual(t, firstGeneration, detector.ScanGeneration())
}

func TestIncompleteBaselineIsRejected(t *testing.T) {
	detector := NewDetector(config.Config{})
	err := detector.SetBaseline([]report.Finding{{ScanStage: report.ScanStagePartial}})
	require.ErrorIs(t, err, ErrIncompleteBaseline)
	require.Nil(t, detector.baseline)

	require.NoError(t, detector.SetBaseline([]report.Finding{{RuleID: "legacy"}}))
}

func TestScanStageErrorClassification(t *testing.T) {
	detector := NewDetector(config.Config{})
	state := detector.beginScan(&scanTestSource{info: sources.GitScanInfo{CommitRange: "--all"}})
	detector.finishScan(state, errors.New("git failed"))

	got := detector.ScanState()
	require.False(t, got.Complete)
	require.Equal(t, report.ScanStagePartial, got.Stage)
	require.Equal(t, "failed", got.Status)
}
