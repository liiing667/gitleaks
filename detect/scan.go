package detect

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/zricethezav/gitleaks/v8/report"
	"github.com/zricethezav/gitleaks/v8/sources"
)

// Scan stage aliases for callers that use the detector API directly.
const (
	ScanStageCompleted = report.ScanStageCompleted
	ScanStagePartial   = report.ScanStagePartial
)

// ScanState describes one admitted scan. The generation, HEAD, revision range
// and completion stage are captured once at admission and are attached to
// every finding produced by that attempt.
type ScanState struct {
	Generation  string
	Head        string
	CommitRange string
	Source      string
	Shallow     bool
	Git         bool
	Stage       string
	Complete    bool
	Status      string
	StartedAt   time.Time
	CompletedAt time.Time
	Err         error `json:"-"`
}

// Metadata returns the report-facing identity for the scan.
func (s ScanState) Metadata() report.ScanMetadata {
	if !s.Git && s.Complete {
		return report.ScanMetadata{}
	}
	return s.scanMetadata()
}

func (s ScanState) scanMetadata() report.ScanMetadata {
	return report.ScanMetadata{
		Head:           s.Head,
		CommitRange:    s.CommitRange,
		ScanGeneration: s.Generation,
		ScanStage:      s.Stage,
		ScanComplete:   s.Complete,
		ScanSource:     s.Source,
	}
}

func (s ScanState) isGit() bool {
	return s.Git
}

var scanGenerationCounter atomic.Uint64

func nextScanGeneration(info sources.GitScanInfo) string {
	sequence := scanGenerationCounter.Add(1)
	identity := fmt.Sprintf("%s\x00%s\x00%s\x00%d\x00%d",
		info.Repository, info.Head, info.CommitRange, time.Now().UTC().UnixNano(), sequence)
	sum := sha256.Sum256([]byte(identity))
	return hex.EncodeToString(sum[:16])
}

func scanInfoFor(source sources.Source) (sources.GitScanInfo, bool) {
	type scanInfoProvider interface {
		ScanInfo() sources.GitScanInfo
	}
	if provider, ok := source.(scanInfoProvider); ok {
		return provider.ScanInfo(), true
	}
	return sources.GitScanInfo{}, false
}

func (d *Detector) beginScan(source sources.Source) *ScanState {
	info, isGit := scanInfoFor(source)
	state := &ScanState{
		Generation:  nextScanGeneration(info),
		Head:        info.Head,
		CommitRange: info.CommitRange,
		Source:      info.Repository,
		Shallow:     info.Shallow,
		Git:         isGit,
		Stage:       report.ScanStagePartial,
		Status:      "started",
		StartedAt:   time.Now().UTC(),
	}
	if state.Source == "" {
		state.Source = fmt.Sprintf("%T", source)
	}

	// A Detector instance can be reused after a failed or cancelled scan. The
	// previous attempt must never leak findings, commit bookkeeping or
	// metadata into the retry.
	d.findingMutex.Lock()
	d.findings = make([]report.Finding, 0)
	d.findingMutex.Unlock()

	d.commitMutex.Lock()
	d.commitMap = make(map[string]bool)
	d.commitMutex.Unlock()
	d.TotalBytes.Store(0)

	d.scanMutex.Lock()
	d.scan = state
	d.scanMutex.Unlock()
	return state
}

func (d *Detector) finishScan(state *ScanState, err error) {
	completedAt := time.Now().UTC()
	stage := report.ScanStageCompleted
	status := "completed"

	switch {
	case err == nil:
	case errors.Is(err, context.Canceled):
		stage = report.ScanStagePartial
		status = "cancelled"
	case errors.Is(err, context.DeadlineExceeded):
		stage = report.ScanStagePartial
		status = "timed_out"
	default:
		stage = report.ScanStagePartial
		status = "failed"
	}

	d.scanMutex.Lock()
	state.Stage = stage
	state.Complete = err == nil
	state.Status = status
	state.CompletedAt = completedAt
	state.Err = err
	d.scanMutex.Unlock()

	// Findings are added while the source is producing fragments, so their
	// final stage is stamped only after all producers have stopped. This also
	// makes a partial result impossible to mistake for completed coverage.
	// Completed file/stdin scans keep their legacy report shape; only failed
	// non-Git scans need the partial marker.
	if state.Git || !state.Complete {
		metadata := state.scanMetadata()
		d.findingMutex.Lock()
		for i := range d.findings {
			metadata.Apply(&d.findings[i])
		}
		d.findingMutex.Unlock()
	}
}

func (d *Detector) applyScanMetadata(finding *report.Finding) {
	d.scanMutex.RLock()
	defer d.scanMutex.RUnlock()
	d.applyScanMetadataLocked(finding, d.scan)
}

func (d *Detector) applyScanMetadataLocked(finding *report.Finding, state *ScanState) {
	if finding == nil || state == nil || !state.isGit() {
		return
	}
	state.Metadata().Apply(finding)
}

func (d *Detector) currentScanMetadata() report.ScanMetadata {
	d.scanMutex.RLock()
	defer d.scanMutex.RUnlock()
	if d.scan == nil {
		return report.ScanMetadata{}
	}
	return d.scan.Metadata()
}

// ScanState returns a copy of the most recent scan's admission and completion
// state. The zero value means no scan has run on this detector yet.
func (d *Detector) ScanState() ScanState {
	d.scanMutex.RLock()
	defer d.scanMutex.RUnlock()
	if d.scan == nil {
		return ScanState{}
	}
	return *d.scan
}

// ScanGeneration returns the generation of the most recent scan.
func (d *Detector) ScanGeneration() string {
	return d.ScanState().Generation
}

// ScanHead returns the HEAD frozen for the most recent scan.
func (d *Detector) ScanHead() string {
	return d.ScanState().Head
}

// Head is an alias for ScanHead.
func (d *Detector) Head() string {
	return d.ScanHead()
}

// CommitRange returns the effective range frozen for the most recent scan.
func (d *Detector) CommitRange() string {
	return d.ScanState().CommitRange
}

// ScanMetadata returns the report-facing metadata for the most recent scan.
func (d *Detector) ScanMetadata() report.ScanMetadata {
	return d.currentScanMetadata()
}

// ScanComplete reports whether the most recent scan ran to completion.
func (d *Detector) ScanComplete() bool {
	return d.ScanState().Complete
}

// Complete is an alias for ScanComplete.
func (d *Detector) Complete() bool {
	return d.ScanComplete()
}
