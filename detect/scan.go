package detect

import (
	"context"
	"sync"
	"sync/atomic"

	"github.com/zricethezav/gitleaks/v8/report"
	"github.com/zricethezav/gitleaks/v8/sources"
)

// scanState represents the lifecycle phase of a scan transaction.
type scanState uint32

const (
	// scanReady means no scan has been accepted yet.
	scanReady scanState = iota
	// scanRunning means a scan has been accepted and is consuming fragments.
	scanRunning
	// scanCommitted means the scan finished successfully and its findings
	// were committed to the detector.
	scanCommitted
	// scanAborted means the scan was canceled or failed; its partial
	// findings were discarded and must never be committed.
	scanAborted
)

// scanTransaction is the single transaction shared between source
// admission, fragment consumption, cancellation/close and report
// termination for one DetectSource invocation.
//
// A transaction freezes the source, the run identity and the cancellation
// generation at admission time. Everything produced while the transaction
// is open is tagged with its identity, so findings left behind by a
// canceled (or otherwise aborted) scan can neither be committed to the
// detector nor observed by a subsequent scan.
type scanTransaction struct {
	// id uniquely identifies the scan run within the detector. Each accepted
	// scan gets a fresh, monotonically increasing id.
	id uint64

	// state tracks the transaction lifecycle atomically.
	state atomic.Uint32

	// mu guards findings and committed.
	mu sync.Mutex

	// findings holds only the findings produced by this transaction.
	findings []report.Finding

	// committed is true once the findings have been committed to the
	// detector. It can only happen on a successful transaction.
	committed bool
}

// beginScan accepts a new scan transaction for the detector.
//
// The source, run identity and cancellation generation are frozen here.
// Only one scan may run at a time on a detector: beginning a new scan
// blocks until any in-flight scan has fully terminated so that goroutines,
// temporary resources and findings can never leak across runs.
func (d *Detector) beginScan(ctx context.Context, source sources.Source) *scanTransaction {
	// Serialize scans on the detector. A previous scan must be completely
	// finished (all goroutines returned and resources released) before a
	// new run identity is handed out.
	d.scanMu.Lock()

	runID := d.nextScanID
	d.nextScanID++

	tx := &scanTransaction{
		id: runID,
	}
	tx.state.Store(uint32(scanRunning))

	return tx
}

// addFinding records a finding against the transaction. Findings are kept
// in the transaction's private buffer and only become visible through the
// detector once the transaction commits. Findings arriving after an abort
// (for example from a goroutine that was still draining a canceled source)
// are dropped so partial results are never committed.
func (tx *scanTransaction) addFinding(finding report.Finding) bool {
	if tx.state.Load() != uint32(scanRunning) {
		return false
	}

	tx.mu.Lock()
	defer tx.mu.Unlock()

	// Re-check under the lock to close the race with abort.
	if tx.state.Load() != uint32(scanRunning) {
		return false
	}
	tx.findings = append(tx.findings, finding)
	return true
}

// commit finalizes a successful transaction by publishing its findings to
// the detector. It returns the committed findings. A transaction that was
// aborted (canceled/failed) cannot commit and yields nil.
func (tx *scanTransaction) commit(d *Detector) []report.Finding {
	tx.mu.Lock()
	defer tx.mu.Unlock()

	if !tx.state.CompareAndSwap(uint32(scanRunning), uint32(scanCommitted)) {
		return nil
	}

	findings := make([]report.Finding, len(tx.findings))
	copy(findings, tx.findings)
	tx.findings = nil
	tx.committed = true

	// Publish the run's findings as the detector's result. Previous runs
	// are fully terminated by now, so replacing the slice cannot mix
	// findings across scans.
	d.findingMutex.Lock()
	d.findings = findings
	d.findingMutex.Unlock()

	return findings
}

// abort terminates the transaction without committing. Any findings the
// scan may have produced are discarded and late-arriving findings from
// still-draining goroutines are rejected by addFinding.
func (tx *scanTransaction) abort() {
	tx.mu.Lock()
	if tx.state.CompareAndSwap(uint32(scanRunning), uint32(scanAborted)) {
		tx.findings = nil
	}
	tx.mu.Unlock()
}

// finish releases the detector-level scan slot and signals that every
// goroutine and temporary resource owned by the transaction is done.
func (d *Detector) finishScan(tx *scanTransaction) {
	d.scanMu.Unlock()
}

// snapshotResult returns the findings of a finished scan. Committed scans
// return their findings; aborted (canceled/failed) scans never expose
// partial results.
func (tx *scanTransaction) snapshotResult(d *Detector) []report.Finding {
	tx.mu.Lock()
	committed := tx.committed
	tx.mu.Unlock()

	if committed {
		return d.Findings()
	}
	return []report.Finding{}
}
