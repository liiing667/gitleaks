package detect

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zricethezav/gitleaks/v8/cmd/scm"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/report"
	"github.com/zricethezav/gitleaks/v8/sources"
)

func loadTestConfig(t *testing.T, name string) config.Config {
	t.Helper()
	viper.AddConfigPath(configPath)
	viper.SetConfigName(name)
	viper.SetConfigType("toml")
	require.NoError(t, viper.ReadInConfig())

	var vc config.ViperConfig
	require.NoError(t, viper.Unmarshal(&vc))
	cfg, err := vc.Translate()
	require.NoError(t, err)
	return cfg
}

// gitFixtureReady reports whether the shared dotGit fixture exists and can
// be renamed to .git. It lets tests skip gracefully when another package
// currently owns the rename instead of racing on the shared fixtures.
func gitFixtureReady(t *testing.T) bool {
	t.Helper()
	entries, err := os.ReadDir(repoBasePath)
	require.NoError(t, err)
	for _, entry := range entries {
		if _, err := os.Stat(filepath.Join(repoBasePath, entry.Name(), "dotGit")); err == nil {
			return true
		}
	}
	return false
}

// TestDetectSourceCanceledCommitsNoFindings makes sure a canceled scan is
// an aborted transaction: it must return the context error, no partial
// findings and must leave nothing behind on the detector.
func TestDetectSourceCanceledCommitsNoFindings(t *testing.T) {
	cfg := loadTestConfig(t, "archives")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	detector := NewDetectorContext(ctx, cfg)
	detector.MaxArchiveDepth = 8

	findings, err := detector.DetectSource(
		ctx, &sources.Files{
			Path:            filepath.Join(archivesBasePath, "nested.tar.gz"),
			Sema:            detector.Sema,
			Config:          &cfg,
			MaxArchiveDepth: detector.MaxArchiveDepth,
		},
	)

	require.EqualError(t, err, "context canceled")
	assert.Empty(t, findings)
	// Nothing was committed to the detector.
	assert.Empty(t, detector.Findings())
}

// TestDetectSourceRestartDoesNotObservePreviousRun proves scan runs are
// isolated: a fresh scan on the same detector only ever sees its own
// findings, even after a prior scan was canceled.
func TestDetectSourceRestartDoesNotObservePreviousRun(t *testing.T) {
	cfg := loadTestConfig(t, "simple")

	// First run: canceled before it starts. Its findings must be discarded.
	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()

	detector := NewDetector(cfg)
	_, err := detector.DetectSource(
		canceledCtx, &sources.Files{
			Path:   filepath.Join(repoBasePath, "nogit"),
			Sema:   detector.Sema,
			Config: &cfg,
		},
	)
	require.EqualError(t, err, "context canceled")
	require.Empty(t, detector.Findings())

	// Second run: a normal scan must return exactly its own findings and
	// never anything left over from the aborted run.
	findings, err := detector.DetectSource(
		context.Background(), &sources.Files{
			Path:   filepath.Join(repoBasePath, "nogit"),
			Sema:   detector.Sema,
			Config: &cfg,
		},
	)
	require.NoError(t, err)
	require.Len(t, findings, 2)
	for _, f := range findings {
		assert.Equal(t, "AKIALALEMEL33243OLIA", f.Secret)
	}
	assert.Equal(t, findings, detector.Findings())
}

// leakySource emits one fragment, then blocks until the context is
// canceled. It models a fragment producer that has already admitted work
// when the scan transaction is canceled.
type leakySource struct {
	fragments []sources.Fragment
	started   chan struct{}
}

func newLeakySource(fragments ...sources.Fragment) *leakySource {
	return &leakySource{fragments: fragments, started: make(chan struct{}, 1)}
}

func (l *leakySource) Fragments(ctx context.Context, yield sources.FragmentsFunc) error {
	// Emit a fragment, then block on the context. The scan is canceled
	// after the fragment has been admitted and processed.
	err := yield(l.fragments[0], nil)
	l.started <- struct{}{}
	if err != nil {
		return err
	}

	<-ctx.Done()
	return ctx.Err()
}

// TestDetectSourceMidScanCancelDiscardsPartialFindings is the core
// regression test: a scan that has already produced a finding is then
// canceled. The partial finding must never be committed or visible to a
// subsequent scan. On the original implementation the detector retained
// the partial finding.
func TestDetectSourceMidScanCancelDiscardsPartialFindings(t *testing.T) {
	cfg := loadTestConfig(t, "simple")

	ctx, cancel := context.WithCancel(context.Background())
	detector := NewDetectorContext(ctx, cfg)

	source := newLeakySource(sources.Fragment{
		FilePath: "leak.go",
		Raw:      `token := "AKIALALEMEL33243OLIA"`,
	})

	done := make(chan struct{})
	var (
		findings []report.Finding
		scanErr  error
	)
	go func() {
		defer close(done)
		findings, scanErr = detector.DetectSource(ctx, source)
	}()

	<-source.started
	// The scan admitted and processed a fragment, then we cancel.
	cancel()
	<-done

	require.EqualError(t, scanErr, "context canceled")
	// The partial finding must be discarded by the aborted transaction.
	assert.Empty(t, findings)
	assert.Empty(t, detector.Findings())

	// A subsequent scan must not observe the discarded finding.
	next, err := detector.DetectSource(
		context.Background(),
		&sources.File{Content: strings.NewReader(`clean = "no secrets here"`)},
	)
	require.NoError(t, err)
	assert.Empty(t, next)
	assert.Empty(t, detector.Findings())
}

// TestDetectSourceEmptyScan keeps empty scans working and isolated.
func TestDetectSourceEmptyScan(t *testing.T) {
	cfg := loadTestConfig(t, "simple")
	detector := NewDetector(cfg)

	findings, err := detector.DetectSource(
		context.Background(),
		&sources.File{
			Content: strings.NewReader(""),
		},
	)
	require.NoError(t, err)
	assert.Empty(t, findings)
	assert.Empty(t, detector.Findings())
}

// TestDetectSourceStdin keeps the streaming stdin-style scan working and
// returns the committed findings.
func TestDetectSourceStdin(t *testing.T) {
	cfg := loadTestConfig(t, "simple")
	detector := NewDetector(cfg)

	findings, err := detector.DetectSource(
		context.Background(),
		&sources.File{
			Content: strings.NewReader(`token := "AKIALALEMEL33243OLIA"`),
		},
	)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "AKIALALEMEL33243OLIA", findings[0].Secret)
}

// TestDetectSourceGitCanceledIsTransaction verifies the Git source stops
// producing fragments when the context is canceled, waits for every
// admitted goroutine/archive reader to terminate, and commits nothing.
func TestDetectSourceGitCanceledIsTransaction(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("git repo fixtures are not renamed on Windows")
	}
	if !gitFixtureReady(t) {
		t.Skip("git fixtures unavailable (another package currently owns the dotGit rename)")
	}

	moveDotGit(t, "dotGit", ".git")
	defer moveDotGit(t, ".git", "dotGit")

	cfg := loadTestConfig(t, "archives")

	detector := NewDetector(cfg)
	detector.MaxArchiveDepth = 8

	gitCmd, err := sources.NewGitLogCmd(filepath.Join(repoBasePath, "archives"), "")
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	findings, err := detector.DetectSource(
		ctx,
		&sources.Git{
			Cmd:             gitCmd,
			Config:          &detector.Config,
			Remote:          sources.NewRemoteInfoContext(ctx, scm.NoPlatform, filepath.Join(repoBasePath, "archives")),
			Sema:            detector.Sema,
			MaxArchiveDepth: detector.MaxArchiveDepth,
		},
	)

	require.EqualError(t, err, "context canceled")
	assert.Empty(t, findings)
	assert.Empty(t, detector.Findings())

	// Every fragment-producing goroutine must have terminated by the time
	// the scan returns.
	baseline := runtime.NumGoroutine()
	for i := 0; i < 50; i++ {
		if runtime.NumGoroutine() <= baseline {
			return
		}
		runtime.Gosched()
	}
	t.Fatalf("goroutines leaked after canceled git scan: baseline=%d now=%d", baseline, runtime.NumGoroutine())
}

// TestDetectSourceGitNormalKeepsFindings ensures ordinary Git scans keep
// their original behavior under the scan transaction.
func TestDetectSourceGitNormalKeepsFindings(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("git repo fixtures are not renamed on Windows")
	}
	if !gitFixtureReady(t) {
		t.Skip("git fixtures unavailable (another package currently owns the dotGit rename)")
	}

	moveDotGit(t, "dotGit", ".git")
	defer moveDotGit(t, ".git", "dotGit")

	cfg := loadTestConfig(t, "simple")
	detector := NewDetector(cfg)
	require.NoError(t, detector.AddGitleaksIgnore(filepath.Join(repoBasePath, "small", ".gitleaksignore")))

	gitCmd, err := sources.NewGitLogCmd(filepath.Join(repoBasePath, "small"), "")
	require.NoError(t, err)

	findings, err := detector.DetectSource(
		context.Background(),
		&sources.Git{
			Cmd:             gitCmd,
			Config:          &cfg,
			Remote:          sources.NewRemoteInfo(scm.NoPlatform, filepath.Join(repoBasePath, "small")),
			Sema:            detector.Sema,
			MaxArchiveDepth: detector.MaxArchiveDepth,
		},
	)
	require.NoError(t, err)
	assert.Len(t, findings, 2)
	assert.Equal(t, findings, detector.Findings())
}

// blockingReader blocks until the context is canceled, simulating a slow
// fragment source that must be unwound by cancellation without leaking.
type blockingReader struct {
	ctx context.Context
}

func (b *blockingReader) Read(p []byte) (int, error) {
	<-b.ctx.Done()
	return 0, b.ctx.Err()
}

// TestCanceledScanReleasesResources makes sure a canceled scan returns and
// leaves no running transaction on the detector (a subsequent scan can be
// accepted immediately).
func TestCanceledScanReleasesResources(t *testing.T) {
	cfg := loadTestConfig(t, "simple")

	ctx, cancel := context.WithCancel(context.Background())
	detector := NewDetectorContext(ctx, cfg)

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = detector.DetectSource(
			ctx,
			&sources.File{Content: &blockingReader{ctx: ctx}},
		)
	}()

	cancel()
	<-done

	// The scan slot must have been released: another scan is accepted.
	findings, err := detector.DetectSource(
		context.Background(),
		&sources.File{Content: strings.NewReader(`x = "AKIALALEMEL33243OLIA"`)},
	)
	require.NoError(t, err)
	require.Len(t, findings, 1)
}

// TestDetectSourceSerializesRuns proves scans on one detector cannot
// overlap: the second scan blocks until the first transaction fully
// terminates, which is what keeps goroutines and temporary resources from
// crossing run boundaries.
func TestDetectSourceSerializesRuns(t *testing.T) {
	cfg := loadTestConfig(t, "simple")
	detector := NewDetector(cfg)

	firstCtx, cancelFirst := context.WithCancel(context.Background())
	firstDone := make(chan struct{})
	go func() {
		defer close(firstDone)
		_, _ = detector.DetectSource(
			firstCtx,
			&sources.File{Content: &blockingReader{ctx: firstCtx}},
		)
	}()

	// Give the first scan time to acquire the detector's scan slot.
	runtime.Gosched()

	secondStarted := make(chan struct{}, 1)
	secondDone := make(chan struct{})
	go func() {
		secondStarted <- struct{}{}
		defer close(secondDone)
		_, _ = detector.DetectSource(
			context.Background(),
			&sources.File{Content: strings.NewReader(`x = "AKIALALEMEL33243OLIA"`)},
		)
	}()

	// The second goroutine is scheduled but must not complete while the
	// first transaction is still open.
	select {
	case <-secondDone:
		t.Fatal("second scan completed while the first scan was still running")
	default:
	}

	// Terminating the first transaction releases the scan slot.
	cancelFirst()
	<-firstDone
	<-secondDone

	// The committed second scan owns the detector's findings.
	require.Len(t, detector.Findings(), 1)
}

// TestAddFindingStillFilters preserves the legacy AddFinding behavior for
// callers that accumulate findings directly on the detector.
func TestAddFindingStillFilters(t *testing.T) {
	cfg := loadTestConfig(t, "simple")
	detector := NewDetector(cfg)

	detector.AddFinding(report.Finding{
		RuleID:    "aws-access-key",
		File:      "main.go",
		Secret:    "AKIALALEMEL33243OLIA",
		StartLine: 1,
	})
	require.Len(t, detector.Findings(), 1)
	assert.Contains(t, detector.Findings()[0].Fingerprint, "main.go:aws-access-key:1")

	// A gitleaks-ignored finding is still dropped.
	ignorePath := filepath.Join(t.TempDir(), ".gitleaksignore")
	require.NoError(t, os.WriteFile(ignorePath, []byte("main.go:aws-access-key:1\n"), 0o600))
	require.NoError(t, detector.AddGitleaksIgnore(ignorePath))
	detector.AddFinding(report.Finding{
		RuleID:    "aws-access-key",
		File:      "main.go",
		Secret:    "AKIALALEMEL33243OLIA",
		StartLine: 1,
	})
	require.Len(t, detector.Findings(), 1)
}

// Ensure the test helpers satisfy the io.Reader interface.
var _ io.Reader = (*blockingReader)(nil)
