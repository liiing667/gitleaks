package sources

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"

	"github.com/fatih/semgroup"
	"github.com/stretchr/testify/require"

	"github.com/zricethezav/gitleaks/v8/cmd/scm"
	"github.com/zricethezav/gitleaks/v8/config"
)

const gitRepoBasePath = "../testdata/repos/"

// TestGitFragmentsCancelStopsAndWaits verifies that canceling the context
// stops fragment admission and that Fragments only returns after every
// admitted worker goroutine has terminated. No fragment may outlive the
// canceled scan.
func TestGitFragmentsCancelStopsAndWaits(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("git repo fixtures are not renamed on Windows")
	}
	if !gitFixtureAvailable(t) {
		t.Skip("git fixtures unavailable (another package currently owns the dotGit rename)")
	}

	moveDotGitSources(t, "dotGit", ".git")
	defer moveDotGitSources(t, ".git", "dotGit")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	gitCmd, err := NewGitLogCmd(filepath.Join(gitRepoBasePath, "archives"), "")
	require.NoError(t, err)

	var yielded atomic.Int32
	source := &Git{
		Cmd:             gitCmd,
		Config:          &config.Config{},
		Remote:          NewRemoteInfo(scm.NoPlatform, filepath.Join(gitRepoBasePath, "archives")),
		Sema:            semgroup.NewGroup(context.Background(), 40),
		MaxArchiveDepth: 8,
	}

	err = source.Fragments(ctx, func(fragment Fragment, err error) error {
		if err != nil {
			return err
		}
		yielded.Add(1)
		return ctx.Err()
	})

	require.EqualError(t, err, "context canceled")
	require.Zero(t, yielded.Load(), "no fragments may be yielded by a canceled scan")

	// After Fragments returns there must be no lingering worker goroutines.
	baseline := runtime.NumGoroutine()
	for i := 0; i < 100; i++ {
		if runtime.NumGoroutine() <= baseline {
			return
		}
		runtime.Gosched()
	}
	t.Fatalf("goroutines leaked after canceled git Fragments: baseline=%d now=%d", baseline, runtime.NumGoroutine())
}

// TestGitFragmentsNormalStillYields keeps the ordinary Git fragment flow
// working under the cancellation-aware implementation.
func TestGitFragmentsNormalStillYields(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("git repo fixtures are not renamed on Windows")
	}
	if !gitFixtureAvailable(t) {
		t.Skip("git fixtures unavailable (another package currently owns the dotGit rename)")
	}

	moveDotGitSources(t, "dotGit", ".git")
	defer moveDotGitSources(t, ".git", "dotGit")

	gitCmd, err := NewGitLogCmd(filepath.Join(gitRepoBasePath, "small"), "")
	require.NoError(t, err)

	var yielded atomic.Int32
	source := &Git{
		Cmd:             gitCmd,
		Config:          &config.Config{},
		Remote:          NewRemoteInfo(scm.NoPlatform, filepath.Join(gitRepoBasePath, "small")),
		Sema:            semgroup.NewGroup(context.Background(), 40),
		MaxArchiveDepth: 8,
	}

	err = source.Fragments(context.Background(), func(fragment Fragment, err error) error {
		if err != nil {
			return err
		}
		yielded.Add(1)
		return nil
	})
	require.NoError(t, err)
	require.Greater(t, yielded.Load(), int32(0))
}

// TestGitFragmentsCancelMidScan drives the Git source against the real
// archives repository and cancels after the first fragment is admitted. It
// proves in-flight workers are awaited and the scan ends in the canceled
// error rather than leaking goroutines or partial fragments.
func TestGitFragmentsCancelMidScan(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("git repo fixtures are not renamed on Windows")
	}
	if !gitFixtureAvailable(t) {
		t.Skip("git fixtures unavailable (another package currently owns the dotGit rename)")
	}

	moveDotGitSources(t, "dotGit", ".git")
	defer moveDotGitSources(t, ".git", "dotGit")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	gitCmd, err := NewGitLogCmd(filepath.Join(gitRepoBasePath, "archives"), "")
	require.NoError(t, err)

	var yielded atomic.Int32
	source := &Git{
		Cmd:             gitCmd,
		Config:          &config.Config{},
		Remote:          NewRemoteInfo(scm.NoPlatform, filepath.Join(gitRepoBasePath, "archives")),
		Sema:            semgroup.NewGroup(context.Background(), 40),
		MaxArchiveDepth: 8,
	}

	err = source.Fragments(ctx, func(fragment Fragment, err error) error {
		if err != nil {
			return err
		}
		yielded.Add(1)
		// Cancel on the first fragment so the rest of the scan has to
		// unwind through the cancellation-aware workers.
		cancel()
		return nil
	})

	require.EqualError(t, err, "context canceled")

	// All admitted workers must have returned before Fragments unwinds.
	baseline := runtime.NumGoroutine()
	for i := 0; i < 100; i++ {
		if runtime.NumGoroutine() <= baseline {
			return
		}
		runtime.Gosched()
	}
	t.Fatalf("goroutines leaked after mid-scan cancel: baseline=%d now=%d", baseline, runtime.NumGoroutine())
}

// moveDotGitSources mirrors the detect package helper for source tests.
func moveDotGitSources(t *testing.T, from, to string) {
	t.Helper()

	repoDirs, err := os.ReadDir(gitRepoBasePath)
	require.NoError(t, err)
	for _, dir := range repoDirs {
		if to == ".git" {
			if _, err := os.Stat(filepath.Join(gitRepoBasePath, dir.Name(), "dotGit")); os.IsNotExist(err) {
				continue
			}
			_ = os.RemoveAll(filepath.Join(gitRepoBasePath, dir.Name(), ".git"))
		}
		if !dir.IsDir() {
			continue
		}
		if _, err := os.Stat(filepath.Join(gitRepoBasePath, dir.Name(), from)); os.IsNotExist(err) {
			continue
		}
		require.NoError(t, os.Rename(
			filepath.Join(gitRepoBasePath, dir.Name(), from),
			filepath.Join(gitRepoBasePath, dir.Name(), to),
		))
	}
}

// gitFixtureAvailable reports whether the shared dotGit fixture can be
// renamed. The fixtures are shared across packages and only stored under
// one of ".git"/"dotGit" at a time, so tests must skip when another
// package currently owns the rename.
func gitFixtureAvailable(t *testing.T) bool {
	t.Helper()
	entries, err := os.ReadDir(gitRepoBasePath)
	require.NoError(t, err)
	for _, entry := range entries {
		if _, err := os.Stat(filepath.Join(gitRepoBasePath, entry.Name(), "dotGit")); err == nil {
			return true
		}
	}
	return false
}
