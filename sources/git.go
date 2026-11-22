package sources

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/fatih/semgroup"
	"github.com/gitleaks/go-gitdiff/gitdiff"

	"github.com/zricethezav/gitleaks/v8/cmd/scm"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/logging"
)

var quotedOptPattern = regexp.MustCompile(`^(?:"[^"]+"|'[^']+')$`)

// GitCmd helps to work with Git's output.
type GitCmd struct {
	cmd         *exec.Cmd
	diffFilesCh <-chan *gitdiff.File
	errCh       <-chan error
	repoPath    string
	scanInfo    GitScanInfo
}

// GitScanInfo describes the repository state fixed when a Git command was
// created. Keeping this separate from the live repository prevents a HEAD
// move (or a concurrent fetch) from being attributed to an older scan.
type GitScanInfo struct {
	Repository  string
	Head        string
	CommitRange string
	Shallow     bool
}

// ScanInfo returns the repository identity captured when the command was
// created.
func (c *GitCmd) ScanInfo() GitScanInfo {
	if c == nil {
		return GitScanInfo{}
	}
	return c.scanInfo
}

// Head returns the HEAD SHA captured for this command.
func (c *GitCmd) Head() string {
	return c.ScanInfo().Head
}

// CommitRange returns the effective revision range captured for this command.
func (c *GitCmd) CommitRange() string {
	return c.ScanInfo().CommitRange
}

// RepositoryPath returns the repository path used by this command.
func (c *GitCmd) RepositoryPath() string {
	return c.ScanInfo().Repository
}

// IsShallow reports whether the repository was shallow when the command was
// created.
func (c *GitCmd) IsShallow() bool {
	return c.ScanInfo().Shallow
}

// blobReader provides a ReadCloser interface git cat-file blob to fetch
// a blob from a repo
type blobReader struct {
	io.ReadCloser
	cmd *exec.Cmd
}

// Close closes the underlying reader and then waits for the command to complete,
// releasing its resources.
func (br *blobReader) Close() error {
	// Discard the remaining data from the pipe to avoid blocking
	_, drainErr := io.Copy(io.Discard, br)
	// Close the pipe (should signal the command to stop if it hasn't already)
	closeErr := br.ReadCloser.Close()
	// Wait to prevent zombie processes.
	waitErr := br.cmd.Wait()
	// Return the first error encountered
	if drainErr != nil {
		return drainErr
	}
	if closeErr != nil {
		return closeErr
	}
	return waitErr
}

// NewGitLogCmd returns `*DiffFilesCmd` with two channels: `<-chan *gitdiff.File` and `<-chan error`.
// Caller should read everything from channels until receiving a signal about their closure and call
// the `func (*DiffFilesCmd) Wait()` error in order to release resources.
func NewGitLogCmd(source string, logOpts string) (*GitCmd, error) {
	return NewGitLogCmdContext(context.Background(), source, logOpts)
}

// NewGitLogCmdContext is the same as NewGitLogCmd but supports passing in a
// context to use for timeouts
func NewGitLogCmdContext(ctx context.Context, source string, logOpts string) (*GitCmd, error) {
	sourceClean := filepath.Clean(source)
	var cmd *exec.Cmd
	scanInfo := captureGitScanInfo(ctx, sourceClean, gitRevisionRange(logOpts), true)
	if logOpts != "" {
		args := []string{"-C", sourceClean, "log", "-p", "-U0"}

		// Ensure that the user-provided |logOpts| aren't wrapped in quotes.
		// https://github.com/gitleaks/gitleaks/issues/1153
		userArgs := strings.Split(logOpts, " ")
		var quotedOpts []string
		for _, element := range userArgs {
			if quotedOptPattern.MatchString(element) {
				quotedOpts = append(quotedOpts, element)
			}
		}
		if len(quotedOpts) > 0 {
			logging.Warn().Msgf("the following `--log-opts` values may not work as expected: %v\n\tsee https://github.com/gitleaks/gitleaks/issues/1153 for more information", quotedOpts)
		}

		userArgs, effectiveRange := freezeGitLogArgs(ctx, sourceClean, userArgs, scanInfo)
		scanInfo.CommitRange = effectiveRange
		args = append(args, userArgs...)
		cmd = exec.CommandContext(ctx, "git", args...)
	} else {
		cmd = exec.CommandContext(ctx, "git", "-C", sourceClean, "log", "-p", "-U0",
			"--full-history", "--all", "--diff-filter=tuxdb")
	}

	logging.Debug().Msgf("executing: %s", cmd.String())

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	errCh := make(chan error)
	go listenForStdErr(stderr, errCh)

	gitdiffFiles, err := gitdiff.Parse(stdout)
	if err != nil {
		return nil, err
	}

	return &GitCmd{
		cmd:         cmd,
		diffFilesCh: gitdiffFiles,
		errCh:       errCh,
		repoPath:    sourceClean,
		scanInfo:    scanInfo,
	}, nil
}

// NewGitDiffCmd returns `*DiffFilesCmd` with two channels: `<-chan *gitdiff.File` and `<-chan error`.
// Caller should read everything from channels until receiving a signal about their closure and call
// the `func (*DiffFilesCmd) Wait()` error in order to release resources.
func NewGitDiffCmd(source string, staged bool) (*GitCmd, error) {
	return NewGitDiffCmdContext(context.Background(), source, staged)
}

// NewGitDiffCmdContext is the same as NewGitDiffCmd but supports passing in a
// context to use for timeouts
func NewGitDiffCmdContext(ctx context.Context, source string, staged bool) (*GitCmd, error) {
	sourceClean := filepath.Clean(source)
	var cmd *exec.Cmd
	rangeName := "worktree"
	if staged {
		rangeName = "staged"
	}
	scanInfo := captureGitScanInfo(ctx, sourceClean, rangeName, true)
	cmd = exec.CommandContext(ctx, "git", "-C", sourceClean, "diff", "-U0", "--no-ext-diff", ".")
	if staged {
		cmd = exec.CommandContext(ctx, "git", "-C", sourceClean, "diff", "-U0", "--no-ext-diff",
			"--staged", ".")
	}
	logging.Debug().Msgf("executing: %s", cmd.String())

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	errCh := make(chan error)
	go listenForStdErr(stderr, errCh)

	gitdiffFiles, err := gitdiff.Parse(stdout)
	if err != nil {
		return nil, err
	}

	return &GitCmd{
		cmd:         cmd,
		diffFilesCh: gitdiffFiles,
		errCh:       errCh,
		repoPath:    sourceClean,
		scanInfo:    scanInfo,
	}, nil
}

func captureGitScanInfo(ctx context.Context, source, commitRange string, includeHead bool) GitScanInfo {
	info := GitScanInfo{
		Repository:  source,
		CommitRange: commitRange,
		Shallow:     isShallowRepository(ctx, source),
	}
	if includeHead {
		if head, ok := resolveGitRevision(ctx, source, "HEAD"); ok {
			info.Head = head
		}
	}
	return info
}

// gitRevisionRange extracts a human-readable revision description from the
// user's log options. The command still receives the original options via
// freezeGitLogArgs; this value is the fallback when no revision-like token is
// present.
func gitRevisionRange(logOpts string) string {
	logOpts = strings.TrimSpace(logOpts)
	if logOpts == "" {
		return "--all"
	}
	for _, arg := range strings.Fields(logOpts) {
		if strings.HasPrefix(arg, "-") {
			continue
		}
		if strings.Contains(arg, "..") {
			return arg
		}
	}
	return logOpts
}

// freezeGitLogArgs resolves revision arguments before starting `git log`.
// This is what makes a scan use one HEAD/range snapshot even if the repository
// moves while the scan is running. In a shallow clone, a range whose lower
// boundary is unavailable is widened to the available endpoint instead of
// silently scanning only a suffix or failing the whole scan.
func freezeGitLogArgs(ctx context.Context, repo string, args []string, info GitScanInfo) ([]string, string) {
	effective := info.CommitRange
	out := append([]string(nil), args...)
	skipNextValue := false
	pathMode := false

	for i, arg := range out {
		if pathMode {
			continue
		}
		if arg == "--" {
			pathMode = true
			continue
		}
		if strings.HasPrefix(arg, "-") {
			if gitLogOptionTakesValue(arg) {
				skipNextValue = true
			}
			continue
		}
		if skipNextValue {
			skipNextValue = false
			continue
		}

		if strings.Contains(arg, "..") {
			resolved, ok := freezeGitRange(ctx, repo, arg, info)
			if ok {
				out[i] = resolved
				effective = resolved
			}
			continue
		}

		if resolved, ok := resolveGitRevision(ctx, repo, arg); ok {
			out[i] = resolved
			effective = resolved
			continue
		}

		if info.Shallow && info.Head != "" {
			// A legitimate shallow clone may not contain the requested old
			// revision. Scan everything reachable from the frozen HEAD rather
			// than leaving a hole in the history coverage.
			logging.Warn().
				Str("revision", arg).
				Str("head", info.Head).
				Msg("revision is unavailable in shallow clone; scanning available history")
			out[i] = info.Head
			effective = info.Head
		}
	}

	if effective == "" {
		effective = info.CommitRange
	}
	return out, effective
}

func freezeGitRange(ctx context.Context, repo, arg string, info GitScanInfo) (string, bool) {
	left, right, sep, ok := splitGitRange(arg)
	if !ok {
		return "", false
	}

	leftResolved, leftOK := resolveGitRangeEndpoint(ctx, repo, left, info.Head)
	rightResolved, rightOK := resolveGitRangeEndpoint(ctx, repo, right, info.Head)
	if leftOK && rightOK {
		return leftResolved + sep + rightResolved, true
	}

	if !info.Shallow {
		return "", false
	}

	switch {
	case rightOK:
		logging.Warn().
			Str("range", arg).
			Str("revision", rightResolved).
			Msg("lower revision boundary is unavailable in shallow clone; scanning available history")
		return rightResolved, true
	case leftOK:
		logging.Warn().
			Str("range", arg).
			Str("revision", leftResolved).
			Msg("upper revision boundary is unavailable in shallow clone; scanning available history")
		return leftResolved, true
	case info.Head != "":
		logging.Warn().
			Str("range", arg).
			Str("revision", info.Head).
			Msg("revision range is unavailable in shallow clone; scanning available history")
		return info.Head, true
	default:
		return "", false
	}
}

func splitGitRange(arg string) (left, right, sep string, ok bool) {
	if idx := strings.Index(arg, "..."); idx >= 0 {
		return arg[:idx], arg[idx+3:], "...", true
	}
	if idx := strings.Index(arg, ".."); idx >= 0 {
		return arg[:idx], arg[idx+2:], "..", true
	}
	return "", "", "", false
}

func resolveGitRangeEndpoint(ctx context.Context, repo, endpoint, head string) (string, bool) {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		endpoint = head
	}
	if endpoint == "" {
		return "", false
	}
	return resolveGitRevision(ctx, repo, endpoint)
}

func resolveGitRevision(ctx context.Context, repo, revision string) (string, bool) {
	revision = strings.TrimSpace(revision)
	if revision == "" {
		return "", false
	}
	out, err := gitCommandOutput(ctx, repo, "rev-parse", "--verify", revision+"^{commit}")
	if err != nil {
		out, err = gitCommandOutput(ctx, repo, "rev-parse", "--verify", revision)
	}
	if err != nil {
		return "", false
	}
	resolved := strings.TrimSpace(string(out))
	return resolved, resolved != ""
}

func isShallowRepository(ctx context.Context, repo string) bool {
	out, err := gitCommandOutput(ctx, repo, "rev-parse", "--is-shallow-repository")
	if err == nil {
		return strings.EqualFold(strings.TrimSpace(string(out)), "true")
	}

	// Older Git versions do not understand --is-shallow-repository. Fall back
	// to the shallow file in the git directory.
	out, err = gitCommandOutput(ctx, repo, "rev-parse", "--git-dir")
	if err != nil {
		return false
	}
	gitDir := strings.TrimSpace(string(out))
	if !filepath.IsAbs(gitDir) {
		gitDir = filepath.Join(repo, gitDir)
	}
	_, err = os.Stat(filepath.Join(gitDir, "shallow"))
	return err == nil
}

func gitCommandOutput(ctx context.Context, repo string, args ...string) ([]byte, error) {
	gitArgs := append([]string{"-C", repo}, args...)
	cmd := exec.CommandContext(ctx, "git", gitArgs...)
	cmd.Env = append(os.Environ(),
		"GIT_TERMINAL_PROMPT=0",
		"LC_ALL=C",
	)
	return cmd.Output()
}

func gitLogOptionTakesValue(arg string) bool {
	if strings.Contains(arg, "=") {
		return false
	}
	switch arg {
	case "-n", "--max-count", "--skip", "--since", "--after", "--until",
		"--before", "--author", "--committer", "--grep", "--format",
		"--date", "--diff-filter", "--max-parents", "--min-parents",
		"--ancestry-path", "--glob", "--exclude":
		return true
	default:
		return false
	}
}

// DiffFilesCh returns a channel with *gitdiff.File.
func (c *GitCmd) DiffFilesCh() <-chan *gitdiff.File {
	return c.diffFilesCh
}

// ErrCh returns a channel that could produce an error if there is something in stderr.
func (c *GitCmd) ErrCh() <-chan error {
	return c.errCh
}

// Wait waits for the command to exit and waits for any copying to
// stdin or copying from stdout or stderr to complete.
//
// Wait also closes underlying stdout and stderr.
func (c *GitCmd) Wait() error {
	return c.cmd.Wait()
}

// String displays the command used for GitCmd
func (c *GitCmd) String() string {
	return c.cmd.String()
}

// NewBlobReader returns an io.ReadCloser that can be used to read a blob
// within the git repo used to create the GitCmd.
//
// The caller is responsible for closing the reader.
func (c *GitCmd) NewBlobReader(commit, path string) (io.ReadCloser, error) {
	return c.NewBlobReaderContext(context.Background(), commit, path)
}

// NewBlobReaderContext is the same as NewBlobReader but supports passing in a
// context to use for timeouts
func (c *GitCmd) NewBlobReaderContext(ctx context.Context, commit, path string) (io.ReadCloser, error) {
	gitArgs := []string{"-C", c.repoPath, "cat-file", "blob", commit + ":" + path}
	cmd := exec.CommandContext(ctx, "git", gitArgs...)
	cmd.Stderr = io.Discard
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to get stdout pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start git command: %w", err)
	}
	return &blobReader{
		ReadCloser: stdout,
		cmd:        cmd,
	}, nil
}

// listenForStdErr listens for stderr output from git, prints it to stdout,
// sends to errCh and closes it.
func listenForStdErr(stderr io.ReadCloser, errCh chan<- error) {
	defer close(errCh)

	var errEncountered bool

	scanner := bufio.NewScanner(stderr)
	for scanner.Scan() {
		// if git throws one of the following errors:
		//
		//  exhaustive rename detection was skipped due to too many files.
		//  you may want to set your diff.renameLimit variable to at least
		//  (some large number) and retry the command.
		//
		//	inexact rename detection was skipped due to too many files.
		//  you may want to set your diff.renameLimit variable to at least
		//  (some large number) and retry the command.
		//
		//  Auto packing the repository in background for optimum performance.
		//  See "git help gc" for manual housekeeping.
		//
		// we skip exiting the program as git log -p/git diff will continue
		// to send data to stdout and finish executing. This next bit of
		// code prevents gitleaks from stopping mid scan if this error is
		// encountered
		if strings.Contains(scanner.Text(),
			"exhaustive rename detection was skipped") ||
			strings.Contains(scanner.Text(),
				"inexact rename detection was skipped") ||
			strings.Contains(scanner.Text(),
				"you may want to set your diff.renameLimit") ||
			strings.Contains(scanner.Text(),
				"See \"git help gc\" for manual housekeeping") ||
			strings.Contains(scanner.Text(),
				"Auto packing the repository in background for optimum performance") {
			logging.Warn().Msg(scanner.Text())
		} else {
			logging.Error().Msgf("[git] %s", scanner.Text())
			errEncountered = true
		}
	}

	if errEncountered {
		errCh <- errors.New("stderr is not empty")
		return
	}
}

// RemoteInfo provides the info needed for reconstructing links from findings
type RemoteInfo struct {
	Platform scm.Platform
	Url      string
}

// Git is a source for yielding fragments from a git repo
type Git struct {
	Cmd             *GitCmd
	Config          *config.Config
	Remote          *RemoteInfo
	Sema            *semgroup.Group
	MaxArchiveDepth int
}

// ScanInfo returns the repository identity frozen by the command that backs
// this Git source.
func (s *Git) ScanInfo() GitScanInfo {
	if s == nil || s.Cmd == nil {
		return GitScanInfo{}
	}
	return s.Cmd.ScanInfo()
}

// CommitInfo captures metadata about the commit
type CommitInfo struct {
	AuthorEmail string
	AuthorName  string
	Date        string
	Message     string
	Remote      *RemoteInfo
	SHA         string
}

// Fragments yields fragments from a git repo
func (s *Git) Fragments(ctx context.Context, yield FragmentsFunc) error {
	defer func() {
		if err := s.Cmd.Wait(); err != nil {
			logging.Debug().Err(err).Str("cmd", s.Cmd.String()).Msg("command aborted")
		}
	}()

	var (
		diffFilesCh = s.Cmd.DiffFilesCh()
		errCh       = s.Cmd.ErrCh()
		wg          sync.WaitGroup
	)

	// loop to range over both DiffFiles (stdout) and ErrCh (stderr)
	for diffFilesCh != nil || errCh != nil {
		select {
		case <-ctx.Done():
			// Let every producer that already passed the cancellation check
			// finish. DetectSource must not return while a worker can still
			// append a finding to the previous scan.
			wg.Wait()
			return ctx.Err()
		case gitdiffFile, open := <-diffFilesCh:
			if !open {
				diffFilesCh = nil
				break
			}

			if gitdiffFile.IsDelete {
				continue
			}

			// skip non-archive binary files
			yieldAsArchive := false
			if gitdiffFile.IsBinary {
				if !isArchive(ctx, gitdiffFile.NewName) {
					continue
				}
				yieldAsArchive = true
			}

			// Check if commit is allowed
			commitSHA := ""
			var commitInfo *CommitInfo
			if gitdiffFile.PatchHeader != nil {
				commitSHA = gitdiffFile.PatchHeader.SHA
				for _, a := range s.Config.Allowlists {
					if ok, c := a.CommitAllowed(gitdiffFile.PatchHeader.SHA); ok {
						logging.Trace().Str("allowed-commit", c).Msg("skipping commit: global allowlist")
						continue
					}
				}

				commitInfo = &CommitInfo{
					Date:    gitdiffFile.PatchHeader.AuthorDate.UTC().Format(time.RFC3339),
					Message: gitdiffFile.PatchHeader.Message(),
					Remote:  s.Remote,
					SHA:     commitSHA,
				}

				if gitdiffFile.PatchHeader.Author != nil {
					commitInfo.AuthorName = gitdiffFile.PatchHeader.Author.Name
					commitInfo.AuthorEmail = gitdiffFile.PatchHeader.Author.Email
				}
			}

			wg.Add(1)
			s.Sema.Go(func() error {
				defer wg.Done()

				if yieldAsArchive {
					blob, err := s.Cmd.NewBlobReaderContext(ctx, commitSHA, gitdiffFile.NewName)
					if err != nil {
						logging.Error().Err(err).Msg("could not read archive blob")
						return nil
					}

					file := File{
						Content:         blob,
						Path:            gitdiffFile.NewName,
						MaxArchiveDepth: s.MaxArchiveDepth,
						Config:          s.Config,
					}

					// enrich and yield fragments
					err = file.Fragments(ctx, func(fragment Fragment, err error) error {
						fragment.CommitSHA = commitSHA
						fragment.CommitInfo = commitInfo
						return yield(fragment, err)
					})

					// Close the blob reader and log any issues
					if err := blob.Close(); err != nil {
						logging.Debug().Err(err).Msg("blobReader.Close() returned an error")
					}

					return err
				}

				for _, textFragment := range gitdiffFile.TextFragments {
					if textFragment == nil {
						return nil
					}

					fragment := Fragment{
						CommitSHA:  commitSHA,
						FilePath:   gitdiffFile.NewName,
						Raw:        textFragment.Raw(gitdiff.OpAdd),
						StartLine:  int(textFragment.NewPosition),
						CommitInfo: commitInfo,
					}

					if err := yield(fragment, nil); err != nil {
						return err
					}
				}

				return nil
			})
		case err, open := <-errCh:
			if !open {
				errCh = nil
				break
			}

			return yield(Fragment{}, err)
		}
	}

	select {
	case <-ctx.Done():
		wg.Wait()
		return ctx.Err()
	default:
		wg.Wait()
		if err := ctx.Err(); err != nil {
			return err
		}
		return nil
	}
}

// NewRemoteInfo builds a new RemoteInfo for generating finding links
func NewRemoteInfo(platform scm.Platform, source string) *RemoteInfo {
	return NewRemoteInfoContext(context.Background(), platform, source)
}

// NewRemoteInfoContext is the same as NewRemoteInfo but supports passing in a
// context to use for timeouts
func NewRemoteInfoContext(ctx context.Context, platform scm.Platform, source string) *RemoteInfo {
	if platform == scm.NoPlatform {
		return &RemoteInfo{Platform: platform}
	}

	remoteUrl, err := getRemoteUrl(ctx, source)
	if err != nil {
		if strings.Contains(err.Error(), "No remote configured") {
			logging.Debug().Msg("skipping finding links: repository has no configured remote.")
			platform = scm.NoPlatform
		} else {
			logging.Error().Err(err).Msg("skipping finding links: unable to parse remote URL")
		}
		goto End
	}

	if platform == scm.UnknownPlatform {
		platform = platformFromHost(remoteUrl)
		if platform == scm.UnknownPlatform {
			logging.Info().
				Str("host", remoteUrl.Hostname()).
				Msg("Unknown SCM platform. Use --platform to include links in findings.")
		} else {
			logging.Debug().
				Str("host", remoteUrl.Hostname()).
				Str("platform", platform.String()).
				Msg("SCM platform parsed from host")
		}
	}

End:
	var rUrl string
	if remoteUrl != nil {
		rUrl = remoteUrl.String()
	}
	return &RemoteInfo{
		Platform: platform,
		Url:      rUrl,
	}
}

var sshUrlpat = regexp.MustCompile(`^git@([a-zA-Z0-9.-]+):(?:\d{1,5}/)?([\w/.-]+?)(?:\.git)?$`)

func getRemoteUrl(ctx context.Context, source string) (*url.URL, error) {
	// This will return the first remote — typically, "origin".
	cmd := exec.CommandContext(ctx, "git", "ls-remote", "--quiet", "--get-url")
	if source != "." {
		cmd.Dir = source
	}

	stdout, err := cmd.Output()
	if err != nil {
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			return nil, fmt.Errorf("command failed (%d): %w, stderr: %s", exitError.ExitCode(), err, string(bytes.TrimSpace(exitError.Stderr)))
		}
		return nil, err
	}

	remoteUrl := string(bytes.TrimSpace(stdout))
	if matches := sshUrlpat.FindStringSubmatch(remoteUrl); matches != nil {
		remoteUrl = fmt.Sprintf("https://%s/%s", matches[1], matches[2])
	}
	remoteUrl = strings.TrimSuffix(remoteUrl, ".git")

	parsedUrl, err := url.Parse(remoteUrl)
	if err != nil {
		return nil, fmt.Errorf("unable to parse remote URL: %w", err)
	}

	// Remove any user info.
	parsedUrl.User = nil
	return parsedUrl, nil
}

func platformFromHost(u *url.URL) scm.Platform {
	switch strings.ToLower(u.Hostname()) {
	case "github.com":
		return scm.GitHubPlatform
	case "gitlab.com":
		return scm.GitLabPlatform
	case "dev.azure.com", "visualstudio.com":
		return scm.AzureDevOpsPlatform
	case "gitea.com", "code.forgejo.org", "codeberg.org":
		return scm.GiteaPlatform
	case "bitbucket.org":
		return scm.BitbucketPlatform
	default:
		return scm.UnknownPlatform
	}
}
