package sources

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sync"

	"github.com/fatih/semgroup"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/logging"
)

// TODO: remove this in v9 and have scanTargets yield file sources
type ScanTarget struct {
	Path    string
	Symlink string
	// Root is the controlled scan root frozen during source discovery. The
	// resolved Path must stay inside it.
	Root string
}

// Deprecated: Use Files and detector.DetectSource instead
func DirectoryTargets(sourcePath string, s *semgroup.Group, followSymlinks bool, allowlists []*config.Allowlist) (<-chan ScanTarget, error) {
	paths := make(chan ScanTarget)

	// create a Files source
	files := Files{
		FollowSymlinks: followSymlinks,
		Path:           sourcePath,
		Sema:           s,
		Config: &config.Config{
			Allowlists: allowlists,
		},
	}

	s.Go(func() error {
		ctx := context.Background()
		err := files.scanTargets(ctx, func(scanTarget ScanTarget, err error) error {
			paths <- scanTarget
			return nil
		})
		close(paths)
		return err
	})

	return paths, nil
}

// Files is a source for yielding fragments from a collection of files
type Files struct {
	Config          *config.Config
	FollowSymlinks  bool
	MaxFileSize     int
	Path            string
	Sema            *semgroup.Group
	MaxArchiveDepth int
	// Root optionally fixes the controlled scan root. If empty, a root is
	// derived from Path once when scanning starts.
	Root string
}

// scanTargets yields scan targets to a callback func
func (s *Files) scanTargets(ctx context.Context, yield func(ScanTarget, error) error) error {
	root := s.Root
	if root == "" {
		root = controlledRootFor(s.Path)
	}
	return s.scanTargetsWithRoot(ctx, root, yield)
}

func (s *Files) scanTargetsWithRoot(ctx context.Context, root string, yield func(ScanTarget, error) error) error {
	return filepath.WalkDir(s.Path, func(path string, d fs.DirEntry, err error) error {
		scanTarget := ScanTarget{Path: path, Root: root}
		logger := logging.With().Str("path", path).Logger()

		if err != nil {
			if os.IsPermission(err) {
				// This seems to only fail on directories at this stage.
				logger.Warn().Err(errors.New("permission denied")).Msg("skipping directory")
				return filepath.SkipDir
			}
			logger.Warn().Err(err).Msg("skipping")
			return nil
		}

		info, err := d.Info()
		if err != nil {
			if d.IsDir() {
				logger.Error().Err(err).Msg("skipping directory: could not get info")
				return filepath.SkipDir
			}
			logger.Error().Err(err).Msg("skipping file: could not get info")
			return nil
		}

		// set the initial scan target values
		if d.Type() == fs.ModeSymlink {
			if !s.FollowSymlinks {
				logger.Debug().Msg("skipping symlink: follow symlinks disabled")
				return nil
			}
			realPath, err := filepath.EvalSymlinks(path)
			if err != nil {
				logger.Error().Err(err).Msg("skipping symlink: could not evaluate")
				return nil
			}
			realPathFileInfo, err := os.Stat(realPath)
			if err != nil {
				logger.Error().Err(err).Msg("skipping symlink: could not stat target")
				return nil
			}
			if realPathFileInfo.IsDir() {
				logger.Debug().Str("target", realPath).Msgf("skipping symlink: target is directory")
				return nil
			}
			// A discovered link is only admitted when its resolved target is
			// under the root frozen at the start of the walk. The same check
			// is repeated immediately before the file is opened. An explicit
			// source that is itself a link is admitted relative to its target,
			// preserving the old single-file call behavior.
			targetRoot := root
			if path == s.Path && s.Root == "" {
				targetRoot = filepath.Dir(realPath)
				if gitRoot := findGitRoot(realPath); gitRoot != "" {
					targetRoot = gitRoot
				}
			} else if !WithinRoot(root, realPath) {
				logger.Warn().
					Str("target", realPath).
					Str("root", root).
					Str("stage", "source_discovery").
					Msg("skipping symlink: target is outside controlled root")
				return nil
			}
			scanTarget = ScanTarget{
				Path:    realPath,
				Symlink: path,
				Root:    targetRoot,
			}
		}

		if !info.IsDir() {
			// Empty; nothing to do here.
			if info.Size() == 0 {
				logger.Debug().Msg("skipping empty file")
				return nil
			}

			// Too large; nothing to do here.
			if s.MaxFileSize > 0 && info.Size() > int64(s.MaxFileSize) {
				logger.Warn().Msgf(
					"skipping file: too large max_size=%dMB, size=%dMB",
					s.MaxFileSize/1_000_000, info.Size()/1_000_000,
				)
				return nil
			}
		}

		// handle dir cases (mainly just see if it should be skipped
		if info.IsDir() {
			if shouldSkipPath(s.Config, path) {
				logger.Debug().Msg("skipping directory: global allowlist")
				return filepath.SkipDir
			}
			return nil
		}

		if shouldSkipPath(s.Config, path) {
			logger.Debug().Msg("skipping file: global allowlist")
			return nil
		}
		if scanTarget.Symlink != "" && scanTarget.Path != path && shouldSkipPath(s.Config, scanTarget.Path) {
			logger.Debug().Msg("skipping symlink: target allowlisted")
			return nil
		}

		return yield(scanTarget, nil)
	})
}

// Fragments yields fragments from files discovered under the path
func (s *Files) Fragments(ctx context.Context, yield FragmentsFunc) error {
	var wg sync.WaitGroup

	root := s.Root
	if root == "" {
		root = controlledRootFor(s.Path)
	}

	err := s.scanTargetsWithRoot(ctx, root, func(scanTarget ScanTarget, err error) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			if scanTarget.Root == "" {
				scanTarget.Root = root
			}
			if !WithinRoot(scanTarget.Root, scanTarget.Path) {
				logging.Warn().
					Str("path", scanTarget.Path).
					Str("root", scanTarget.Root).
					Str("stage", "source_admission").
					Msg("skipping file: outside controlled root")
				return nil
			}

			wg.Add(1)
			s.Sema.Go(func() error {
				logger := logging.With().Str("path", scanTarget.Path).Logger()
				logger.Trace().Msg("scanning path")

				f, err := OpenControlled(scanTarget.Root, scanTarget.Path)
				if err != nil {
					if errors.Is(err, ErrPathOutsideRoot) {
						logger.Warn().Msg("skipping file: outside controlled root")
					} else if os.IsPermission(err) {
						logger.Warn().Msg("skipping file: permission denied")
					}
					wg.Done()
					return nil
				}

				// Convert this to a file source
				file := File{
					Content:         f,
					Path:            scanTarget.Path,
					Symlink:         scanTarget.Symlink,
					Root:            scanTarget.Root,
					Config:          s.Config,
					MaxArchiveDepth: s.MaxArchiveDepth,
				}

				err = file.Fragments(ctx, yield)
				// Avoiding a defer in a hot loop
				_ = f.Close()
				wg.Done()
				return err
			})

			return nil
		}
	})

	// Always wait for the goroutines this call scheduled. Returning as soon as
	// the context is done would let late fragments mutate findings after the
	// scan appeared to finish.
	wg.Wait()
	if err != nil {
		return err
	}
	return ctx.Err()
}
