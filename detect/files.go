package detect

import (
	"context"
	"errors"
	"os"
	"sync"

	"github.com/zricethezav/gitleaks/v8/logging"
	"github.com/zricethezav/gitleaks/v8/report"
	"github.com/zricethezav/gitleaks/v8/sources"
)

// DetectFiles runs detections against a chanel of scan targets
//
// Deprecated: Use sources.Files and Detector.DetectSource instead
func (d *Detector) DetectFiles(scanTargets <-chan sources.ScanTarget) ([]report.Finding, error) {
	if d.scanMutex == nil {
		d.scanMutex = &sync.Mutex{}
	}
	d.scanMutex.Lock()
	defer d.scanMutex.Unlock()

	scan := d.newScanDetector()
	scan.Sema = d.Sema
	scan.ConfigGeneration = d.generation.Add(1)
	scan.ScanSource = "files"
	var wg sync.WaitGroup

	for scanTarget := range scanTargets {
		wg.Add(1)

		scan.Sema.Go(func() error {
			defer wg.Done()

			logger := logging.With().Str("path", scanTarget.Path).Logger()
			logger.Trace().Msg("scanning path")

			f, err := os.Open(scanTarget.Path)
			if err != nil {
				if os.IsPermission(err) {
					err = errors.New("permission denied")
				}

				logger.Warn().Err(err).Msg("skipping file")
				return nil
			}
			defer func() {
				_ = f.Close()
			}()

			info, err := f.Stat()
			if err != nil {
				logger.Error().Err(err).Msg("skipping file: could not get info")
				return nil
			}

			// Empty; nothing to do here.
			if info.Size() == 0 {
				logger.Debug().Msg("skipping empty file")
				return nil
			}

			// Too large; nothing to do here.
			if scan.MaxTargetMegaBytes > 0 {
				rawLength := info.Size() / 1_000_000
				if rawLength > int64(scan.MaxTargetMegaBytes) {
					logger.Warn().Msgf(
						"skipping file: too large max_size=%dMB, size=%dMB",
						scan.MaxTargetMegaBytes, rawLength,
					)
					return nil
				}
			}

			// Convert this to a file source
			file := sources.File{
				Content:         f,
				Path:            scanTarget.Path,
				Symlink:         scanTarget.Symlink,
				Config:          &scan.Config,
				MaxArchiveDepth: scan.MaxArchiveDepth,
			}

			ctx := context.Background()
			return file.Fragments(ctx, func(fragment sources.Fragment, err error) error {
				if err != nil {
					logging.Error().Err(err)
					return nil
				}

				for _, finding := range scan.detectContext(ctx, Fragment(fragment)) {
					scan.AddFinding(finding)
				}
				return nil
			})
		})
	}

	wg.Wait()
	d.TotalBytes.Add(scan.TotalBytes.Load())
	d.ConfigVersion = scan.ConfigVersion
	d.ConfigPath = scan.ConfigPath
	d.ScanSource = scan.ScanSource
	d.ConfigGeneration = scan.ConfigGeneration
	d.Config.Version = scan.ConfigVersion
	findings := scan.Findings()
	d.setFindings(d.ReportFindings(findings))
	return findings, nil
}
