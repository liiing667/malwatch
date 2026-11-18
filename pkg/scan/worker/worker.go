// © Roscoe Skeens <rskeens@defended.net>
// SPDX-License-Identifier: AGPL-3.0-or-later

package worker

import (
	"context"
	"fmt"
	"math/rand/v2"
	"slices"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"

	"github.com/defended-net/malwatch/pkg/boot/env"
	"github.com/defended-net/malwatch/pkg/boot/env/cfg/act"
	"github.com/defended-net/malwatch/pkg/boot/env/cfg/base"
	"github.com/defended-net/malwatch/pkg/db/orm/hit"
	"github.com/defended-net/malwatch/pkg/fsys"
	"github.com/defended-net/malwatch/pkg/scan/state"
	"github.com/defended-net/malwatch/pkg/sig"
	"github.com/defended-net/malwatch/third_party/yr"
)

// Worker represents a worker.
// blkSz unit is byte.
type Worker struct {
	scanner atomic.Pointer[state.Scanner]
	matches matches
	capped  bool
	acts    *act.Cfg
	buff    []byte
	stat    *unix.Stat_t
	maxAge  int
	exp     time.Time
}

// matches represents matched rules.
type matches []string

const (
	// maxHits is the per-file rule budget. Matching beyond the budget is not
	// evaluated and every capped result is flagged as incomplete.
	maxHits = 4

	// windowOverlap is the fraction of a window re-read by the next window.
	// Consecutive windows overlap by len(buff)/windowOverlap bytes, which keeps
	// any string up to the overlap length whole inside a window regardless of
	// where the randomized boundary lands.
	windowOverlap = 2
)

// New returns a worker from given cfg, rules and max file age.
func New(cfg *base.Cfg) (*Worker, error) {
	var (
		// #nosec G404 -- non crypto jitter.
		blkSz = int(float64(cfg.Scans.BlkSz) * (0.8 + rand.Float64()*0.2))

		worker = &Worker{
			acts:   cfg.Acts,
			buff:   make([]byte, blkSz),
			stat:   &unix.Stat_t{},
			maxAge: cfg.Scans.MaxAge,
			exp:    time.Now().AddDate(0, 0, -cfg.Scans.MaxAge),
		}
	)

	if err := worker.Refresh(); err != nil {
		return nil, err
	}

	return worker, nil
}

// Work receives given queued paths to scan.
func (worker *Worker) Work(ctx context.Context, state *state.Job, queue <-chan string) {
	defer state.WGrp.Done()

	done := ctx.Done()

	for {
		select {
		case <-done:
			return

		case path, ok := <-queue:
			if !ok {
				return
			}

			worker.Scan(path, state)
		}
	}
}

// Scan scans given file path and job state. Results and errs to job state.
func (worker *Worker) Scan(path string, result *state.Job) {
	worker.matches = worker.matches[:0]
	worker.capped = false

	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		result.AddErr(fmt.Errorf("%w, %v, %v", ErrFileRead, err, path))

		return
	}

	// nolint
	defer unix.Close(fd)

	if worker.maxAge != 0 && fsys.IsExp(worker.exp, fd, worker.stat) {
		return
	}

	var (
		scanner = worker.scanner.Load()
		// Windows are buff long and advance by half a buffer. Consecutive
		// windows therefore overlap by half a buffer, keeping any string up to
		// buff bytes whole inside at least one window across every boundary.
		window      = make([]byte, 0, len(worker.buff))
		readErr     error
		complete    bool
		windowStart int64
	)

	for {
		if windowStart, err = unix.Seek(fd, 0, unix.SEEK_CUR); err != nil {
			result.AddErr(fmt.Errorf("%w, %v, %v", ErrFileRead, err, path))

			return
		}

		window, complete, readErr = worker.nextWindow(fd, window)

		if len(window) == 0 {
			break
		}

		if err := scanner.Val.ScanMem(window); err != nil {
			result.AddErr(fmt.Errorf("%w, %v, %v", ErrYrScan, err, path))

			return
		}

		if worker.capped {
			// The flag is only honest when bytes exist beyond the window just
			// scanned. A window reaching EOF (complete, or a full window ending
			// exactly at EOF) has covered the whole file despite the budget.
			if complete || windowStart+int64(len(window)) >= worker.fileSize(fd) {
				worker.capped = false
			}

			break
		}

		if complete {
			// The final short window covered the file tail. Every byte was
			// inside at least one window and the result is complete.
			break
		}
	}

	if readErr != nil {
		result.AddErr(fmt.Errorf("%w, %v, %v", ErrFileRead, readErr, path))

		return
	}

	if len(worker.matches) == 0 {
		return
	}

	matches := slices.Clone(worker.matches)
	slices.Sort(matches)

	if err := unix.Fstat(fd, worker.stat); err != nil {
		result.AddErr(fmt.Errorf("%w, %v, %v", fsys.ErrStat, err, path))
	}

	result.Hits <- &state.Hit{
		Path: path,

		Meta: hit.NewMeta(
			fsys.NewAttr(worker.stat),
			matches,
			worker.capped,
			worker.acts.NewVerbs(path, matches...)...,
		),
	}
}

// nextWindow returns the next fixed-budget scan window for given fd. The file
// offset is managed with Seek so the fd always sits at the start of the
// returned window: the first window starts at zero, every later window starts
// half a buffer further on, which leaves a half-buffer overlap with the
// previous window. A short final window signals complete=true and proves the
// whole file was covered. Read errors are returned alongside the partial
// window so its evidence is not lost. dst is reused and keeps its own backing
// array, separate from the read buffer.
func (worker *Worker) nextWindow(fd int, dst []byte) (window []byte, complete bool, err error) {
	window = dst[:0]

	for len(window) < len(worker.buff) {
		n, readErr := unix.Read(fd, worker.buff)
		if n > 0 {
			window = append(window, worker.buff[:n]...)
		}

		if readErr != nil {
			return window, false, readErr
		}

		if n == 0 {
			return window, true, nil
		}
	}

	// Advance only by half a window: the next Seek rewinds the other half so
	// consecutive windows overlap by len(worker.buff)/windowOverlap bytes.
	if _, err = unix.Seek(fd, -int64(len(worker.buff)/windowOverlap), unix.SEEK_CUR); err != nil {
		return window, false, err
	}

	return window, false, nil
}

// fileSize returns given fd's size in bytes. On error it returns a value
// larger than any real offset so callers conservatively keep the incomplete
// flag rather than silently claiming complete evidence.
func (worker *Worker) fileSize(fd int) int64 {
	var stat unix.Stat_t

	if err := unix.Fstat(fd, &stat); err != nil {
		return 1<<63 - 1
	}

	return stat.Size
}

// Refresh updates the worker to use the latest sigs with a new scanner.
func (worker *Worker) Refresh() error {
	sigs, err := sig.Acquire()
	if err != nil {
		return err
	}

	scanner, err := yr.NewScanner(sigs.Rules)
	if err != nil {
		sigs.Release()
		return err
	}

	scanner.SetFlags(yr.ScanFlagsFastMode)
	scanner.SetCallback(worker)

	update := &state.Scanner{
		Val:  scanner,
		Rev:  sigs.Rev,
		GcFn: sigs.Release,
	}

	if old := worker.scanner.Swap(update); old != nil {
		old.Gc()
	}

	return nil
}

// RuleMatching implements yr.ScanCallback.
func (worker *Worker) RuleMatching(_ *yr.ScanContext, rule *yr.Rule) (bool, error) {
	hit := rule.Identifier()

	if slices.Contains(worker.matches, hit) {
		return false, nil
	}

	worker.matches = append(worker.matches, hit)

	if len(worker.matches) >= maxHits {
		// Tell libyara to stop evaluating this file. The caller marks the
		// resulting hit as incomplete because later rules were not evaluated.
		worker.capped = true

		return true, nil
	}

	return false, nil
}

// Mock mocks a worker.
func Mock(env *env.Env) (*Worker, error) {
	if err := sig.Mock(env, true); err != nil {
		return nil, err
	}

	worker, err := New(env.Cfg)
	if err != nil {
		return nil, err
	}

	return worker, nil
}
