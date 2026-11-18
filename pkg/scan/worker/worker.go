// © Roscoe Skeens <rskeens@defended.net>
// SPDX-License-Identifier: AGPL-3.0-or-later

package worker

import (
	"context"
	"fmt"
	"math/rand/v2"
	"runtime"
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
	"github.com/defended-net/malwatch/pkg/tui/tbl"
	"github.com/defended-net/malwatch/third_party/yr"
)

// Refresh stages.
const (
	stageBuild  = "BUILD"
	stageSwitch = "SWITCH"

	statusOK    = "OK"
	statusErr   = "ERROR"
	statusSkip  = "SKIP"
	stageCommit = "COMMIT"
	stageBack   = "ROLLBACK"
)

// Stage records one refresh stage for a worker.
type Stage struct {
	Worker int
	Name   string
	Before uint64
	After  uint64
	Status string
	Err    error
}

// Report represents an atomic multi-worker refresh report.
type Report struct {
	Target     uint64
	Prev       uint64
	Stages     []Stage
	Committed  bool
	RolledBack bool
}

// Worker represents a worker.
// blkSz unit is byte.
type Worker struct {
	scanner atomic.Pointer[state.Scanner]
	matches matches
	acts    *act.Cfg
	buff    []byte
	stat    *unix.Stat_t
	maxAge  int
	exp     time.Time
}

// matches represents matched rules.
type matches []string

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
		scanner *state.Scanner
		offset  int
	)

	// Pin one generation for the whole block: a rule refresh may retire the
	// current scanner mid-scan, but the pinned generation stays valid until
	// Exit, so a block never mixes revisions.
	for !worker.pin(&scanner) {
		runtime.Gosched()
	}

	defer scanner.Exit()

out:
	for {
		offset, err = unix.Read(fd, worker.buff)

		switch {
		case offset > 0:
			if err := scanner.Val.ScanMem(worker.buff[:offset]); err != nil {
				result.AddErr(fmt.Errorf("%w, %v, %v", ErrYrScan, err, path))

				return
			}

			// condemn
			if len(worker.matches) > 3 {
				break out
			}

		default:
			break out
		}
	}

	if err != nil {
		result.AddErr(fmt.Errorf("%w, %v, %v", ErrFileRead, err, path))
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
			worker.acts.NewVerbs(path, matches...)...,
		),
	}
}

func (worker *Worker) pin(scanner **state.Scanner) bool {
	candidate := worker.scanner.Load()

	if candidate == nil || !candidate.Enter() {
		return false
	}

	if worker.scanner.Load() != candidate {
		candidate.Exit()

		return false
	}

	*scanner = candidate

	return true
}

// Refresh updates the worker to use the latest sigs with a new scanner.
func (worker *Worker) Refresh() error {
	scanner, err := worker.build()
	if err != nil {
		return err
	}

	if old := worker.scanner.Swap(scanner); old != nil {
		old.Retire()
	}

	return nil
}

// Rev returns the worker's current scanner revision.
func (worker *Worker) Rev() uint64 {
	scanner := worker.scanner.Load()
	if scanner == nil {
		return 0
	}

	return scanner.Rev
}

// build creates a scanner for the current global sigs without publishing it.
// The returned scanner holds one sigs reference, released on retirement.
func (worker *Worker) build() (*state.Scanner, error) {
	sigs, err := sig.Acquire()
	if err != nil {
		return nil, err
	}

	scanner, err := yr.NewScanner(sigs.Rules)
	if err != nil {
		sigs.Release()
		return nil, err
	}

	scanner.SetFlags(yr.ScanFlagsFastMode)
	scanner.SetCallback(&worker.matches)

	update := &state.Scanner{
		Val:  scanner,
		Rev:  sigs.Rev,
		GcFn: sigs.Release,
	}

	return update, nil
}

// Publish atomically switches every worker to a freshly built scanner for the
// current global sigs. All scanners are built first: any build failure leaves
// every worker on its previous generation and the staged scanners are freed,
// so a later refresh retries the same global revision instead of repeating a
// half update. On success the scanners are swapped in one per worker and the
// previous generation is retired once in-flight blocks finish.
func Publish(workers []*Worker) (*Report, error) {
	return publish(workers, nil)
}

func publish(workers []*Worker, buildErr func(int) error) (*Report, error) {
	var (
		report  = &Report{}
		staged  = make([]*state.Scanner, len(workers))
		failure error
	)

	if len(workers) > 0 {
		report.Prev = workers[0].Rev()
	}

	for idx, worker := range workers {
		var (
			before = worker.Rev()
			stage  = Stage{
				Worker: idx + 1,
				Name:   stageBuild,
				Before: before,
				After:  before,
				Status: statusOK,
			}
		)

		scanner, err := worker.build()

		if err == nil && buildErr != nil {
			if injected := buildErr(idx); injected != nil {
				err = injected
				scanner.Retire()
				scanner = nil
			}
		}

		if err != nil {
			stage.Status = statusErr
			stage.Err = err
			report.Stages = append(report.Stages, stage)

			if failure == nil {
				failure = err
			}

			for _, pending := range staged {
				if pending != nil {
					pending.Retire()
				}
			}

			for remaining := idx + 1; remaining < len(workers); remaining++ {
				report.Stages = append(report.Stages, Stage{
					Worker: remaining + 1,
					Name:   stageBuild,
					Before: workers[remaining].Rev(),
					After:  workers[remaining].Rev(),
					Status: statusSkip,
				})
			}

			report.finish(stageBack, failure)

			return report, failure
		}

		stage.After = scanner.Rev
		report.Target = scanner.Rev
		staged[idx] = scanner
		report.Stages = append(report.Stages, stage)
	}

	// Every scanner built successfully: swap the generations. A swap cannot
	// fail, so workers cannot end up split across revisions.
	for idx, worker := range workers {
		before := worker.Rev()
		old := worker.scanner.Swap(staged[idx])

		if old != nil {
			old.Retire()
		}

		report.Stages = append(report.Stages, Stage{
			Worker: idx + 1,
			Name:   stageSwitch,
			Before: before,
			After:  staged[idx].Rev,
			Status: statusOK,
		})
	}

	report.finish(stageCommit, nil)

	return report, nil
}

func (report *Report) finish(name string, err error) {
	committed := name == stageCommit
	report.Committed = committed
	report.RolledBack = !committed

	var (
		rev    = report.Prev
		status = statusErr
	)

	if committed {
		rev = report.Target
		status = statusOK
	}

	report.Stages = append(report.Stages, Stage{
		Name:   name,
		Before: report.Prev,
		After:  rev,
		Status: status,
		Err:    err,
	})
}

// Print renders the fixed refresh table: every worker's revision per stage,
// followed by the final committed revision or a full rollback.
func (report *Report) Print() {
	rows := make([][]string, 0, len(report.Stages)+1)

	for _, stage := range report.Stages {
		status := stage.Status
		if stage.Err != nil {
			status = fmt.Sprintf("%v: %v", status, stage.Err)
		}

		worker := "-"
		if stage.Worker != 0 {
			worker = fmt.Sprint(stage.Worker)
		}

		rows = append(rows, []string{
			worker,
			stage.Name,
			fmt.Sprint(stage.Before),
			fmt.Sprint(stage.After),
			status,
		})
	}

	tbl.Print("sig refresh", tbl.HdrSigRefresh, rows)
}

// RuleMatching implements yr.ScanCallback.
func (matches *matches) RuleMatching(_ *yr.ScanContext, rule *yr.Rule) (bool, error) {
	hit := rule.Identifier()

	if slices.Contains(*matches, hit) {
		return false, nil
	}

	*matches = append(*matches, hit)

	return len(*matches) > 3, nil
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
