// © Roscoe Skeens <rskeens@defended.net>
// SPDX-License-Identifier: AGPL-3.0-or-later

package worker

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/defended-net/malwatch/pkg/boot/env"
	"github.com/defended-net/malwatch/pkg/scan/state"
	"github.com/defended-net/malwatch/pkg/sig"
)

var sample = `X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`

func TestNew(t *testing.T) {
	env, err := env.Mock(t.Name(), t.TempDir())
	if err != nil {
		t.Fatalf("env mock err %v", err)
	}

	if err := sig.Mock(env, true); err != nil {
		t.Fatalf("sig mock err %v", err)
	}

	if _, got := New(env.Cfg); got != nil {
		t.Errorf("create worker err %v", got)
	}
}

func TestWork(t *testing.T) {
	env, err := env.Mock(t.Name(), t.TempDir())
	if err != nil {
		t.Fatalf("env mock err %v", err)
	}

	worker, err := Mock(env)
	if err != nil {
		t.Fatalf("sig mock err %v", err)
	}

	queue := make(chan string)

	go func() {
		defer close(queue)

		queue <- filepath.Join(t.TempDir(), t.Name())
	}()

	state := state.NewJob()

	state.WGrp.Add(1)

	worker.Work(context.Background(), state, queue)
}

func TestScan(t *testing.T) {
	var (
		path  = filepath.Join(t.TempDir(), t.Name())
		input = []byte(sample)
	)

	env, err := env.Mock(t.Name(), t.TempDir())
	if err != nil {
		t.Fatalf("env mock err %v", err)
	}

	worker, err := Mock(env)
	if err != nil {
		t.Fatalf("sig mock err %v", err)
	}

	if err := os.WriteFile(path, input, 0600); err != nil {
		t.Errorf("file write err %v", err)
	}

	state := state.NewJob()

	go func(worker *Worker) {
		defer close(state.Hits)

		worker.Scan(path, state)
	}(worker)
}

func TestScanOpenErr(t *testing.T) {
	env, err := env.Mock(t.Name(), t.TempDir())
	if err != nil {
		t.Fatalf("env mock err %v", err)
	}

	worker, err := Mock(env)
	if err != nil {
		t.Fatalf("worker mock err %v", err)
	}

	job := state.NewJob()

	worker.Scan(filepath.Join(t.TempDir(), "not-exist"), job)

	if len(job.Errs()) == 0 {
		t.Errorf("unexpected empty errs")
	}
}

func TestWorkCtxCancel(t *testing.T) {
	env, err := env.Mock(t.Name(), t.TempDir())
	if err != nil {
		t.Fatalf("env mock err %v", err)
	}

	worker, err := Mock(env)
	if err != nil {
		t.Fatalf("worker mock err %v", err)
	}

	queue := make(chan string, 1)
	queue <- filepath.Join(t.TempDir(), t.Name())
	close(queue)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	job := state.NewJob()
	job.WGrp.Add(1)

	worker.Work(ctx, job, queue)
}

func TestScanMatch(t *testing.T) {
	var (
		path  = filepath.Join(t.TempDir(), t.Name())
		input = []byte(sample)
	)

	env, err := env.Mock(t.Name(), t.TempDir())
	if err != nil {
		t.Fatalf("env mock err %v", err)
	}

	worker, err := Mock(env)
	if err != nil {
		t.Fatalf("worker mock err %v", err)
	}

	if err := os.WriteFile(path, input, 0600); err != nil {
		t.Fatalf("file write err %v", err)
	}

	job := state.NewJob()

	go func() {
		defer close(job.Hits)

		worker.Scan(path, job)
	}()

	for hit := range job.Hits {
		if hit.Path != path {
			t.Errorf("unexpected hit path %v, want %v", hit.Path, path)
		}
	}
}

func TestRefresh(t *testing.T) {
	_env, err := env.Mock(t.Name(), t.TempDir())
	if err != nil {
		t.Fatalf("env mock err %v", err)
	}

	worker, err := Mock(_env)
	if err != nil {
		t.Fatalf("worker mock err %v", err)
	}

	if got := worker.Refresh(); got != nil {
		t.Errorf("refresh err %v", got)
	}
}

func TestMock(t *testing.T) {
	env, err := env.Mock(t.Name(), t.TempDir())
	if err != nil {
		t.Fatalf("env mock err %v", err)
	}

	if _, got := Mock(env); got != nil {
		t.Errorf("sig mock err %v", got)
	}
}

// newWorker returns a worker whose block size is exactly blkSz, bypassing the
// production jitter so window boundaries are deterministic for a test.
func newWorker(t *testing.T, env *env.Env, blkSz int) *Worker {
	t.Helper()

	if err := sig.Mock(env, true); err != nil {
		t.Fatalf("sig mock err %v", err)
	}

	worker, err := New(env.Cfg)
	if err != nil {
		t.Fatalf("worker err %v", err)
	}

	// Replace the jittered read buffer with a deterministic one while keeping
	// the scanner and action configuration built by New.
	worker.buff = make([]byte, blkSz)

	return worker
}

func drain(t *testing.T, worker *Worker, path string) *state.Hit {
	t.Helper()

	job := state.NewJob()

	go func() {
		defer close(job.Hits)

		worker.Scan(path, job)
	}()

	var got *state.Hit

	for hit := range job.Hits {
		if got != nil {
			t.Fatalf("unexpected extra hit %v", hit.Path)
		}

		got = hit
	}

	if errs := job.Errs(); len(errs) != 0 {
		t.Fatalf("unexpected job errs %v", errs)
	}

	return got
}

// writeRules writes one rule per name, each matching its own "<name>MARK"
// marker, into the mock sig dir and returns the worker built from them.
func writeRules(t *testing.T, env *env.Env, blkSz int, names ...string) *Worker {
	t.Helper()

	if err := os.MkdirAll(filepath.Join(env.Paths.Sigs.Src, "mock"), 0700); err != nil {
		t.Fatalf("sig dir err %v", err)
	}

	rules := ""
	for _, name := range names {
		rules += "rule " + name + ` { strings: $s = "` + name + `MARK" condition: any of them }` + "\n"
	}

	if err := os.WriteFile(
		filepath.Join(env.Paths.Sigs.Src, "mock", "extra.yr"),
		[]byte(rules),
		0600,
	); err != nil {
		t.Fatalf("rule write err %v", err)
	}

	return newWorker(t, env, blkSz)
}

// markerInput joins the named markers with single spaces, matching writeRules.
func markerInput(names ...string) []byte {
	markers := make([]string, len(names))

	for i, name := range names {
		markers[i] = name + "MARK"
	}

	return []byte(strings.Join(markers, " "))
}

// TestNextWindowOverlap proves the chunk context directly: every window after
// the first starts half a buffer before the previous end, so a marker straddling
// a read boundary is contained whole inside the following window, and the
// final short window reports the whole file was consumed.
func TestNextWindowOverlap(t *testing.T) {
	const blkSz = 128

	env, err := env.Mock(t.Name(), t.TempDir())
	if err != nil {
		t.Fatalf("env mock err %v", err)
	}

	worker := newWorker(t, env, blkSz)

	// Marker (36 bytes) starts inside the first full window's trailing overlap
	// region and is shorter than the half-window overlap (64 bytes), so it must
	// be contained whole inside the following window.
	input := append(bytes.Repeat([]byte{'z'}, blkSz-4), []byte(sample)...)
	input = append(input, bytes.Repeat([]byte{'z'}, 16)...)

	path := filepath.Join(t.TempDir(), t.Name())

	if err := os.WriteFile(path, input, 0600); err != nil {
		t.Fatalf("file write err %v", err)
	}

	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatalf("open err %v", err)
	}

	defer unix.Close(fd)

	var (
		dst      []byte
		windows  [][]byte
		complete bool
	)

	for {
		dst, complete, err = worker.nextWindow(fd, dst)
		if err != nil {
			t.Fatalf("next window err %v", err)
		}

		windows = append(windows, slices.Clone(dst))

		if complete {
			break
		}
	}

	if len(windows) < 2 {
		t.Fatalf("expected overlapping windows, got %d", len(windows))
	}

	// Every full window except the first must start half a buffer after the
	// previous one, proving consecutive windows overlap by half a buffer: a
	// string shorter than the overlap cannot fall between two windows.
	step := blkSz / windowOverlap

	for i := 1; i < len(windows)-1; i++ {
		if got := len(windows[i]); got != blkSz {
			t.Fatalf("window %d len %v, want %v", i, got, blkSz)
		}

		want := windows[i-1][step:]

		if !bytes.Equal(windows[i][:len(want)], want) {
			t.Fatalf("window %d missing half-buffer overlap with previous window", i)
		}
	}

	marker := []byte("$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!")

	if len(marker) > blkSz/windowOverlap {
		t.Fatalf("marker longer than overlap window")
	}

	seenWhole := false

	for _, window := range windows {
		if bytes.Contains(window, marker) {
			seenWhole = true
		}
	}

	if !seenWhole {
		t.Errorf("marker straddling boundary never seen whole; windows %v", windows)
	}
}

// TestScanCrossBlock proves end to end that a marker straddling a window
// boundary still matches through the overlapping window context.
func TestScanCrossBlock(t *testing.T) {
	const blkSz = 128

	env, err := env.Mock(t.Name(), t.TempDir())
	if err != nil {
		t.Fatalf("env mock err %v", err)
	}

	worker := newWorker(t, env, blkSz)

	input := append(bytes.Repeat([]byte{'z'}, blkSz-4), []byte(sample)...)
	input = append(input, bytes.Repeat([]byte{'z'}, 16)...)

	path := filepath.Join(t.TempDir(), t.Name())

	if err := os.WriteFile(path, input, 0600); err != nil {
		t.Fatalf("file write err %v", err)
	}

	hit := drain(t, worker, path)
	if hit == nil {
		t.Fatal("expected cross-block hit, got none")
	}

	if !slices.Contains(hit.Meta.Rules, "eicar") {
		t.Errorf("expected eicar rule in %v", hit.Meta.Rules)
	}

	if hit.Meta.Incomplete {
		t.Errorf("fully covered file must be complete, got incomplete")
	}
}

// TestScanSmallFileComplete proves ordinary small files keep full, complete
// evidence with no truncation flag and no extra windowing artifacts.
func TestScanSmallFileComplete(t *testing.T) {
	env, err := env.Mock(t.Name(), t.TempDir())
	if err != nil {
		t.Fatalf("env mock err %v", err)
	}

	worker := newWorker(t, env, 4096)

	path := filepath.Join(t.TempDir(), t.Name())

	if err := os.WriteFile(path, []byte(sample), 0600); err != nil {
		t.Fatalf("file write err %v", err)
	}

	hit := drain(t, worker, path)
	if hit == nil {
		t.Fatal("expected hit, got none")
	}

	switch {
	case !slices.Equal(hit.Meta.Rules, []string{"eicar"}):
		t.Errorf("unexpected rules %v, want [eicar]", hit.Meta.Rules)

	case hit.Meta.Incomplete:
		t.Errorf("small file result must be complete, got incomplete")
	}
}

// TestScanEmptyFile proves an empty file produces no hit, no error and no
// incomplete flag: there is simply no evidence, not truncated evidence.
func TestScanEmptyFile(t *testing.T) {
	env, err := env.Mock(t.Name(), t.TempDir())
	if err != nil {
		t.Fatalf("env mock err %v", err)
	}

	worker := newWorker(t, env, 128)

	path := filepath.Join(t.TempDir(), t.Name())

	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatalf("file write err %v", err)
	}

	job := state.NewJob()

	go func() {
		defer close(job.Hits)

		worker.Scan(path, job)
	}()

	for range job.Hits {
		t.Fatal("empty file must not produce a hit")
	}

	if errs := job.Errs(); len(errs) != 0 {
		t.Fatalf("empty file must not error, got %v", errs)
	}

	if worker.capped {
		t.Errorf("empty file must not be flagged capped")
	}
}

// TestScanHitsCapped proves the per-file rule budget: exactly maxHits rules
// are reported, the file is not read to completion and the result is flagged
// incomplete rather than silently truncated.
func TestScanHitsCapped(t *testing.T) {
	const blkSz = 32

	env, err := env.Mock(t.Name(), t.TempDir())
	if err != nil {
		t.Fatalf("env mock err %v", err)
	}

	// Five rules, each with a distinct marker, so the budget of four must
	// leave at least one rule unevaluated when all markers are present.
	worker := writeRules(t, env, blkSz, "r0", "r1", "r2", "r3", "r4")
	input := markerInput("r0", "r1", "r2", "r3", "r4")

	path := filepath.Join(t.TempDir(), t.Name())

	if err := os.WriteFile(path, input, 0600); err != nil {
		t.Fatalf("file write err %v", err)
	}

	hit := drain(t, worker, path)
	if hit == nil {
		t.Fatal("expected capped hit, got none")
	}

	switch {
	case len(hit.Meta.Rules) != maxHits:
		t.Errorf("unexpected rule count %v, want %v (%v)", len(hit.Meta.Rules), maxHits, hit.Meta.Rules)

	case !hit.Meta.Incomplete:
		t.Errorf("capped result must be flagged incomplete, rules %v", hit.Meta.Rules)

	case slices.Contains(hit.Meta.Rules, "r4"):
		t.Errorf("budget must stop before later rules, got %v", hit.Meta.Rules)
	}
}

// TestScanCapAtEOFComplete proves that reaching the rule budget in the very
// last window is not mislabeled incomplete: every byte was evaluated, so the
// evidence is complete even though the budget was reached.
func TestScanCapAtEOFComplete(t *testing.T) {
	const blkSz = 32

	env, err := env.Mock(t.Name(), t.TempDir())
	if err != nil {
		t.Fatalf("env mock err %v", err)
	}

	worker := writeRules(t, env, blkSz, "e0", "e1", "e2", "e3")

	// Exactly maxHits markers, all inside the single short final window.
	input := markerInput("e0", "e1", "e2", "e3")

	path := filepath.Join(t.TempDir(), t.Name())

	if err := os.WriteFile(path, input, 0600); err != nil {
		t.Fatalf("file write err %v", err)
	}

	hit := drain(t, worker, path)
	if hit == nil {
		t.Fatal("expected hit, got none")
	}

	switch {
	case len(hit.Meta.Rules) != maxHits:
		t.Errorf("unexpected rule count %v, want %v", len(hit.Meta.Rules), maxHits)

	case hit.Meta.Incomplete:
		t.Errorf("budget reached at EOF must stay complete, rules %v", hit.Meta.Rules)
	}
}

// TestScanBelowCapComplete proves a multi-hit file under the budget keeps
// complete evidence and the incomplete flag stays unset.
func TestScanBelowCapComplete(t *testing.T) {
	const blkSz = 32

	env, err := env.Mock(t.Name(), t.TempDir())
	if err != nil {
		t.Fatalf("env mock err %v", err)
	}

	worker := writeRules(t, env, blkSz, "a0", "a1", "a2")

	path := filepath.Join(t.TempDir(), t.Name())

	if err := os.WriteFile(path, markerInput("a0", "a1", "a2"), 0600); err != nil {
		t.Fatalf("file write err %v", err)
	}

	hit := drain(t, worker, path)
	if hit == nil {
		t.Fatal("expected hit, got none")
	}

	switch {
	case len(hit.Meta.Rules) != 3:
		t.Errorf("unexpected rules %v, want all three", hit.Meta.Rules)

	case hit.Meta.Incomplete:
		t.Errorf("under-budget result must be complete, got incomplete")
	}
}
