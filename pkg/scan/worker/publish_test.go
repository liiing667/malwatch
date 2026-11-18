// © Roscoe Skeens <rskeens@defended.net>
// SPDX-License-Identifier: AGPL-3.0-or-later

package worker

import (
	"errors"
	"testing"

	"github.com/defended-net/malwatch/pkg/boot/env"
	"github.com/defended-net/malwatch/pkg/sig"
)

func mockWorkers(t *testing.T, n int) []*Worker {
	t.Helper()

	env, err := env.Mock(t.Name(), t.TempDir())
	if err != nil {
		t.Fatalf("env mock err %v", err)
	}

	if err := sig.Mock(env, true); err != nil {
		t.Fatalf("sig mock err %v", err)
	}

	workers := make([]*Worker, 0, n)

	for range n {
		worker, err := New(env.Cfg)
		if err != nil {
			t.Fatalf("worker create err %v", err)
		}

		workers = append(workers, worker)
	}

	return workers
}

func TestPublishCommit(t *testing.T) {
	workers := mockWorkers(t, 3)

	sigs, err := sig.Acquire()
	if err != nil {
		t.Fatalf("acquire err %v", err)
	}

	want := sigs.Rev
	sigs.Release()

	before := make([]uint64, len(workers))

	for idx, worker := range workers {
		before[idx] = worker.Rev()
	}

	report, err := Publish(workers)
	if err != nil {
		t.Fatalf("publish err %v", err)
	}

	if !report.Committed || report.RolledBack {
		t.Fatalf("unexpected report state committed=%v rolledback=%v", report.Committed, report.RolledBack)
	}

	if len(report.Stages) != 2*len(workers)+1 {
		t.Fatalf("unexpected stage count %v, want %v", len(report.Stages), 2*len(workers)+1)
	}

	for idx, worker := range workers {
		if worker.Rev() != want {
			t.Errorf("worker %v rev %v, want %v", idx+1, worker.Rev(), want)
		}

		if report.Target != want {
			t.Errorf("target %v, want %v", report.Target, want)
		}
	}

	last := report.Stages[len(report.Stages)-1]

	if last.Name != stageCommit || last.After != want || last.Status != statusOK {
		t.Errorf("unexpected final stage %+v", last)
	}

	report.Print()
}

func TestPublishRollback(t *testing.T) {
	var (
		workers = mockWorkers(t, 3)
		want    = errors.New("build failure")
		before  = make([]uint64, len(workers))
	)

	for idx, worker := range workers {
		before[idx] = worker.Rev()
	}

	// Fail the build for the second worker.
	report, got := publish(workers, func(idx int) error {
		if idx == 1 {
			return want
		}

		return nil
	})

	if !errors.Is(got, want) {
		t.Fatalf("unexpected err %v, want %v", got, want)
	}

	if report.Committed || !report.RolledBack {
		t.Fatalf("unexpected report state committed=%v rolledback=%v", report.Committed, report.RolledBack)
	}

	// Every worker stays on its previous generation: no half update.
	for idx, worker := range workers {
		if worker.Rev() != before[idx] {
			t.Errorf("worker %v rev %v, want rolled back %v", idx+1, worker.Rev(), before[idx])
		}
	}

	var (
		builds    int
		switches  int
		skipped   int
		rollbacks int
	)

	for _, stage := range report.Stages {
		switch stage.Name {
		case stageBuild:
			builds++
		case stageSwitch:
			switches++
		case stageBack:
			rollbacks++

			if stage.After != report.Prev || stage.Err == nil {
				t.Errorf("unexpected rollback stage %+v", stage)
			}
		}

		if stage.Status == statusSkip {
			skipped++
		}
	}

	switch {
	case builds != len(workers):
		t.Errorf("build stages %v, want %v", builds, len(workers))

	case switches != 0:
		t.Errorf("switch stages %v, want 0", switches)

	case skipped != 1:
		t.Errorf("skipped stages %v, want 1", skipped)

	case rollbacks != 1:
		t.Errorf("rollback stages %v, want 1", rollbacks)
	}

	report.Print()
}

func TestRev(t *testing.T) {
	workers := mockWorkers(t, 1)

	sigs, err := sig.Acquire()
	if err != nil {
		t.Fatalf("acquire err %v", err)
	}

	defer sigs.Release()

	if got := workers[0].Rev(); got != sigs.Rev {
		t.Errorf("unexpected rev %v, want %v", got, sigs.Rev)
	}
}

func TestPublishEmpty(t *testing.T) {
	report, err := Publish(nil)
	if err != nil {
		t.Fatalf("empty publish err %v", err)
	}

	if !report.Committed || report.Target != 0 || report.Prev != 0 {
		t.Errorf("unexpected empty report %+v", report)
	}

	if len(report.Stages) != 1 || report.Stages[0].Name != stageCommit {
		t.Errorf("unexpected empty stages %+v", report.Stages)
	}
}
