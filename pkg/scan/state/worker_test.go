// © Roscoe Skeens <rskeens@defended.net>
// SPDX-License-Identifier: AGPL-3.0-or-later

package state

import (
	"sync/atomic"
	"testing"
)

func TestGc(t *testing.T) {
	var (
		called = false

		input = &Scanner{
			GcFn: func() { called = true },
		}
	)

	input.Gc()

	switch {
	case !called:
		t.Errorf("gc fn not called")

	case input.GcFn != nil:
		t.Errorf("gc fn not cleared")
	}

	// Second call must be noop.
	input.Gc()
}

func TestGcEmpty(_ *testing.T) {
	input := &Scanner{}

	// Safe as nil val with nil gcfn.
	input.Gc()
}

func TestEnterExit(t *testing.T) {
	var calls atomic.Int32

	input := &Scanner{
		GcFn: func() { calls.Add(1) },
	}

	if !input.Enter() {
		t.Fatalf("enter rejected live scanner")
	}

	// Retire while a block is in flight: destruction must wait for Exit.
	input.Retire()

	if got := calls.Load(); got != 0 {
		t.Fatalf("destroyed while in flight, calls %v", got)
	}

	if input.Enter() {
		t.Fatalf("enter accepted retired scanner")
	}

	input.Exit()

	if got := calls.Load(); got != 1 {
		t.Errorf("unexpected gc calls %v, want 1", got)
	}

	// Retirement and exit are idempotent.
	input.Retire()
	input.Exit()

	if got := calls.Load(); got != 1 {
		t.Errorf("unexpected gc calls %v, want 1", got)
	}
}

func TestRetireWithoutFlight(t *testing.T) {
	var calls atomic.Int32

	input := &Scanner{
		GcFn: func() { calls.Add(1) },
	}

	input.Retire()

	if got := calls.Load(); got != 1 {
		t.Errorf("unexpected gc calls %v, want 1", got)
	}
}

func TestEnterNil(t *testing.T) {
	var input *Scanner

	if input.Enter() {
		t.Errorf("nil enter accepted")
	}

	input.Exit()
	input.Retire()
}
