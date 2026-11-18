// © Roscoe Skeens <rskeens@defended.net>
// SPDX-License-Identifier: AGPL-3.0-or-later

package state

import (
	"sync"
	"sync/atomic"

	"github.com/defended-net/malwatch/third_party/yr"
)

// Scanner represents yara.
type Scanner struct {
	Val      *yr.Scanner
	Rev      uint64
	GcFn     func()
	inFlight atomic.Int64
	retired  atomic.Bool
	done     sync.Once
}

// Enter pins the scanner for one in-flight scan. Returns false once the
// scanner has been retired and the caller must load a newer generation.
func (scanner *Scanner) Enter() bool {
	if scanner == nil || scanner.retired.Load() {
		return false
	}

	scanner.inFlight.Add(1)

	if scanner.retired.Load() {
		scanner.Exit()

		return false
	}

	return true
}

// Exit releases one in-flight scan pin obtained through Enter.
func (scanner *Scanner) Exit() {
	if scanner == nil {
		return
	}

	if scanner.inFlight.Add(-1) == 0 && scanner.retired.Load() {
		scanner.done.Do(scanner.destroy)
	}
}

// Retire releases the generation reference held by the owner. The underlying
// yara scanner stays alive until every in-flight scan has called Exit.
func (scanner *Scanner) Retire() {
	if scanner == nil || !scanner.retired.CompareAndSwap(false, true) {
		return
	}

	if scanner.inFlight.Load() == 0 {
		scanner.done.Do(scanner.destroy)
	}
}

// Gc does cleanup.
func (scanner *Scanner) Gc() {
	scanner.Retire()
}

// destroy frees the yara scanner and the sigs reference exactly once.
func (scanner *Scanner) destroy() {
	if scanner.Val != nil {
		scanner.Val.Destroy()
		scanner.Val = nil
	}

	if scanner.GcFn != nil {
		scanner.GcFn()
		scanner.GcFn = nil
	}
}
