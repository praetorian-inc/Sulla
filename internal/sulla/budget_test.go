package sulla

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sync/semaphore"
)

// nil budgets => unbounded: reserve returns a usable no-op release, never blocks.
func TestReserveBytesNilUnbounded(t *testing.T) {
	var c Config // SmallBudget and LargeBudget are nil
	release, err := c.reserveBytes(context.Background(), 50*1024*1024)
	if err != nil {
		t.Fatalf("nil budget should not error: %v", err)
	}
	release() // must not panic
}

// A small acquire must NOT queue behind a parked large acquire (the FIFO head-of-line
// problem). With LargeBudget saturated and a large request parked, a small reserve
// still succeeds because it draws from SmallBudget.
func TestReserveBytesSmallNotBlockedByParkedLarge(t *testing.T) {
	c := Config{
		SmallBudget: semaphore.NewWeighted(10 * 1024 * 1024),
		LargeBudget: semaphore.NewWeighted(50 * 1024 * 1024),
	}

	// Saturate LargeBudget (40MB > budgetSmallClassMax => routes to LargeBudget).
	relBig, err := c.reserveBytes(context.Background(), 40*1024*1024)
	if err != nil {
		t.Fatalf("first large reserve: %v", err)
	}

	// Park a second large acquire that cannot be satisfied (40MB + 40MB > 50MB).
	parked := make(chan struct{})
	go func() {
		rel, _ := c.reserveBytes(context.Background(), 40*1024*1024)
		rel()
		close(parked)
	}()
	time.Sleep(20 * time.Millisecond) // let it park at the LargeBudget queue head

	// A small reserve (4KB) must proceed immediately despite the parked large one.
	done := make(chan struct{})
	go func() {
		rel, rerr := c.reserveBytes(context.Background(), 4*1024)
		if rerr != nil {
			t.Errorf("small reserve errored: %v", rerr)
		}
		rel()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("small reserve blocked behind parked large acquire (partition failed)")
	}

	relBig() // unblocks the parked large acquire
	<-parked
}

// LargeBudget bounds concurrent large bytes: with a 100MB budget, no more than two
// 50MB reserves are ever held at once.
func TestReserveBytesBoundsLargeConcurrency(t *testing.T) {
	c := Config{
		SmallBudget: semaphore.NewWeighted(10 * 1024 * 1024),
		LargeBudget: semaphore.NewWeighted(100 * 1024 * 1024),
	}
	var current, peak int64
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rel, err := c.reserveBytes(context.Background(), 50*1024*1024)
			if err != nil {
				t.Errorf("reserve: %v", err)
				return
			}
			cur := atomic.AddInt64(&current, 1)
			for {
				p := atomic.LoadInt64(&peak)
				if cur <= p || atomic.CompareAndSwapInt64(&peak, p, cur) {
					break
				}
			}
			time.Sleep(time.Millisecond)
			atomic.AddInt64(&current, -1)
			rel()
		}()
	}
	wg.Wait()
	if peak > 2 {
		t.Fatalf("peak concurrent 50MB reserves = %d, want <= 2 (100MB budget)", peak)
	}
	if peak == 0 {
		t.Fatal("peak was 0; test did not exercise the budget")
	}
}

// A cancelled context aborts a blocked reserve with an error and a no-op release.
func TestReserveBytesContextCancel(t *testing.T) {
	c := Config{LargeBudget: semaphore.NewWeighted(10 * 1024 * 1024)}
	hold, _ := c.reserveBytes(context.Background(), 10*1024*1024) // fully saturate
	defer hold()

	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(20 * time.Millisecond); cancel() }()

	release, err := c.reserveBytes(ctx, 10*1024*1024)
	if err == nil {
		t.Fatal("expected context error from blocked reserve")
	}
	release() // must be a safe no-op on error
}
