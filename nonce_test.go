package samesame

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// testNonceStore returns a store with a controllable clock.
func testNonceStore(size int) (*MemoryNonceStore, *time.Time) {
	now := time.Unix(1_000_000, 0)
	s := NewMemoryNonceStore(size)
	s.now = func() time.Time { return now }
	return s, &now
}

func mustCheck(t *testing.T, s *MemoryNonceStore, scope, nonce string, until time.Time, wantFresh bool) {
	t.Helper()

	fresh, err := s.CheckAndRecord(context.Background(), scope, nonce, until)
	if err != nil {
		t.Fatalf("%s/%s: %v", scope, nonce, err)
	}
	if fresh != wantFresh {
		t.Fatalf("%s/%s: want fresh=%v, got %v", scope, nonce, wantFresh, fresh)
	}
}

func TestMemoryNonceStore(t *testing.T) {
	t.Parallel()

	s, now := testNonceStore(4)
	later := func(d time.Duration) time.Time { return now.Add(d) }

	mustCheck(t, s, "agent", "a", later(time.Minute), true)
	mustCheck(t, s, "agent", "a", later(time.Minute), false)

	// Nonces are per scope.
	mustCheck(t, s, "other", "a", later(time.Minute), true)

	// An already-expired signature has nothing to remember.
	mustCheck(t, s, "agent", "b", *now, true)
	if s.Len() != 2 {
		t.Fatalf("want 2 nonces, got %d", s.Len())
	}

	// Once a nonce expires it is forgotten.
	*now = now.Add(time.Minute)
	mustCheck(t, s, "agent", "a", later(time.Minute), true)
	if s.Len() != 1 {
		t.Fatalf("want 1 nonce after expiry, got %d", s.Len())
	}
	if s.Evicted() != 0 {
		t.Errorf("want no evictions, got %d", s.Evicted())
	}
}

// A flood from one scope must not stop other scopes from being checked,
// and must not evict their nonces.
func TestMemoryNonceStoreFloodEvictsFlooder(t *testing.T) {
	t.Parallel()

	s, now := testNonceStore(8)
	until := now.Add(24 * time.Hour)

	mustCheck(t, s, "honest", "h1", until, true)
	for i := range 100 {
		mustCheck(t, s, "flooder", fmt.Sprint(i), until, true)
	}

	// The honest agent still gets answers, and its nonce survived.
	mustCheck(t, s, "honest", "h2", until, true)
	mustCheck(t, s, "honest", "h1", until, false)

	if s.Len() != 8 {
		t.Errorf("want the store full at 8, got %d", s.Len())
	}
	if s.Evicted() == 0 {
		t.Error("evictions were not counted")
	}
}

func TestMemoryNonceStoreEvictsLargestScopeFirst(t *testing.T) {
	t.Parallel()

	s, now := testNonceStore(6)

	// small holds 1, big holds 3 with different expiries, mid holds 2.
	mustCheck(t, s, "small", "s", now.Add(time.Hour), true)
	mustCheck(t, s, "big", "b-late", now.Add(3*time.Hour), true)
	mustCheck(t, s, "big", "b-soon", now.Add(time.Hour), true)
	mustCheck(t, s, "big", "b-mid", now.Add(2*time.Hour), true)
	mustCheck(t, s, "mid", "m1", now.Add(time.Hour), true)
	mustCheck(t, s, "mid", "m2", now.Add(time.Hour), true)

	// Full: the next add evicts big's soonest-expiring nonce.
	mustCheck(t, s, "small", "s2", now.Add(time.Hour), true)

	mustCheck(t, s, "big", "b-late", now.Add(3*time.Hour), false)
	mustCheck(t, s, "big", "b-mid", now.Add(2*time.Hour), false)
	mustCheck(t, s, "mid", "m1", now.Add(time.Hour), false)
	mustCheck(t, s, "small", "s", now.Add(time.Hour), false)
	if s.Evicted() != 1 {
		t.Errorf("want 1 eviction, got %d", s.Evicted())
	}

	// b-soon was the one evicted, so it reads as fresh again. Re-adding it
	// evicts another nonce from the now-largest scope.
	mustCheck(t, s, "big", "b-soon", now.Add(time.Hour), true)
}

// A sustained flood must not grow internal state past the capacity bound.
func TestMemoryNonceStoreBoundedUnderFlood(t *testing.T) {
	t.Parallel()

	const size = 64
	s, now := testNonceStore(size)
	until := now.Add(24 * time.Hour)

	for i := range 100 * size {
		mustCheck(t, s, fmt.Sprint("scope", i%7), fmt.Sprint(i), until, true)
	}

	expiry, queues := s.heapSizes()
	if expiry > 2*size+1 {
		t.Errorf("expiry heap grew to %d, bound is %d", expiry, 2*size+1)
	}
	if queues > 2*size {
		t.Errorf("scope queues grew to %d", queues)
	}
	if s.Len() != size {
		t.Errorf("want %d live nonces, got %d", size, s.Len())
	}
}

func TestMemoryNonceStoreManyScopes(t *testing.T) {
	t.Parallel()

	// Many distinct scopes, as from wildcard subdomains, must stay fast.
	s, now := testNonceStore(1 << 12)
	until := now.Add(time.Hour)

	start := time.Now()
	for i := range 200_000 {
		if _, err := s.CheckAndRecord(context.Background(), fmt.Sprint(i%100_000), fmt.Sprint(i), until); err != nil {
			t.Fatal(err)
		}
	}
	if took := time.Since(start); took > 5*time.Second {
		t.Errorf("200k inserts took %s", took)
	}
}

func TestMemoryNonceStoreConcurrent(t *testing.T) {
	t.Parallel()

	s := NewMemoryNonceStore(0)
	until := time.Now().Add(time.Hour)

	var (
		wg    sync.WaitGroup
		fresh atomic.Int64
	)
	for i := range 64 {
		wg.Go(func() {
			// Every goroutine races on the same 8 nonces.
			ok, err := s.CheckAndRecord(context.Background(), "agent", fmt.Sprint(i%8), until)
			if err != nil {
				t.Error(err)
			}
			if ok {
				fresh.Add(1)
			}
		})
	}
	wg.Wait()

	if got := fresh.Load(); got != 8 {
		t.Errorf("want exactly 8 fresh nonces, got %d", got)
	}
}
