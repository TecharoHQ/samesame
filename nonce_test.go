package samesame

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestMemoryNonceStore(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Unix(1_000_000, 0)
	s := NewMemoryNonceStore(2)
	s.now = func() time.Time { return now }

	check := func(nonce string, until time.Time, wantFresh bool, wantErr error) {
		t.Helper()
		fresh, err := s.CheckAndRecord(ctx, nonce, until)
		if !errors.Is(err, wantErr) {
			t.Fatalf("%s: want error %v, got %v", nonce, wantErr, err)
		}
		if fresh != wantFresh {
			t.Fatalf("%s: want fresh=%v, got %v", nonce, wantFresh, fresh)
		}
	}

	check("a", now.Add(time.Minute), true, nil)
	check("a", now.Add(time.Minute), false, nil)
	check("b", now.Add(2*time.Minute), true, nil)

	// Full of live nonces: refuse rather than evict.
	check("c", now.Add(time.Minute), false, ErrNonceStoreFull)

	// An already-expired signature has nothing to remember.
	check("d", now, true, nil)
	if s.Len() != 2 {
		t.Fatalf("want 2 nonces, got %d", s.Len())
	}

	// Once a expires, its slot frees up and it may be seen again.
	now = now.Add(time.Minute)
	check("c", now.Add(time.Minute), true, nil)
	check("a", now.Add(time.Minute), false, ErrNonceStoreFull)
	check("b", now.Add(time.Minute), false, nil)

	now = now.Add(time.Hour)
	if _, err := s.CheckAndRecord(ctx, "e", now.Add(time.Second)); err != nil {
		t.Fatalf("after expiry: %v", err)
	}
	if s.Len() != 1 {
		t.Fatalf("want 1 nonce after expiry, got %d", s.Len())
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
			ok, err := s.CheckAndRecord(context.Background(), fmt.Sprint(i%8), until)
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
