package samesame

import (
	"container/heap"
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// DefaultNonceStoreSize is the default capacity of a MemoryNonceStore.
const DefaultNonceStoreSize = 1 << 16

var ErrNonceStoreFull = errors.New("samesame: nonce store is full")

// NonceStore records signature nonces to detect replays.
//
// CheckAndRecord must atomically check whether nonce has been seen and, if
// not, record it until the given time. It returns true when the nonce is
// fresh. If it returns an error, the verifier treats the signature as
// unverified: without nonce state it cannot say whether the request is a
// replay (protocol draft Appendix C.6).
type NonceStore interface {
	CheckAndRecord(ctx context.Context, nonce string, until time.Time) (fresh bool, err error)
}

// MemoryNonceStore is an in-process NonceStore with a fixed capacity. Entries
// are forgotten once their signature expires. When the store is full of
// unexpired entries it refuses new ones instead of evicting live nonces,
// because evicting them would let those nonces be replayed.
type MemoryNonceStore struct {
	mu      sync.Mutex
	max     int
	now     func() time.Time
	entries map[string]time.Time
	byTime  nonceHeap
}

// NewMemoryNonceStore creates a MemoryNonceStore holding at most size
// nonces. A size of zero or less means DefaultNonceStoreSize.
func NewMemoryNonceStore(size int) *MemoryNonceStore {
	if size <= 0 {
		size = DefaultNonceStoreSize
	}
	return &MemoryNonceStore{
		max:     size,
		now:     time.Now,
		entries: make(map[string]time.Time),
	}
}

func (s *MemoryNonceStore) CheckAndRecord(_ context.Context, nonce string, until time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	s.expire(now)

	if _, ok := s.entries[nonce]; ok {
		return false, nil
	}
	if !until.After(now) {
		// Already expired; the verifier rejects the signature anyway, and
		// there is nothing to remember.
		return true, nil
	}
	if len(s.entries) >= s.max {
		return false, fmt.Errorf("%w: %d live nonces", ErrNonceStoreFull, len(s.entries))
	}

	s.entries[nonce] = until
	heap.Push(&s.byTime, nonceEntry{nonce: nonce, until: until})
	return true, nil
}

// Len returns the number of nonces currently remembered.
func (s *MemoryNonceStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}

func (s *MemoryNonceStore) expire(now time.Time) {
	for s.byTime.Len() > 0 && !s.byTime[0].until.After(now) {
		e := heap.Pop(&s.byTime).(nonceEntry)
		delete(s.entries, e.nonce)
	}
}

type nonceEntry struct {
	nonce string
	until time.Time
}

type nonceHeap []nonceEntry

func (h nonceHeap) Len() int           { return len(h) }
func (h nonceHeap) Less(i, j int) bool { return h[i].until.Before(h[j].until) }
func (h nonceHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *nonceHeap) Push(x any)        { *h = append(*h, x.(nonceEntry)) }
func (h *nonceHeap) Pop() any {
	old := *h
	e := old[len(old)-1]
	*h = old[:len(old)-1]
	return e
}
