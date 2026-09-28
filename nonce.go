package samesame

import (
	"container/heap"
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// DefaultNonceStoreSize is the default capacity of a MemoryNonceStore.
const DefaultNonceStoreSize = 1 << 16

// NonceStore records signature nonces to detect replays.
//
// CheckAndRecord must atomically check whether nonce has been seen in scope
// and, if not, record it until the given time. It returns true when the
// nonce is fresh. The verifier passes the agent's identifier, or its keyid
// for static keys, as scope, so one agent's nonces cannot collide with or
// crowd out another's.
//
// If CheckAndRecord returns an error, the verifier treats the signature as
// unverified: without nonce state it cannot say whether the request is a
// replay (protocol draft Appendix C.6).
type NonceStore interface {
	CheckAndRecord(ctx context.Context, scope, nonce string, until time.Time) (fresh bool, err error)
}

// MemoryNonceStore is an in-process NonceStore with a fixed capacity.
// Entries are forgotten once their signature expires.
//
// When the store is full, it evicts the soonest-expiring nonce of the scope
// holding the most entries instead of refusing new ones. A flood of signed
// requests, which anyone with their own key directory can produce, then
// weakens replay protection for the heaviest scope, usually the flooder,
// rather than making every agent unverifiable. Evicted reports how often
// this happens.
type MemoryNonceStore struct {
	mu      sync.Mutex
	max     int
	now     func() time.Time
	entries map[nonceKey]time.Time
	scopes  map[string]*nonceScope
	expiry  nonceHeap // every entry by expiry; stale items are skipped

	// byCount[n] is the set of scopes holding n entries, and maxCount is
	// the largest n with a non-empty set. Together they find the largest
	// scope in constant time.
	byCount  map[int]map[string]struct{}
	maxCount int

	evicted atomic.Uint64
}

type nonceKey struct{ scope, nonce string }

type nonceScope struct {
	count int
	queue nonceHeap // this scope's entries by expiry; stale items are skipped
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
		entries: make(map[nonceKey]time.Time),
		scopes:  make(map[string]*nonceScope),
		byCount: make(map[int]map[string]struct{}),
	}
}

func (s *MemoryNonceStore) CheckAndRecord(_ context.Context, scope, nonce string, until time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	s.expire(now)

	key := nonceKey{scope, nonce}
	if _, ok := s.entries[key]; ok {
		return false, nil
	}
	if !until.After(now) {
		// Already expired; the verifier rejects the signature anyway, and
		// there is nothing to remember.
		return true, nil
	}
	if len(s.entries) >= s.max {
		s.evictFromLargest()
	}

	s.add(key, until)
	return true, nil
}

// Len returns the number of nonces currently remembered.
func (s *MemoryNonceStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}

// Evicted returns how many unexpired nonces were dropped to make room.
func (s *MemoryNonceStore) Evicted() uint64 { return s.evicted.Load() }

func (s *MemoryNonceStore) add(key nonceKey, until time.Time) {
	s.entries[key] = until

	sc, ok := s.scopes[key.scope]
	if !ok {
		sc = &nonceScope{}
		s.scopes[key.scope] = sc
	}
	s.setCount(key.scope, sc.count, sc.count+1)
	sc.count++

	e := nonceEntry{key: key, until: until}
	heap.Push(&sc.queue, e)
	heap.Push(&s.expiry, e)

	// Evicted entries stay in the expiry heap until they expire. Under a
	// sustained flood that could be far more than max, so rebuild it from
	// the live entries now and then; the cost is amortized over max adds.
	if s.expiry.Len() > 2*s.max {
		s.expiry = s.expiry[:0]
		for k, u := range s.entries {
			s.expiry = append(s.expiry, nonceEntry{key: k, until: u})
		}
		heap.Init(&s.expiry)
	}
}

// heapSizes reports the expiry heap length and the total of all scope
// queue lengths, for tests.
func (s *MemoryNonceStore) heapSizes() (expiry, queues int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, sc := range s.scopes {
		queues += sc.queue.Len()
	}
	return s.expiry.Len(), queues
}

func (s *MemoryNonceStore) remove(key nonceKey) {
	delete(s.entries, key)

	sc := s.scopes[key.scope]
	s.setCount(key.scope, sc.count, sc.count-1)
	sc.count--
	if sc.count == 0 {
		delete(s.scopes, key.scope)
		return
	}
	s.dropStale(sc)
}

// live reports whether e still describes a stored entry.
func (s *MemoryNonceStore) live(e nonceEntry) bool {
	until, ok := s.entries[e.key]
	return ok && until.Equal(e.until)
}

// dropStale pops removed entries off the front of a scope's queue so the
// queue does not grow without bound.
func (s *MemoryNonceStore) dropStale(sc *nonceScope) {
	for sc.queue.Len() > 0 && !s.live(sc.queue[0]) {
		heap.Pop(&sc.queue)
	}
}

func (s *MemoryNonceStore) expire(now time.Time) {
	for s.expiry.Len() > 0 && !s.expiry[0].until.After(now) {
		e := heap.Pop(&s.expiry).(nonceEntry)
		if s.live(e) {
			s.remove(e.key)
		}
	}
}

func (s *MemoryNonceStore) evictFromLargest() {
	for scope := range s.byCount[s.maxCount] {
		sc := s.scopes[scope]
		s.dropStale(sc)
		e := heap.Pop(&sc.queue).(nonceEntry)
		s.remove(e.key)
		s.evicted.Add(1)
		return
	}
}

func (s *MemoryNonceStore) setCount(scope string, from, to int) {
	if from > 0 {
		delete(s.byCount[from], scope)
		if len(s.byCount[from]) == 0 {
			delete(s.byCount, from)
		}
	}
	if to > 0 {
		set, ok := s.byCount[to]
		if !ok {
			set = make(map[string]struct{})
			s.byCount[to] = set
		}
		set[scope] = struct{}{}
	}

	if to > s.maxCount {
		s.maxCount = to
	}
	for s.maxCount > 0 && len(s.byCount[s.maxCount]) == 0 {
		s.maxCount--
	}
}

type nonceEntry struct {
	key   nonceKey
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
