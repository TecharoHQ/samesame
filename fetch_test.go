package samesame

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// testDirectoryServer serves a switchable handler over TLS and counts
// requests.
type testDirectoryServer struct {
	srv      *httptest.Server
	hits     atomic.Int64
	mu       sync.Mutex
	handler  http.Handler
	lastReqs []*http.Request
}

func newTestDirectoryServer(t *testing.T, h http.Handler) *testDirectoryServer {
	t.Helper()

	s := &testDirectoryServer{handler: h}
	s.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.hits.Add(1)
		s.mu.Lock()
		h := s.handler
		s.lastReqs = append(s.lastReqs, r.Clone(r.Context()))
		s.mu.Unlock()
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *testDirectoryServer) set(h http.Handler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.handler = h
}

func (s *testDirectoryServer) lastRequest() *http.Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastReqs[len(s.lastReqs)-1]
}

func (s *testDirectoryServer) identifier(t *testing.T) *url.URL {
	t.Helper()
	u, err := url.Parse(s.srv.URL + WellKnownPath)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// fetcherFor returns a Fetcher that trusts srv's certificate and may dial
// loopback, with a controllable clock.
func fetcherFor(t *testing.T, srv *testDirectoryServer, opts FetcherOptions, now *atomic.Pointer[time.Time]) *Fetcher {
	t.Helper()

	pool := x509.NewCertPool()
	pool.AddCert(srv.srv.Certificate())
	opts.TLSConfig = &tls.Config{RootCAs: pool}
	opts.AllowPrivateAddresses = true
	if now != nil {
		opts.Now = func() time.Time { return *now.Load() }
	}
	return NewFetcher(opts)
}

// mustDirectoryHandler returns a directory handler for keys. Test servers
// get random ports, so it builds a real NewDirectoryHandler for each
// request's authority on first use, with Authorities set to exactly that
// host.
func mustDirectoryHandler(t *testing.T, keys ...crypto.Signer) http.Handler {
	t.Helper()

	// Fail fast on bad keys.
	if _, err := NewDirectoryHandler(keys, DirectoryHandlerOptions{Authorities: []string{"check.test"}}); err != nil {
		t.Fatalf("NewDirectoryHandler: %v", err)
	}

	var (
		mu       sync.Mutex
		handlers = map[string]http.Handler{}
	)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		h, ok := handlers[r.Host]
		if !ok {
			var err error
			h, err = NewDirectoryHandler(keys, DirectoryHandlerOptions{Authorities: []string{r.Host}})
			if err != nil {
				mu.Unlock()
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			handlers[r.Host] = h
		}
		mu.Unlock()
		h.ServeHTTP(w, r)
	})
}

func status(code int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(code)
	})
}

func TestFetcherCaching(t *testing.T) {
	t.Parallel()

	key, next := mustGenerate(t, "ed25519"), mustGenerate(t, "ed25519")
	keyID, nextID := mustThumbprint(t, key.Public()), mustThumbprint(t, next.Public())

	srv := newTestDirectoryServer(t, mustDirectoryHandler(t, key))
	var now atomic.Pointer[time.Time]
	start := time.Now()
	now.Store(&start)
	advance := func(d time.Duration) {
		n := now.Load().Add(d)
		now.Store(&n)
	}

	f := fetcherFor(t, srv, FetcherOptions{}, &now)
	id := srv.identifier(t)
	ctx := context.Background()

	resolveHas := func(wantID string) {
		t.Helper()
		dir, err := f.Resolve(ctx, id)
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if _, ok := dir.Key(wantID, *now.Load()); !ok {
			t.Fatalf("directory does not have %s: %+v", wantID, dir.Keys)
		}
	}
	wantHits := func(n int64) {
		t.Helper()
		if got := srv.hits.Load(); got != n {
			t.Fatalf("want %d fetches, got %d", n, got)
		}
	}

	resolveHas(keyID)
	wantHits(1)

	// Fresh for max-age=3600: no refetch.
	advance(30 * time.Minute)
	resolveHas(keyID)
	wantHits(1)

	// Stale: revalidated with If-None-Match and a 304.
	advance(time.Hour)
	resolveHas(keyID)
	wantHits(2)
	if srv.lastRequest().Header.Get("If-None-Match") == "" {
		t.Error("revalidation did not send If-None-Match")
	}

	// Stale and the server is down: the cached directory is kept
	// (Section 6.10), and the failure is not retried immediately.
	advance(2 * time.Hour)
	srv.set(status(http.StatusServiceUnavailable))
	resolveHas(keyID)
	wantHits(3)
	resolveHas(keyID)
	wantHits(3)

	// Back up with a rotated directory: the new one replaces the old,
	// even though it drops the old key.
	advance(MaxNegativeTTL + time.Second)
	srv.set(mustDirectoryHandler(t, next))
	resolveHas(nextID)
	wantHits(4)
	dir, _ := f.Resolve(ctx, id)
	if _, ok := dir.Key(keyID, *now.Load()); ok {
		t.Error("rotated-out key is still served")
	}
}

func TestFetcherNegativeCache(t *testing.T) {
	t.Parallel()

	srv := newTestDirectoryServer(t, status(http.StatusInternalServerError))
	var now atomic.Pointer[time.Time]
	start := time.Now()
	now.Store(&start)

	f := fetcherFor(t, srv, FetcherOptions{NegativeTTL: 10 * time.Second}, &now)
	id := srv.identifier(t)

	for range 3 {
		if _, err := f.Resolve(context.Background(), id); !errors.Is(err, ErrFetchFailed) {
			t.Fatalf("want %v, got %v", ErrFetchFailed, err)
		}
	}
	if got := srv.hits.Load(); got != 1 {
		t.Fatalf("failure was not negatively cached: %d fetches", got)
	}

	later := start.Add(MaxNegativeTTL + time.Second)
	now.Store(&later)
	srv.set(mustDirectoryHandler(t, mustGenerate(t, "ed25519")))
	if _, err := f.Resolve(context.Background(), id); err != nil {
		t.Fatalf("after backoff: %v", err)
	}
}

func TestFetcherFailures(t *testing.T) {
	t.Parallel()

	key := mustGenerate(t, "ed25519")
	good := mustDirectoryHandler(t, key)

	for _, tt := range []struct {
		name    string
		handler http.Handler
		opts    FetcherOptions
		err     error
	}{
		{
			name: "redirect is not followed",
			handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == WellKnownPath {
					http.Redirect(w, r, "/elsewhere", http.StatusFound)
					return
				}
				good.ServeHTTP(w, r)
			}),
			err: ErrFetchFailed,
		},
		{
			name:    "not found",
			handler: status(http.StatusNotFound),
			err:     ErrFetchFailed,
		},
		{
			name: "wrong content type",
			handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				io.WriteString(w, `{"keys":[]}`)
			}),
			err: ErrNotADirectory,
		},
		{
			name:    "too large",
			handler: good,
			opts:    FetcherOptions{MaxBodySize: 10},
			err:     ErrDirectoryTooBig,
		},
		{
			name: "malformed directory",
			handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", MediaTypeDirectory)
				io.WriteString(w, `{"keys":`)
			}),
			err: ErrMalformedDirectory,
		},
		{
			name: "too slow",
			handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				select {
				case <-time.After(2 * time.Second):
				case <-r.Context().Done():
				}
			}),
			opts: FetcherOptions{Timeout: 100 * time.Millisecond},
			err:  ErrFetchFailed,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			srv := newTestDirectoryServer(t, tt.handler)
			f := fetcherFor(t, srv, tt.opts, nil)

			_, err := f.Resolve(context.Background(), srv.identifier(t))
			if !errors.Is(err, tt.err) {
				t.Logf("want: %v", tt.err)
				t.Logf("got:  %v", err)
				t.Error("got wrong error")
			}
		})
	}
}

func TestFetcherRefusals(t *testing.T) {
	t.Parallel()

	srv := newTestDirectoryServer(t, mustDirectoryHandler(t, mustGenerate(t, "ed25519")))
	pool := x509.NewCertPool()
	pool.AddCert(srv.srv.Certificate())

	for _, tt := range []struct {
		name string
		opts FetcherOptions
		id   string
		err  error
	}{
		{
			// httptest listens on loopback, which the default dialer
			// refuses (Section 6.7).
			name: "loopback blocked by default",
			opts: FetcherOptions{TLSConfig: &tls.Config{RootCAs: pool}},
			id:   srv.srv.URL + WellKnownPath,
			err:  ErrBlockedAddress,
		},
		{
			name: "plain http",
			opts: FetcherOptions{AllowPrivateAddresses: true},
			id:   "http://bot.test" + WellKnownPath,
			err:  ErrFetchRefused,
		},
		{
			name: "host not in allow-list",
			opts: FetcherOptions{AllowPrivateAddresses: true, AllowedHosts: []string{"bot.test"}},
			id:   srv.srv.URL + WellKnownPath,
			err:  ErrFetchRefused,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			u, err := url.Parse(tt.id)
			if err != nil {
				t.Fatal(err)
			}
			_, err = NewFetcher(tt.opts).Resolve(context.Background(), u)
			if !errors.Is(err, tt.err) {
				t.Logf("want: %v", tt.err)
				t.Logf("got:  %v", err)
				t.Error("got wrong error")
			}
		})
	}
}

func TestFetcherVerifyDirectorySignatures(t *testing.T) {
	t.Parallel()

	key := mustGenerate(t, "ed25519")
	keyID := mustThumbprint(t, key.Public())
	good := mustDirectoryHandler(t, key)

	for _, tt := range []struct {
		name     string
		handler  http.Handler
		wantKeys int
	}{
		{name: "signed by the handler", handler: good, wantKeys: 1},
		{
			name: "signatures stripped",
			handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				rec := httptest.NewRecorder()
				good.ServeHTTP(rec, r)
				for k, v := range rec.Header() {
					if k != "Signature" && k != "Signature-Input" {
						w.Header()[k] = v
					}
				}
				w.Write(rec.Body.Bytes())
			}),
		},
		{
			name: "body changed after signing",
			handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				rec := httptest.NewRecorder()
				good.ServeHTTP(rec, r)
				maps.Copy(w.Header(), rec.Header())
				w.Header().Del("Content-Length")
				w.Write([]byte(strings.Replace(rec.Body.String(), `"keys":[`, `"keys":[`+`{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"},`, 1)))
			}),
		},
		{
			name: "signed by another key",
			handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Serve key's directory with signatures made by a
				// different key that claims key's keyid.
				rec := httptest.NewRecorder()
				good.ServeHTTP(rec, r)
				forged := httptest.NewRecorder()
				mustDirectoryHandler(t, mustGenerate(t, "ed25519")).ServeHTTP(forged, r)
				maps.Copy(w.Header(), rec.Header())
				w.Header()["Signature"] = forged.Header()["Signature"]
				w.Write(rec.Body.Bytes())
			}),
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			srv := newTestDirectoryServer(t, tt.handler)
			f := fetcherFor(t, srv, FetcherOptions{VerifyDirectorySignatures: true}, nil)

			dir, err := f.Resolve(context.Background(), srv.identifier(t))
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			if len(dir.Keys) != tt.wantKeys {
				t.Fatalf("want %d keys, got %d: %v", tt.wantKeys, len(dir.Keys), dir.Invalid)
			}
			if tt.wantKeys == 0 && !errors.Is(errors.Join(dir.Invalid...), ErrDirectoryUnbound) {
				t.Errorf("dropped key not reported as unbound: %v", dir.Invalid)
			}
			if tt.wantKeys == 1 && dir.Keys[0].ID != keyID {
				t.Errorf("wrong key %s", dir.Keys[0].ID)
			}
		})
	}
}

// Appendix B.1: a directory response signature created in the future MUST
// be rejected. httpsign cannot sign with a future created, so the signature
// base is built by hand.
func TestDirectorySignatureCreatedInFuture(t *testing.T) {
	t.Parallel()

	_, priv := loadEd25519(t)
	const (
		body   = `{"keys":[` + testEd25519JWK + `]}`
		digest = "sha-256=:CADMT2aBdV/rqQr/NIru64ERQkCobVvllA4V0fLFDu0=:"
	)
	now := time.Now()

	for _, tt := range []struct {
		name     string
		created  time.Time
		wantKeys int
	}{
		{name: "created in the past", created: now.Add(-time.Hour), wantKeys: 1},
		{name: "created in the future", created: now.Add(time.Hour), wantKeys: 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			params := fmt.Sprintf(`("@authority";req "content-digest");created=%d;expires=%d;keyid="%s";tag="%s"`,
				tt.created.Unix(), now.Add(48*time.Hour).Unix(), testEd25519KeyID, TagDirectory)
			base := "\"@authority\";req: signature-agent.test\n" +
				"\"content-digest\": " + digest + "\n" +
				"\"@signature-params\": " + params
			sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(base)))

			req := httptest.NewRequest(http.MethodGet, "https://signature-agent.test"+WellKnownPath, nil)
			resp := &http.Response{
				StatusCode: http.StatusOK,
				Header: http.Header{
					"Content-Type":    {MediaTypeDirectory},
					"Content-Digest":  {digest},
					"Signature-Input": {"binding=" + params},
					"Signature":       {"binding=:" + sig + ":"},
				},
				Body:    io.NopCloser(strings.NewReader(body)),
				Request: req,
			}

			dir, err := ParseDirectory([]byte(body), DirectoryOptions{AllowTestKeys: true})
			if err != nil {
				t.Fatalf("ParseDirectory: %v", err)
			}

			NewFetcher(FetcherOptions{}).dropUnboundKeys(dir, resp, req, []byte(body))
			if len(dir.Keys) != tt.wantKeys {
				t.Errorf("want %d keys, got %d: %v", tt.wantKeys, len(dir.Keys), dir.Invalid)
			}
		})
	}
}

func TestFetcherCoalescesConcurrentFetches(t *testing.T) {
	t.Parallel()

	good := mustDirectoryHandler(t, mustGenerate(t, "ed25519"))
	release := make(chan struct{})
	srv := newTestDirectoryServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
		good.ServeHTTP(w, r)
	}))
	f := fetcherFor(t, srv, FetcherOptions{}, nil)
	id := srv.identifier(t)

	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			if _, err := f.Resolve(context.Background(), id); err != nil {
				t.Error(err)
			}
		})
	}
	time.Sleep(100 * time.Millisecond)
	close(release)
	wg.Wait()

	if got := srv.hits.Load(); got != 1 {
		t.Errorf("want 1 fetch, got %d", got)
	}
}

func TestFetcherTTL(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
	f := NewFetcher(FetcherOptions{Now: func() time.Time { return now }})

	for _, tt := range []struct {
		name   string
		header http.Header
		want   time.Duration
	}{
		{name: "no caching headers", header: http.Header{}, want: DefaultTTL},
		{name: "max-age", header: http.Header{"Cache-Control": {"public, max-age=7200"}}, want: 2 * time.Hour},
		{name: "max-age below floor", header: http.Header{"Cache-Control": {"max-age=1"}}, want: DefaultMinTTL},
		{name: "max-age above ceiling", header: http.Header{"Cache-Control": {"max-age=99999999999"}}, want: DefaultMaxTTL},
		{name: "no-store", header: http.Header{"Cache-Control": {"no-store"}}, want: DefaultMinTTL},
		{
			name: "expires",
			header: http.Header{
				"Date":    {now.Format(http.TimeFormat)},
				"Expires": {now.Add(3 * time.Hour).Format(http.TimeFormat)},
			},
			want: 3 * time.Hour,
		},
		{name: "invalid expires", header: http.Header{"Expires": {"0"}}, want: DefaultMinTTL},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := f.ttl(tt.header); got != tt.want {
				t.Errorf("want %s, got %s", tt.want, got)
			}
		})
	}
}

func TestFetcherBackoff(t *testing.T) {
	t.Parallel()

	f := NewFetcher(FetcherOptions{NegativeTTL: 10 * time.Second})

	for failures := 1; failures <= 20; failures++ {
		d := f.backoff(failures, 0)
		if d <= 0 || d > MaxNegativeTTL {
			t.Errorf("failure %d: backoff %s out of (0, %s]", failures, d, MaxNegativeTTL)
		}
	}
	if d := f.backoff(1, 2*time.Minute); d != 2*time.Minute {
		t.Errorf("Retry-After not honored: %s", d)
	}
	if d := f.backoff(1, time.Hour); d != MaxNegativeTTL {
		t.Errorf("Retry-After not capped: %s", d)
	}
}

func TestCheckPublicAddress(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		address string
		allowed bool
	}{
		{"93.184.216.34:443", true},
		{"[2606:2800:220:1:248:1893:25c8:1946]:443", true},
		{"127.0.0.1:443", false},
		{"[::1]:443", false},
		{"10.1.2.3:443", false},
		{"172.16.0.1:443", false},
		{"192.168.1.1:443", false},
		{"169.254.169.254:80", false},
		{"100.64.0.1:443", false},
		{"0.0.0.0:443", false},
		{"[fd00::1]:443", false},
		{"[fe80::1]:443", false},
		{"[::ffff:127.0.0.1]:443", false},
		{"[64:ff9b::a00:1]:443", false},
		{"[2002:a00:1::]:443", false},
		{"224.0.0.1:443", false},
		{"not-an-ip:443", false},
	} {
		t.Run(tt.address, func(t *testing.T) {
			t.Parallel()

			err := checkPublicAddress(tt.address)
			if (err == nil) != tt.allowed {
				t.Errorf("want allowed=%v, got %v", tt.allowed, err)
			}
		})
	}
}

func TestFetcherCallerCancellation(t *testing.T) {
	t.Parallel()

	good := mustDirectoryHandler(t, mustGenerate(t, "ed25519"))
	release := make(chan struct{})
	srv := newTestDirectoryServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
		good.ServeHTTP(w, r)
	}))
	f := fetcherFor(t, srv, FetcherOptions{}, nil)
	id := srv.identifier(t)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	if _, err := f.Resolve(ctx, id); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want %v, got %v", context.DeadlineExceeded, err)
	}
	if waited := time.Since(start); waited > time.Second {
		t.Errorf("cancelled caller waited %s for the fetch", waited)
	}

	// The shared fetch keeps going and fills the cache.
	close(release)
	deadline := time.Now().Add(5 * time.Second)
	for {
		dir, err := f.Resolve(context.Background(), id)
		if err == nil && len(dir.Keys) == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("background fetch never completed: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := srv.hits.Load(); got != 1 {
		t.Errorf("want 1 fetch, got %d", got)
	}
}

func TestFetcherConcurrencyLimit(t *testing.T) {
	t.Parallel()

	good := mustDirectoryHandler(t, mustGenerate(t, "ed25519"))
	release := make(chan struct{})
	slow := newTestDirectoryServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
		good.ServeHTTP(w, r)
	}))
	fast := newTestDirectoryServer(t, good)
	defer close(release)

	pool := x509.NewCertPool()
	pool.AddCert(slow.srv.Certificate())
	pool.AddCert(fast.srv.Certificate())
	f := NewFetcher(FetcherOptions{
		TLSConfig:             &tls.Config{RootCAs: pool},
		AllowPrivateAddresses: true,
		MaxConcurrentFetches:  1,
	})

	go f.Resolve(context.Background(), slow.identifier(t))
	for slow.hits.Load() == 0 {
		time.Sleep(5 * time.Millisecond)
	}

	// The only slot is taken, so another origin's fetch must wait.
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := f.Resolve(ctx, fast.identifier(t)); err == nil {
		t.Fatal("fetch ran while the only slot was taken")
	}
	if got := fast.hits.Load(); got != 0 {
		t.Errorf("want 0 fetches of the second origin, got %d", got)
	}
}

// Directory signature expiry must use the Fetcher's clock, not the wall
// clock.
func TestFetcherDirectorySignatureExpiryUsesClock(t *testing.T) {
	t.Parallel()

	key := mustGenerate(t, "ed25519")
	srv := newTestDirectoryServer(t, mustDirectoryHandler(t, key))

	for _, tt := range []struct {
		name     string
		offset   time.Duration
		wantKeys int
	}{
		{name: "now", offset: 0, wantKeys: 1},
		{name: "after the signatures expire", offset: DefaultDirectorySignatureLifetime + time.Hour, wantKeys: 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var now atomic.Pointer[time.Time]
			n := time.Now().Add(tt.offset)
			now.Store(&n)

			f := fetcherFor(t, srv, FetcherOptions{VerifyDirectorySignatures: true}, &now)
			dir, err := f.Resolve(context.Background(), srv.identifier(t))
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			if len(dir.Keys) != tt.wantKeys {
				t.Errorf("want %d keys, got %d: %v", tt.wantKeys, len(dir.Keys), dir.Invalid)
			}
		})
	}
}

// A directory at the default key limit, all RSA, has more than 16 KiB of
// signature headers.
func TestFetcherLargeSignedDirectory(t *testing.T) {
	t.Parallel()

	keys := make([]crypto.Signer, DefaultMaxKeys)
	var wg sync.WaitGroup
	for i := range keys {
		wg.Go(func() { keys[i] = mustGenerate(t, "rsa") })
	}
	wg.Wait()

	srv := newTestDirectoryServer(t, mustDirectoryHandler(t, keys...))
	f := fetcherFor(t, srv, FetcherOptions{VerifyDirectorySignatures: true}, nil)

	dir, err := f.Resolve(context.Background(), srv.identifier(t))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(dir.Keys) != len(keys) {
		t.Errorf("want %d keys, got %d: %v", len(keys), len(dir.Keys), dir.Invalid)
	}
}
