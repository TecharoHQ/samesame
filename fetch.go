package samesame

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/yaronf/httpsign"
	"golang.org/x/sync/singleflight"
)

// Fetcher defaults.
const (
	DefaultFetchTimeout         = 5 * time.Second
	DefaultMaxDirectorySize     = 64 << 10
	DefaultMinTTL               = time.Minute
	DefaultMaxTTL               = 24 * time.Hour
	DefaultTTL                  = time.Hour
	DefaultNegativeTTL          = 30 * time.Second
	DefaultMaxCacheEntries      = 10_000
	DefaultMaxConcurrentFetches = 64

	// MaxNegativeTTL bounds how long a failed fetch is remembered (protocol
	// draft Appendix C.5).
	MaxNegativeTTL = 5 * time.Minute
)

var (
	ErrFetchRefused     = errors.New("samesame: directory fetch refused")
	ErrFetchFailed      = errors.New("samesame: directory fetch failed")
	ErrNotADirectory    = errors.New("samesame: response is not a key directory")
	ErrDirectoryTooBig  = errors.New("samesame: key directory too large")
	ErrBlockedAddress   = errors.New("samesame: address is not publicly routable")
	ErrDirectoryUnbound = errors.New("samesame: directory key has no valid response signature")
)

// FetcherOptions configures a Fetcher.
type FetcherOptions struct {
	// Directory controls how fetched directories are parsed.
	Directory DirectoryOptions

	// Timeout bounds each fetch, including reading the body. Defaults to
	// DefaultFetchTimeout.
	Timeout time.Duration

	// MaxBodySize caps the directory size after content decoding. Defaults
	// to DefaultMaxDirectorySize.
	MaxBodySize int64

	// MinTTL and MaxTTL clamp how long a fetched directory is cached. TTL
	// is used when the response has no caching headers.
	MinTTL, MaxTTL, TTL time.Duration

	// NegativeTTL is the base backoff after a failed fetch. It grows
	// exponentially with consecutive failures, is raised to any
	// Retry-After, and never exceeds MaxNegativeTTL.
	NegativeTTL time.Duration

	// MaxCacheEntries caps the number of cached directories. Defaults to
	// DefaultMaxCacheEntries.
	MaxCacheEntries int

	// MaxConcurrentFetches caps fetches in flight across all origins.
	// Fetches of the same identifier are coalesced, and a directory
	// identifier is one per origin, so each origin already has at most one
	// fetch in flight (protocol draft Appendix C.3). Defaults to
	// DefaultMaxConcurrentFetches.
	MaxConcurrentFetches int

	// ClockSkew is the tolerance for directory response signature times.
	// Defaults to DefaultClockSkew.
	ClockSkew time.Duration

	// AllowedHosts, when set, is the only set of hosts (as in URL.Host)
	// that may be fetched.
	AllowedHosts []string

	// AllowPrivateAddresses permits fetching from loopback, private,
	// link-local, and other non-public addresses. Only tests should set it.
	AllowPrivateAddresses bool

	// TLSConfig is used for fetches, for example to trust a test CA.
	TLSConfig *tls.Config

	// DirectorySignatures decides what to do with directory response
	// signatures (protocol draft Appendix B.1). Defaults to
	// DirectorySignaturesPrefer.
	DirectorySignatures DirectorySignaturePolicy

	// Deprecated: set DirectorySignatures to DirectorySignaturesRequire.
	// When true, it overrides DirectorySignatures.
	VerifyDirectorySignatures bool

	// Now returns the current time. Defaults to time.Now.
	Now func() time.Time
}

// DirectorySignaturePolicy decides which directory keys need a valid
// directory response signature (protocol draft Appendix B.1). A key that
// needs one and lacks it is moved to Directory.Invalid with
// ErrDirectoryUnbound.
type DirectorySignaturePolicy int

const (
	// DirectorySignaturesPrefer accepts an unsigned directory, because the
	// draft only recommends signing and lets verifiers use directly
	// resolved keys without proof. A directory with any
	// http-message-signatures-directory signature is held to its claim:
	// every key must then carry a valid signature, and Content-Digest must
	// match the body.
	DirectorySignaturesPrefer DirectorySignaturePolicy = iota

	// DirectorySignaturesRequire keeps only keys with a valid signature.
	// Keys from unsigned directories are dropped.
	DirectorySignaturesRequire

	// DirectorySignaturesIgnore does not check signatures.
	DirectorySignaturesIgnore
)

func (p DirectorySignaturePolicy) String() string {
	switch p {
	case DirectorySignaturesPrefer:
		return "prefer"
	case DirectorySignaturesRequire:
		return "require"
	case DirectorySignaturesIgnore:
		return "ignore"
	default:
		return "DirectorySignaturePolicy(" + strconv.Itoa(int(p)) + ")"
	}
}

// Fetcher resolves Signature-Agent identifiers to key directories over
// HTTPS, with caching. It implements KeyResolver.
type Fetcher struct {
	opts   FetcherOptions
	client *http.Client
	group  singleflight.Group

	mu    sync.Mutex
	cache map[string]*cacheEntry
	slots chan struct{}
}

type cacheEntry struct {
	dir          *Directory
	etag         string
	lastModified string
	freshUntil   time.Time

	failures    int
	retryAfter  time.Time // no fetch before this time
	lastFailure error
}

// NewFetcher creates a Fetcher.
func NewFetcher(opts FetcherOptions) *Fetcher {
	if opts.Timeout <= 0 {
		opts.Timeout = DefaultFetchTimeout
	}
	if opts.MaxBodySize <= 0 {
		opts.MaxBodySize = DefaultMaxDirectorySize
	}
	if opts.MinTTL <= 0 {
		opts.MinTTL = DefaultMinTTL
	}
	if opts.MaxTTL <= 0 {
		opts.MaxTTL = DefaultMaxTTL
	}
	if opts.TTL <= 0 {
		opts.TTL = DefaultTTL
	}
	if opts.NegativeTTL <= 0 {
		opts.NegativeTTL = DefaultNegativeTTL
	}
	opts.NegativeTTL = min(opts.NegativeTTL, MaxNegativeTTL)
	if opts.MaxCacheEntries <= 0 {
		opts.MaxCacheEntries = DefaultMaxCacheEntries
	}
	if opts.MaxConcurrentFetches <= 0 {
		opts.MaxConcurrentFetches = DefaultMaxConcurrentFetches
	}
	if opts.ClockSkew <= 0 {
		opts.ClockSkew = DefaultClockSkew
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.VerifyDirectorySignatures {
		opts.DirectorySignatures = DirectorySignaturesRequire
	}

	dialer := &net.Dialer{Timeout: opts.Timeout}
	if !opts.AllowPrivateAddresses {
		// Check the address actually dialed, after DNS resolution, so a
		// hostname cannot rebind to an internal address (Section 6.7).
		dialer.Control = func(_, address string, _ syscall.RawConn) error {
			return checkPublicAddress(address)
		}
	}

	transport := &http.Transport{
		// No proxy: the dialer would then check the proxy's address, not
		// the directory's.
		Proxy:                 nil,
		DialContext:           dialer.DialContext,
		TLSClientConfig:       opts.TLSConfig,
		TLSHandshakeTimeout:   opts.Timeout,
		ResponseHeaderTimeout: opts.Timeout,
		// Signed directories carry one Signature and Signature-Input
		// per key, which for many RSA keys exceeds 16 KiB.
		MaxResponseHeaderBytes: 64 << 10,
		ForceAttemptHTTP2:      true,
		IdleConnTimeout:        90 * time.Second,
	}

	return &Fetcher{
		opts: opts,
		client: &http.Client{
			Transport: transport,
			Timeout:   opts.Timeout,
			// Section 5.5: verifiers MUST NOT follow redirects.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		cache: make(map[string]*cacheEntry),
		slots: make(chan struct{}, opts.MaxConcurrentFetches),
	}
}

// Resolve returns the key directory at identifier, from cache when fresh.
//
// A failed fetch never evicts a cached directory (protocol draft Section
// 6.10): the last good directory keeps being returned until a fetch
// succeeds. A successful fetch always replaces it, even if keys disappear.
func (f *Fetcher) Resolve(ctx context.Context, identifier *url.URL) (*Directory, error) {
	if identifier.Scheme != "https" {
		return nil, fmt.Errorf("%w: %s is not https", ErrFetchRefused, identifier)
	}
	if len(f.opts.AllowedHosts) != 0 && !slices.Contains(f.opts.AllowedHosts, identifier.Host) {
		return nil, fmt.Errorf("%w: host %s is not allowed", ErrFetchRefused, identifier.Host)
	}

	key := identifier.String()
	now := f.opts.Now()

	f.mu.Lock()
	e := f.cache[key]
	switch {
	case e != nil && e.dir != nil && now.Before(e.freshUntil):
		f.mu.Unlock()
		return e.dir, nil
	case e != nil && now.Before(e.retryAfter):
		dir, err := e.dir, e.lastFailure
		f.mu.Unlock()
		if dir != nil {
			return dir, nil
		}
		return nil, err
	}
	f.mu.Unlock()

	// Detach from the caller's cancellation: other callers may be waiting
	// on this fetch. f.opts.Timeout still bounds it.
	ch := f.group.DoChan(key, func() (any, error) {
		return f.refresh(context.WithoutCancel(ctx), identifier)
	})
	select {
	case res := <-ch:
		if res.Err != nil {
			return nil, res.Err
		}
		return res.Val.(*Directory), nil
	case <-ctx.Done():
		// The fetch keeps running for other callers and fills the cache.
		return nil, fmt.Errorf("%w: %w", ErrFetchFailed, ctx.Err())
	}
}

// refresh fetches identifier and updates the cache. It returns the cached
// directory when the fetch fails and one exists.
func (f *Fetcher) refresh(ctx context.Context, identifier *url.URL) (*Directory, error) {
	key := identifier.String()

	f.mu.Lock()
	prev := f.cache[key]
	var etag, lastModified string
	if prev != nil && prev.dir != nil {
		etag, lastModified = prev.etag, prev.lastModified
	}
	f.mu.Unlock()

	res, err := f.fetch(ctx, identifier, etag, lastModified)

	f.mu.Lock()
	defer f.mu.Unlock()

	now := f.opts.Now()
	e := f.cache[key]
	if e == nil {
		f.evictLocked(now)
		e = &cacheEntry{}
		f.cache[key] = e
	}

	if err == nil && res.notModified && e.dir == nil {
		// The entry was evicted while the conditional request was in
		// flight, so there is nothing to revalidate.
		err = fmt.Errorf("%w: %s: 304 without a cached directory", ErrFetchFailed, identifier)
	}

	if err != nil {
		e.failures++
		e.lastFailure = err
		e.retryAfter = now.Add(f.backoff(e.failures, res.retryAfter))
		if e.dir != nil {
			return e.dir, nil
		}
		return nil, err
	}

	if !res.notModified {
		e.dir = res.dir
		e.etag = res.etag
		e.lastModified = res.lastModified
	}
	e.freshUntil = now.Add(res.ttl)
	e.failures = 0
	e.retryAfter = time.Time{}
	e.lastFailure = nil

	return e.dir, nil
}

// backoff returns how long to wait after the nth consecutive failure:
// exponential from NegativeTTL with jitter, raised to retryAfter, capped at
// MaxNegativeTTL.
func (f *Fetcher) backoff(failures int, retryAfter time.Duration) time.Duration {
	d := f.opts.NegativeTTL << min(failures-1, 10)
	d = d/2 + rand.N(d/2+1)
	d = max(d, retryAfter)
	return min(d, MaxNegativeTTL)
}

// evictLocked makes room for a new cache entry, preferring entries that
// are stale and not backing off.
func (f *Fetcher) evictLocked(now time.Time) {
	if len(f.cache) < f.opts.MaxCacheEntries {
		return
	}
	for k, e := range f.cache {
		if now.After(e.freshUntil) && now.After(e.retryAfter) {
			delete(f.cache, k)
			return
		}
	}
	for k := range f.cache {
		delete(f.cache, k)
		return
	}
}

type fetchResult struct {
	dir          *Directory
	notModified  bool
	etag         string
	lastModified string
	ttl          time.Duration
	retryAfter   time.Duration
}

func (f *Fetcher) fetch(ctx context.Context, identifier *url.URL, etag, lastModified string) (fetchResult, error) {
	var result fetchResult

	release, err := f.acquire(ctx)
	if err != nil {
		return result, fmt.Errorf("%w: %w", ErrFetchFailed, err)
	}
	defer release()

	ctx, cancel := context.WithTimeout(ctx, f.opts.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, identifier.String(), nil)
	if err != nil {
		return result, fmt.Errorf("%w: %w", ErrFetchFailed, err)
	}
	req.Header.Set("Accept", MediaTypeDirectory)
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	if lastModified != "" {
		req.Header.Set("If-Modified-Since", lastModified)
	}

	resp, err := f.client.Do(req)
	if err != nil {
		return result, fmt.Errorf("%w: %s: %w", ErrFetchFailed, identifier, err)
	}
	// Close only releases the connection; the body is fully read or
	// discarded by then.
	defer func() { _ = resp.Body.Close() }()

	result.retryAfter = parseRetryAfter(resp.Header.Get("Retry-After"), f.opts.Now())

	switch {
	case resp.StatusCode == http.StatusNotModified && etag+lastModified != "":
		result.notModified = true
		result.ttl = f.ttl(resp.Header)
		return result, nil
	case resp.StatusCode != http.StatusOK:
		// Section 5.5: anything but 200, including redirects, is a
		// discovery failure.
		return result, fmt.Errorf("%w: %s: status %d", ErrFetchFailed, identifier, resp.StatusCode)
	}

	mt, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || mt != MediaTypeDirectory {
		return result, fmt.Errorf("%w: %s: content type %q", ErrNotADirectory, identifier, resp.Header.Get("Content-Type"))
	}

	// The transport decodes gzip transparently, so this limit applies
	// after content decoding.
	body, err := io.ReadAll(io.LimitReader(resp.Body, f.opts.MaxBodySize+1))
	if err != nil {
		return result, fmt.Errorf("%w: %s: reading body: %w", ErrFetchFailed, identifier, err)
	}
	if int64(len(body)) > f.opts.MaxBodySize {
		return result, fmt.Errorf("%w: %s: over %d bytes", ErrDirectoryTooBig, identifier, f.opts.MaxBodySize)
	}

	dir, err := ParseDirectory(body, f.opts.Directory)
	if err != nil {
		return result, fmt.Errorf("%s: %w", identifier, err)
	}

	switch f.opts.DirectorySignatures {
	case DirectorySignaturesIgnore:
	case DirectorySignaturesPrefer:
		if isSignedDirectory(resp) {
			f.dropUnboundKeys(dir, resp, req, body)
		}
	default:
		// Unknown policies fail closed.
		f.dropUnboundKeys(dir, resp, req, body)
	}

	result.dir = dir
	result.etag = resp.Header.Get("ETag")
	result.lastModified = resp.Header.Get("Last-Modified")
	result.ttl = f.ttl(resp.Header)
	return result, nil
}

// isSignedDirectory reports whether resp claims to carry directory response
// signatures. Signature headers that fail to parse count as a claim, so a
// mangled signature is rejected rather than ignored.
func isSignedDirectory(resp *http.Response) bool {
	all, err := httpsign.ResponseDetailsListByTag(resp, TagDirectory)
	return err != nil || len(all) != 0
}

// dropUnboundKeys removes keys without a valid directory response signature
// (protocol draft Appendix B.1): the signature must be tagged
// http-message-signatures-directory, cover "@authority";req and
// content-digest, verify with that key, and not be created in the future;
// and Content-Digest must match the body.
func (f *Fetcher) dropUnboundKeys(dir *Directory, resp *http.Response, req *http.Request, body []byte) {
	reject := func(err error) {
		for _, k := range dir.Keys {
			dir.Invalid = append(dir.Invalid, fmt.Errorf("%w: %s: %w", ErrDirectoryUnbound, k.ID, err))
		}
		dir.Keys = nil
	}

	rc := io.NopCloser(bytes.NewReader(body))
	if err := httpsign.ValidateContentDigestHeader(resp.Header.Values("Content-Digest"), &rc, []string{httpsign.DigestSha256, httpsign.DigestSha512}); err != nil {
		reject(fmt.Errorf("content-digest: %w", err))
		return
	}

	all, err := httpsign.ResponseDetailsListByTag(resp, TagDirectory)
	if err != nil {
		reject(err)
		return
	}

	now := f.opts.Now()
	fields := httpsign.NewFields().AddRequestComponent("@authority").AddHeader("content-digest")

	var bound []Key
	for _, k := range dir.Keys {
		if err := verifyBinding(k, all, resp, req, *fields, now, f.opts.ClockSkew); err != nil {
			dir.Invalid = append(dir.Invalid, fmt.Errorf("%w: %s: %w", ErrDirectoryUnbound, k.ID, err))
			continue
		}
		bound = append(bound, k)
	}
	dir.Keys = bound
}

func verifyBinding(k Key, all []*httpsign.MessageDetails, resp *http.Response, req *http.Request, fields httpsign.Fields, now time.Time, skew time.Duration) error {
	newV := k.newVerifier
	if newV == nil {
		built, err := NewKey(k.JWK)
		if err != nil {
			return err
		}
		newV = built.newVerifier
	}

	lastErr := errors.New("no signature with this keyid")
	for _, d := range all {
		if d.KeyID == nil || *d.KeyID != k.ID {
			continue
		}
		if d.Created == nil || d.Expires == nil {
			lastErr = errors.New("created and expires are required")
			continue
		}
		if !d.Expires.After(now.Add(-skew)) {
			lastErr = errors.New("signature expired")
			continue
		}
		if d.Created.After(now.Add(skew)) {
			// Appendix B.1: MUST reject a future created.
			lastErr = errors.New("created is in the future")
			continue
		}

		cfg := httpsign.NewVerifyConfig().
			SetVerifyCreated(false).
			SetRejectExpired(false). // checked above against f.opts.Now
			SetAllowedTags([]string{TagDirectory}).
			SetKeyID(k.ID)
		v, err := newV(cfg, fields)
		if err != nil {
			return err
		}
		if err := httpsign.VerifyResponse(d.Label, *v, resp, req); err != nil {
			lastErr = err
			continue
		}
		return nil
	}
	return lastErr
}

// ttl computes how long a response may be cached (Appendix C.4), clamped to
// [MinTTL, MaxTTL].
func (f *Fetcher) ttl(h http.Header) time.Duration {
	ttl := f.opts.TTL

	cc := strings.ToLower(h.Get("Cache-Control"))
	switch {
	case strings.Contains(cc, "no-store"), strings.Contains(cc, "no-cache"):
		ttl = 0
	case strings.Contains(cc, "max-age="):
		for _, d := range strings.Split(cc, ",") {
			d = strings.TrimSpace(d)
			if v, ok := strings.CutPrefix(d, "max-age="); ok {
				if n, err := strconv.ParseInt(strings.Trim(v, `"`), 10, 64); err == nil && n >= 0 {
					ttl = time.Duration(min(n, int64(f.opts.MaxTTL/time.Second))) * time.Second
				}
			}
		}
	case h.Get("Expires") != "":
		exp, err := http.ParseTime(h.Get("Expires"))
		if err != nil {
			ttl = 0
			break
		}
		date, err := http.ParseTime(h.Get("Date"))
		if err != nil {
			date = f.opts.Now()
		}
		ttl = exp.Sub(date)
	}

	return min(max(ttl, f.opts.MinTTL), f.opts.MaxTTL)
}

// acquire takes one of the MaxConcurrentFetches fetch slots.
func (f *Fetcher) acquire(ctx context.Context) (func(), error) {
	select {
	case f.slots <- struct{}{}:
		return func() { <-f.slots }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func parseRetryAfter(v string, now time.Time) time.Duration {
	if v == "" {
		return 0
	}
	if n, err := strconv.Atoi(v); err == nil && n > 0 {
		return time.Duration(n) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		return max(t.Sub(now), 0)
	}
	return 0
}

// checkPublicAddress rejects dialing addresses that are not publicly
// routable (protocol draft Section 6.7).
func checkPublicAddress(address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("%w: %s: %w", ErrBlockedAddress, address, err)
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("%w: %s: %w", ErrBlockedAddress, address, err)
	}
	ip = ip.Unmap()

	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return fmt.Errorf("%w: %s", ErrBlockedAddress, ip)
	}
	for _, p := range blockedPrefixes {
		if p.Contains(ip) {
			return fmt.Errorf("%w: %s is in %s", ErrBlockedAddress, ip, p)
		}
	}
	return nil
}

// blockedPrefixes are special-purpose ranges that IsGlobalUnicast and
// IsPrivate do not exclude.
var blockedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),   // carrier-grade NAT
	netip.MustParsePrefix("192.0.0.0/24"),    // IETF protocol assignments
	netip.MustParsePrefix("192.0.2.0/24"),    // TEST-NET-1
	netip.MustParsePrefix("198.18.0.0/15"),   // benchmarking
	netip.MustParsePrefix("198.51.100.0/24"), // TEST-NET-2
	netip.MustParsePrefix("203.0.113.0/24"),  // TEST-NET-3
	netip.MustParsePrefix("240.0.0.0/4"),     // reserved
	netip.MustParsePrefix("64:ff9b::/96"),    // NAT64, can reach IPv4 internals
	netip.MustParsePrefix("64:ff9b:1::/48"),  // local-use NAT64
	netip.MustParsePrefix("2001:db8::/32"),   // documentation
	netip.MustParsePrefix("2002::/16"),       // 6to4, can embed private IPv4
}
