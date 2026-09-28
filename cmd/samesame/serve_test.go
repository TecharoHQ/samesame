package main

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/TecharoHQ/samesame"
)

// newKeyFile writes a new private key to dir/name and returns its keyid.
func newKeyFile(t *testing.T, dir, name string) string {
	t.Helper()

	key, err := samesame.GenerateKey(samesame.AlgEd25519)
	if err != nil {
		t.Fatal(err)
	}
	data, err := samesame.MarshalPrivateKeyPEM(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
		t.Fatal(err)
	}
	k, err := samesame.PublicJWK(key)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := k.KeyID()
	return id
}

// served fetches the directory from ds as host bot.test and returns the
// status code and the keyids it lists.
func served(t *testing.T, ds *directoryServer) (int, []string) {
	t.Helper()

	w := httptest.NewRecorder()
	ds.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "https://bot.test"+samesame.WellKnownPath, nil))
	if w.Code != http.StatusOK {
		return w.Code, nil
	}

	dir, err := samesame.ParseDirectory(w.Body.Bytes(), samesame.DirectoryOptions{})
	if err != nil {
		t.Fatalf("ParseDirectory: %v", err)
	}
	var ids []string
	for _, k := range dir.Keys {
		ids = append(ids, k.ID)
	}
	return w.Code, ids
}

func sorted(ids ...string) []string {
	s := slices.Clone(ids)
	slices.Sort(s)
	return s
}

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestLoadKeyFolder(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	a := newKeyFile(t, dir, "a.pem")
	b := newKeyFile(t, dir, "b.pem")

	// Ignored: not .pem, hidden, and a folder named like a key.
	newKeyFile(t, dir, "c.key")
	newKeyFile(t, dir, ".hidden.pem")
	if err := os.Mkdir(filepath.Join(dir, "d.pem"), 0o755); err != nil {
		t.Fatal(err)
	}
	// The same key twice is served once.
	data, err := os.ReadFile(filepath.Join(dir, "a.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "a-copy.pem"), data, 0o600); err != nil {
		t.Fatal(err)
	}

	_, ids, err := loadKeyFolder(dir)
	if err != nil {
		t.Fatalf("loadKeyFolder: %v", err)
	}
	if want := sorted(a, b); !slices.Equal(ids, want) {
		t.Errorf("want %v, got %v", want, ids)
	}

	// A .pem that does not parse fails the whole load.
	if err := os.WriteFile(filepath.Join(dir, "broken.pem"), []byte("-----BEGIN PRIV"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadKeyFolder(dir); err == nil {
		t.Error("broken.pem did not fail the load")
	}

	if _, _, err := loadKeyFolder(filepath.Join(dir, "missing")); err == nil {
		t.Error("missing folder did not fail the load")
	}
}

func TestDirectoryServerReload(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	ds := newDirectoryServer(dir, []string{"bot.test"}, quietLog())

	reload := func() {
		t.Helper()
		if err := ds.reload(); err != nil {
			t.Fatalf("reload: %v", err)
		}
	}
	want := func(code int, ids ...string) {
		t.Helper()
		gotCode, gotIDs := served(t, ds)
		if gotCode != code || !slices.Equal(gotIDs, sorted(ids...)) {
			t.Fatalf("want %d %v, got %d %v", code, sorted(ids...), gotCode, gotIDs)
		}
	}

	reload()
	want(http.StatusServiceUnavailable)

	a := newKeyFile(t, dir, "a.pem")
	reload()
	want(http.StatusOK, a)

	b := newKeyFile(t, dir, "b.pem")
	reload()
	want(http.StatusOK, a, b)

	// Deleting a file removes its key.
	if err := os.Remove(filepath.Join(dir, "a.pem")); err != nil {
		t.Fatal(err)
	}
	reload()
	want(http.StatusOK, b)

	// A file caught mid-write keeps the previous keys served.
	broken := filepath.Join(dir, "c.pem")
	if err := os.WriteFile(broken, []byte("-----BEGIN PRIVATE KEY-----\nMC4C"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ds.reload(); err == nil {
		t.Fatal("reload accepted a broken key file")
	}
	want(http.StatusOK, b)

	c := newKeyFile(t, dir, "c.pem")
	reload()
	want(http.StatusOK, b, c)

	// Only the configured authority is signed for.
	w := httptest.NewRecorder()
	ds.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "https://evil.test"+samesame.WellKnownPath, nil))
	if w.Code != http.StatusMisdirectedRequest {
		t.Errorf("other host: want 421, got %d", w.Code)
	}

	// Removing every key goes back to 503.
	for _, name := range []string{"b.pem", "c.pem"} {
		if err := os.Remove(filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	reload()
	want(http.StatusServiceUnavailable)
}

func TestDirectoryServerKeepsHandlerWhenUnchanged(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	newKeyFile(t, dir, "a.pem")
	ds := newDirectoryServer(dir, []string{"bot.test"}, quietLog())
	if err := ds.reload(); err != nil {
		t.Fatal(err)
	}
	before := ds.handler.Load()

	// Touching the folder without changing keys must not rebuild the
	// handler, which would throw away its signature cache.
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := ds.reload(); err != nil {
		t.Fatal(err)
	}
	if ds.handler.Load() != before {
		t.Error("handler was rebuilt although the keys did not change")
	}
}

func TestDirectoryServerWatch(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	ds := newDirectoryServer(dir, []string{"bot.test"}, quietLog())
	if err := ds.reload(); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	// A long poll interval, so only filesystem events can cause reloads.
	go func() { done <- ds.watch(ctx, time.Hour, 20*time.Millisecond) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("watch: %v", err)
		}
	})

	eventually := func(what string, ids ...string) {
		t.Helper()
		want := sorted(ids...)
		deadline := time.Now().Add(5 * time.Second)
		for {
			_, got := served(t, ds)
			if slices.Equal(got, want) {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s: want %v, got %v", what, want, got)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}

	// Give the watcher a moment to start.
	time.Sleep(50 * time.Millisecond)

	a := newKeyFile(t, dir, "a.pem")
	eventually("new file", a)

	// Editors and deploy tools often write a temporary file and rename it
	// into place.
	tmpDir := t.TempDir()
	b := newKeyFile(t, tmpDir, "b.pem.tmp")
	if err := os.Rename(filepath.Join(tmpDir, "b.pem.tmp"), filepath.Join(dir, "b.pem")); err != nil {
		t.Fatal(err)
	}
	eventually("renamed into place", a, b)

	if err := os.Remove(filepath.Join(dir, "a.pem")); err != nil {
		t.Fatal(err)
	}
	eventually("deleted", b)
}
