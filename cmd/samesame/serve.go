package main

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/TecharoHQ/samesame"
	"github.com/fsnotify/fsnotify"
	"github.com/urfave/cli/v3"
)

func serveCommand() *cli.Command {
	return &cli.Command{
		Name:  "serve",
		Usage: "serve the key directory for the .pem private keys in a folder",
		Description: "Serves " + samesame.WellKnownPath + " for every .pem private key in\n" +
			"--keys, signed for each --authority. The folder is watched: adding or\n" +
			"deleting a key file updates the served directory. If a .pem file does not\n" +
			"parse, for example while it is being written, the previous keys stay\n" +
			"served until it does.",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "keys",
				Usage:    "folder of .pem private keys",
				Required: true,
				Sources:  cli.EnvVars("SAMESAME_KEYS"),
			},
			&cli.StringSliceFlag{
				Name:     "authority",
				Usage:    "host the directory is served for, such as bot.example; repeat for several",
				Required: true,
				Sources:  cli.EnvVars("SAMESAME_AUTHORITY"),
			},
			&cli.StringFlag{
				Name:    "bind",
				Value:   ":8080",
				Usage:   "address to listen on",
				Sources: cli.EnvVars("SAMESAME_BIND"),
			},
			&cli.DurationFlag{
				Name:  "poll",
				Value: time.Minute,
				Usage: "also reload on this interval, in case a change event is missed",
			},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
			defer stop()

			log := slog.New(slog.NewJSONHandler(cmd.Root().ErrWriter, nil))

			ds := newDirectoryServer(cmd.String("keys"), cmd.StringSlice("authority"), log)
			if err := ds.reload(); err != nil {
				// Keep going: the folder may be fixed while we run.
				log.Error("can't load keys", "err", err)
			}

			ln, err := net.Listen("tcp", cmd.String("bind"))
			if err != nil {
				return err
			}

			mux := http.NewServeMux()
			mux.Handle(samesame.WellKnownPath, ds)
			srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}

			var wg sync.WaitGroup
			wg.Go(func() {
				if err := ds.watch(ctx, cmd.Duration("poll"), 250*time.Millisecond); err != nil {
					log.Error("watching keys failed", "err", err)
					stop()
				}
			})

			go func() {
				<-ctx.Done()
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_ = srv.Shutdown(shutdownCtx)
			}()

			log.Info("serving key directory", "bind", ln.Addr().String(), "keys", cmd.String("keys"), "authorities", cmd.StringSlice("authority"))
			err = srv.Serve(ln)
			stop()
			wg.Wait()
			if errors.Is(err, http.ErrServerClosed) {
				return nil
			}
			return err
		},
	}
}

// directoryServer serves the key directory for the keys in a folder and
// swaps in a new one when they change.
type directoryServer struct {
	dir         string
	authorities []string
	log         *slog.Logger

	handler  atomic.Pointer[http.Handler] // nil while there are no keys
	keyIDs   []string                     // guarded by reloadMu
	loaded   bool                         // guarded by reloadMu
	reloadMu sync.Mutex
}

func newDirectoryServer(dir string, authorities []string, log *slog.Logger) *directoryServer {
	return &directoryServer{dir: dir, authorities: authorities, log: log}
}

func (ds *directoryServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := ds.handler.Load()
	if h == nil {
		http.Error(w, "no keys", http.StatusServiceUnavailable)
		return
	}
	(*h).ServeHTTP(w, r)
}

// reload reads every .pem file in the folder. If any fails to parse, it
// returns an error and leaves the served directory alone, so a key file
// caught mid-write is never dropped. The handler is only rebuilt when the
// set of keys changes, which keeps its signature cache.
func (ds *directoryServer) reload() error {
	ds.reloadMu.Lock()
	defer ds.reloadMu.Unlock()

	keys, ids, err := loadKeyFolder(ds.dir)
	if err != nil {
		return err
	}
	if ds.loaded && slices.Equal(ids, ds.keyIDs) {
		return nil
	}
	ds.loaded = true

	if len(keys) == 0 {
		ds.handler.Store(nil)
		ds.keyIDs = nil
		ds.log.Warn("no keys in folder, serving 503", "keys", ds.dir)
		return nil
	}

	h, err := samesame.NewDirectoryHandler(keys, samesame.DirectoryHandlerOptions{Authorities: ds.authorities})
	if err != nil {
		return err
	}
	ds.handler.Store(&h)
	ds.keyIDs = ids
	ds.log.Info("serving keys", "keyids", ids)
	return nil
}

// watch reloads after changes in the folder, batching bursts of events
// that arrive within debounce, and every poll as a fallback.
func (ds *directoryServer) watch(ctx context.Context, poll, debounce time.Duration) error {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	defer w.Close()

	// Watch the folder rather than the files, so editors that save by
	// renaming and symlink swaps (as in Kubernetes ConfigMaps) are seen.
	if err := w.Add(ds.dir); err != nil {
		return fmt.Errorf("watching %s: %w", ds.dir, err)
	}

	ticker := time.NewTicker(poll)
	defer ticker.Stop()

	var timer <-chan time.Time
	reload := func(why string) {
		if err := ds.reload(); err != nil {
			ds.log.Error("can't reload keys, still serving the previous ones", "why", why, "err", err)
		}
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case ev, ok := <-w.Events:
			if !ok {
				return errors.New("watcher closed")
			}
			ds.log.Debug("key folder changed", "event", ev.String())
			timer = time.After(debounce)
		case err, ok := <-w.Errors:
			if !ok {
				return errors.New("watcher closed")
			}
			// Events may have been lost, so reload to be sure.
			ds.log.Error("watch error", "err", err)
			timer = time.After(debounce)
		case <-timer:
			timer = nil
			reload("change")
		case <-ticker.C:
			reload("poll")
		}
	}
}

// loadKeyFolder parses every .pem file in dir as a private key and returns
// the keys with their keyids, sorted by keyid so the served order is stable.
func loadKeyFolder(dir string) ([]crypto.Signer, []string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil, err
	}

	type loaded struct {
		key crypto.Signer
		id  string
	}
	var (
		all  []loaded
		errs []error
		seen = map[string]string{}
	)
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".pem") || strings.HasPrefix(name, ".") {
			continue
		}
		path := filepath.Join(dir, name)
		info, err := os.Stat(path) // follows symlinks
		if err != nil || !info.Mode().IsRegular() {
			continue
		}

		data, err := os.ReadFile(path)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		key, err := samesame.ParsePrivateKeyPEM(data)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
			continue
		}
		jwk, err := samesame.PublicJWK(key)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
			continue
		}
		id, _ := jwk.KeyID()
		if _, ok := seen[id]; ok {
			// The same key in two files is served once.
			continue
		}
		seen[id] = name
		all = append(all, loaded{key, id})
	}
	if len(errs) != 0 {
		return nil, nil, errors.Join(errs...)
	}

	slices.SortFunc(all, func(a, b loaded) int { return strings.Compare(a.id, b.id) })
	keys := make([]crypto.Signer, len(all))
	ids := make([]string, len(all))
	for i, l := range all {
		keys[i], ids[i] = l.key, l.id
	}
	return keys, ids, nil
}
