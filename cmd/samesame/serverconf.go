package main

import (
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/TecharoHQ/samesame"
)

// Server config formats for `samesame directory --sign-for`.
const (
	formatNginx = "nginx"
	formatCaddy = "caddy"
	formatBoth  = "both"
)

// staticHeaders is the order header lines are written in. Signature-Input
// and Signature have one value per key.
var staticHeaders = []string{"Cache-Control", "Content-Digest", "Signature-Input", "Signature"}

// writeNginx writes an nginx location block that serves file as the signed
// directory for host.
func writeNginx(w io.Writer, host, file string, sd *samesame.StaticDirectory) error {
	fmt.Fprintf(w, "# nginx: put this inside the server block for %s.\n", host)
	writeExpiryComment(w, sd.Expires)
	fmt.Fprintln(w, "# add_header here replaces any add_header inherited from the server block.")
	fmt.Fprintf(w, "location = %s {\n", samesame.WellKnownPath)
	fmt.Fprintf(w, "    alias %s;\n", file)
	fmt.Fprintln(w, "    types { }")
	fmt.Fprintf(w, "    default_type %s;\n", samesame.MediaTypeDirectory)
	fmt.Fprintln(w, "    # Content-Digest covers the exact bytes sent, so never compress this file.")
	fmt.Fprintln(w, "    gzip off;")
	fmt.Fprintln(w, "    gzip_static off;")
	for _, name := range staticHeaders {
		for _, v := range sd.Header.Values(name) {
			// Single quotes keep the value's double quotes literal. None
			// of these values can contain a quote, backslash, or $.
			if strings.ContainsAny(v, `'\$`) {
				return fmt.Errorf("nginx: can't quote %s value %q", name, v)
			}
			fmt.Fprintf(w, "    add_header %s '%s';\n", name, v)
		}
	}
	fmt.Fprintln(w, "}")
	return nil
}

// writeCaddy writes a Caddyfile handle block that serves file as the signed
// directory for host.
func writeCaddy(w io.Writer, host, file string, sd *samesame.StaticDirectory) error {
	fmt.Fprintf(w, "# Caddy: put this inside the site block for %s.\n", host)
	writeExpiryComment(w, sd.Expires)
	fmt.Fprintln(w, "# Content-Digest covers the exact bytes sent, so if this site uses `encode`,")
	fmt.Fprintln(w, "# limit it to other paths:")
	fmt.Fprintf(w, "#   @compress not path %s\n", samesame.WellKnownPath)
	fmt.Fprintln(w, "#   encode @compress")
	fmt.Fprintf(w, "handle %s {\n", samesame.WellKnownPath)
	fmt.Fprintf(w, "\theader Content-Type %s\n", samesame.MediaTypeDirectory)
	for _, name := range staticHeaders {
		for _, v := range sd.Header.Values(name) {
			// Backticks keep the value's double quotes literal.
			if strings.Contains(v, "`") {
				return fmt.Errorf("caddy: can't quote %s value %q", name, v)
			}
			fmt.Fprintf(w, "\theader +%s `%s`\n", name, v)
		}
	}
	fmt.Fprintf(w, "\troot * %s\n", filepath.Dir(file))
	fmt.Fprintf(w, "\trewrite * /%s\n", filepath.Base(file))
	fmt.Fprintln(w, "\tfile_server")
	fmt.Fprintln(w, "}")
	return nil
}

func writeExpiryComment(w io.Writer, expires time.Time) {
	fmt.Fprintf(w, "# The signatures expire at %s. Run this command again before then,\n", expires.UTC().Format(time.RFC3339))
	fmt.Fprintln(w, "# and whenever the keys change.")
}
