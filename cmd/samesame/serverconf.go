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

// confWriter writes formatted text and remembers the first error, so the
// many writes of a config block are checked once.
type confWriter struct {
	w   io.Writer
	err error
}

func (c *confWriter) printf(format string, args ...any) {
	if c.err == nil {
		_, c.err = fmt.Fprintf(c.w, format, args...)
	}
}

// writeNginx writes an nginx location block that serves file as the signed
// directory for host.
func writeNginx(w io.Writer, host, file string, sd *samesame.StaticDirectory) error {
	c := &confWriter{w: w}
	c.printf("# nginx: put this inside the server block for %s.\n", host)
	writeExpiryComment(c, sd.Expires)
	c.printf("# add_header here replaces any add_header inherited from the server block.\n")
	c.printf("location = %s {\n", samesame.WellKnownPath)
	c.printf("    alias %s;\n", file)
	c.printf("    types { }\n")
	c.printf("    default_type %s;\n", samesame.MediaTypeDirectory)
	c.printf("    # Content-Digest covers the exact bytes sent, so never compress this file.\n")
	c.printf("    gzip off;\n")
	c.printf("    gzip_static off;\n")
	for _, name := range staticHeaders {
		for _, v := range sd.Header.Values(name) {
			// Single quotes keep the value's double quotes literal. None
			// of these values can contain a quote, backslash, or $.
			if strings.ContainsAny(v, `'\$`) {
				return fmt.Errorf("nginx: can't quote %s value %q", name, v)
			}
			c.printf("    add_header %s '%s';\n", name, v)
		}
	}
	c.printf("}\n")
	return c.err
}

// writeCaddy writes a Caddyfile handle block that serves file as the signed
// directory for host.
func writeCaddy(w io.Writer, host, file string, sd *samesame.StaticDirectory) error {
	c := &confWriter{w: w}
	c.printf("# Caddy: put this inside the site block for %s.\n", host)
	writeExpiryComment(c, sd.Expires)
	c.printf("# Content-Digest covers the exact bytes sent, so if this site uses `encode`,\n")
	c.printf("# limit it to other paths:\n")
	c.printf("#   @compress not path %s\n", samesame.WellKnownPath)
	c.printf("#   encode @compress\n")
	c.printf("handle %s {\n", samesame.WellKnownPath)
	c.printf("\theader Content-Type %s\n", samesame.MediaTypeDirectory)
	for _, name := range staticHeaders {
		for _, v := range sd.Header.Values(name) {
			// Backticks keep the value's double quotes literal.
			if strings.Contains(v, "`") {
				return fmt.Errorf("caddy: can't quote %s value %q", name, v)
			}
			c.printf("\theader +%s `%s`\n", name, v)
		}
	}
	c.printf("\troot * %s\n", filepath.Dir(file))
	c.printf("\trewrite * /%s\n", filepath.Base(file))
	c.printf("\tfile_server\n")
	c.printf("}\n")
	return c.err
}

func writeExpiryComment(c *confWriter, expires time.Time) {
	c.printf("# The signatures expire at %s. Run this command again before then,\n", expires.UTC().Format(time.RFC3339))
	c.printf("# and whenever the keys change.\n")
}
