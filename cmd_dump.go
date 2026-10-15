package main

import (
	"bytes"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/themakers/cage/libcage"
)

// dump writes values only to an explicit file: printing secrets is never a
// default (`-o /dev/stdout` is a deliberate choice).
func cmdDump(logger *slog.Logger, wd string, args []string) error {
	fs := flag.NewFlagSet("dump", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	out := fs.String("o", "", "output file (required; created with mode 0600)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	specs := fs.Args()
	if *out == "" {
		return fmt.Errorf("dump: -o <file> is required (values are never printed by default; use `cage inspect` to look at secrets)")
	}
	if len(specs) == 0 {
		return fmt.Errorf("dump: expected one or more secrets")
	}

	needsRoot := false
	for _, a := range specs {
		_, rest, _ := strings.Cut(a, "=")
		if !strings.Contains(a, "=") {
			rest = a
		}
		if strings.HasPrefix(rest, "@") || !strings.HasSuffix(rest, ".cage") {
			needsRoot = true
			break
		}
	}

	var c *libcage.Cage
	var err error
	if needsRoot {
		root, e := resolveRoot(wd)
		if e != nil {
			return e
		}
		c, err = newCage(logger, root)
	} else {
		c, err = newRawCage(logger)
	}
	if err != nil {
		return err
	}

	var buf bytes.Buffer
	if err := c.Dump(specs, &buf); err != nil {
		return err
	}
	return writeOutput(*out, buf.Bytes())
}

func writeOutput(path string, data []byte) error {
	if path == "-" || path == "/dev/stdout" {
		_, err := os.Stdout.Write(data)
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
