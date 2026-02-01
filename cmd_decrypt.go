package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
)

func cmdDecrypt(logger *slog.Logger, wd string, args []string) error {
	fs := flag.NewFlagSet("decrypt", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	raw := fs.Bool("raw", false, "raw mode: decrypt explicit .cage files/directories (no cage root)")
	out := fs.String("o", "", "output directory (raw mode only)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	rest := fs.Args()

	if *raw {
		if len(rest) == 0 {
			return fmt.Errorf("decrypt -raw: provide at least one .cage file or directory")
		}
		c, err := newRawCage(logger)
		if err != nil {
			return err
		}
		return c.DecryptRaw(rest, *out)
	}

	if len(rest) != 0 {
		return fmt.Errorf("decrypt: no arguments expected (did you mean -raw?)")
	}
	root, err := resolveRoot(wd)
	if err != nil {
		return err
	}
	c, err := newCage(logger, root)
	if err != nil {
		return err
	}
	return c.DecryptAll()
}
