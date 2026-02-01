package main

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
)

func cmdDump(logger *slog.Logger, wd string, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("dump: expected one or more secrets")
	}

	needsRoot := false
	for _, a := range args {
		if strings.HasPrefix(a, "@") {
			needsRoot = true
			break
		}
		if !strings.HasSuffix(a, ".cage") {
			needsRoot = true
			break
		}
	}

	if needsRoot {
		root, err := resolveRoot(wd)
		if err != nil {
			return err
		}
		c, err := newCage(logger, root)
		if err != nil {
			return err
		}
		return c.Dump(args, os.Stdout)
	}

	// Paths-only dump: can work without cage root.
	c, err := newRawCage(logger)
	if err != nil {
		return err
	}
	return c.Dump(args, os.Stdout)
}
