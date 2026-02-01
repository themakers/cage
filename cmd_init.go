package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/themakers/cage/libcage"
)

func cmdInit(logger *slog.Logger, wd string, args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(fs.Args()) != 0 {
		return fmt.Errorf("init: no arguments expected")
	}

	target := "."
	if wd != "" {
		target = wd
	}
	abs, err := filepath.Abs(target)
	if err != nil {
		return err
	}
	logger.Info("creating .cage", "dir", abs)
	return libcage.InitCage(abs)
}
