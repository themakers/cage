package main

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/themakers/cage/libcage"
)

func resolveRoot(wd string) (string, error) {
	if wd != "" {
		abs, err := filepath.Abs(wd)
		if err != nil {
			return "", err
		}
		st, err := os.Stat(filepath.Join(abs, ".cage"))
		if err != nil {
			if os.IsNotExist(err) {
				return "", fmt.Errorf("-wd %s: no .cage directory", abs)
			}
			return "", err
		}
		if !st.IsDir() {
			return "", fmt.Errorf("-wd %s: .cage is not a directory", abs)
		}
		return abs, nil
	}
	return libcage.FindRoot(".")
}

func newCage(logger *slog.Logger, root string) (*libcage.Cage, error) {
	return libcage.New(libcage.NewOptions{Root: root, Logger: logger})
}

func newRawCage(logger *slog.Logger) (*libcage.Cage, error) {
	return libcage.New(libcage.NewOptions{Logger: logger})
}
