package main

import (
	"fmt"
	"log/slog"
)

func cmdEncrypt(logger *slog.Logger, wd string, args []string) error {
	if len(args) != 0 {
		return fmt.Errorf("encrypt: no arguments expected")
	}
	root, err := resolveRoot(wd)
	if err != nil {
		return err
	}
	c, err := newCage(logger, root)
	if err != nil {
		return err
	}
	return c.EncryptAll()
}
