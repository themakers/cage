package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/themakers/cage/libcage"
)

func main() {
	logger := newLogger()

	global := flag.NewFlagSet("cage", flag.ContinueOnError)
	global.SetOutput(os.Stderr)
	wd := global.String("wd", "", "cage root (directory containing .cage); if omitted, discover from CWD")
	if err := global.Parse(os.Args[1:]); err != nil {
		exitErr(err)
	}
	args := global.Args()
	if len(args) == 0 {
		printUsage(os.Stderr)
		os.Exit(2)
	}

	cmd := args[0]
	cmdArgs := args[1:]

	switch cmd {
	case "encrypt":
		exitErr(cmdEncrypt(logger, *wd, cmdArgs))
	case "decrypt":
		exitErr(cmdDecrypt(logger, *wd, cmdArgs))
	case "dump":
		exitErr(cmdDump(logger, *wd, cmdArgs))
	case "run":
		exitErr(cmdRun(logger, *wd, cmdArgs))
	case "init":
		exitErr(cmdInit(logger, *wd, cmdArgs))
	case "-h", "--help", "help":
		printUsage(os.Stdout)
		return
	default:
		printUsage(os.Stderr)
		os.Exit(2)
	}
}

func newLogger() *slog.Logger {
	level := slog.LevelInfo
	if s := strings.TrimSpace(os.Getenv("CAGE_LOG_LEVEL")); s != "" {
		s = strings.ToLower(s)
		switch s {
		case "debug":
			level = slog.LevelDebug
		case "warn", "warning":
			level = slog.LevelWarn
		case "error":
			level = slog.LevelError
		case "info":
			level = slog.LevelInfo
		}
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
}

func exitErr(err error) {
	if err == nil {
		return
	}
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}

var _ = libcage.IsEnvSecretName
