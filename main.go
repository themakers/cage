package main

import (
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"
)

// TODO: rm command
// TODO: dump/decrypt -raw > add -merge
// TODO: keep order of secrets in environment dump
// TODO: -shred flag for encrypt
// TODO: selective decrypt
// TODO: status subcommand
// TODO: hand rewrite
// TODO: tui
//
// TODO: age
// TODO: yubikey
// TODO: tpm

func main() {
	logger := newLogger()

	global := flag.NewFlagSet("cage", flag.ContinueOnError)
	global.SetOutput(os.Stderr)
	wd := global.String("wd", "", "cage root (directory containing .cage); if omitted, discover from CWD")
	global.Usage = func() {}
	if err := global.Parse(os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			printUsage(os.Stdout)
			return
		}
		exitErr(err)
	}
	args := global.Args()
	if len(args) == 0 {
		printUsage(os.Stdout)
		return
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
	case "inspect":
		exitErr(cmdInspect(logger, *wd, cmdArgs))
	case "status":
		exitErr(cmdStatus(logger, *wd, cmdArgs))
	case "whoami":
		exitErr(cmdWhoami(logger, *wd, cmdArgs))
	case "set":
		exitErr(cmdSet(logger, *wd, cmdArgs))
	case "import":
		exitErr(cmdImport(logger, *wd, cmdArgs))
	case "keygen":
		exitErr(cmdKeygen(logger, *wd, cmdArgs))
	case "mv":
		exitErr(cmdMv(logger, *wd, cmdArgs))
	case "rm":
		exitErr(cmdRm(logger, *wd, cmdArgs))
	case "comment":
		exitErr(cmdComment(logger, *wd, cmdArgs))
	case "skill":
		fmt.Print(skillText)
		return
	case "-h", "-help", "--help", "help":
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
