package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/themakers/cage/libcage"
)

var envVarPattern = regexp.MustCompile(`^\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?$`)

func cmdRun(logger *slog.Logger, wd string, args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	raw := fs.Bool("raw", false, "raw mode: read explicit .cage files/directories")
	noMask := fs.Bool("no-mask", false, "do not mask secret values in the command output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	secretSpecs, cmdArgs, err := splitAtDash(fs.Args(), "run")
	if err != nil {
		return err
	}
	if len(secretSpecs) == 0 {
		return fmt.Errorf("run: provide secrets/@env before '-'")
	}

	var c *libcage.Cage
	if *raw {
		c, err = newRawCage(logger)
	} else {
		root, e := resolveRoot(wd)
		if e != nil {
			return e
		}
		c, err = newCage(logger, root)
	}
	if err != nil {
		return err
	}

	vars, err := c.BuildEnv(secretSpecs, *raw)
	if err != nil {
		return err
	}
	m := make(map[string]string, len(vars))
	values := make([]string, 0, len(vars))
	for _, v := range vars {
		m[v.Name] = v.Value
		values = append(values, v.Value)
	}
	cmdArgs = expandArgVars(cmdArgs, m)

	var patterns [][]byte
	if !*noMask && !interactive() {
		patterns = libcage.MaskPatterns(values)
	}
	return runCommand(cmdArgs, mergeEnv(os.Environ(), m), os.Stdout, true, patterns)
}

// runCommand runs the command with env; stdout goes to out (masked only if
// maskOut: it may be data for cage), stderr to os.Stderr masked by patterns
// (if any). The exit code of the command becomes the exit code of cage.
func runCommand(cmdArgs, env []string, out io.Writer, maskOut bool, patterns [][]byte) error {
	ex := exec.Command(cmdArgs[0], cmdArgs[1:]...)
	ex.Env = env
	ex.Stdin = os.Stdin
	var closers []*libcage.MaskWriter
	wrap := func(w io.Writer) io.Writer {
		if len(patterns) == 0 {
			return w
		}
		mw := libcage.NewMaskWriter(w, patterns)
		closers = append(closers, mw)
		return mw
	}
	ex.Stdout = out
	if maskOut {
		ex.Stdout = wrap(out)
	}
	ex.Stderr = wrap(os.Stderr)
	err := ex.Run()
	for _, c := range closers {
		_ = c.Close()
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		os.Exit(exitErr.ExitCode())
	}
	return err
}

// interactive: a human at a terminal (stdin and stdout are terminals).
// Masking needs to intercept output, which breaks interactive programs.
func interactive() bool {
	return isTerminal(os.Stdin) && isTerminal(os.Stdout)
}

func isTerminal(f *os.File) bool {
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

func splitAtDash(rest []string, cmd string) ([]string, []string, error) {
	for i, a := range rest {
		if a == "-" {
			if i == len(rest)-1 {
				return nil, nil, fmt.Errorf("%s: provide command after '-'", cmd)
			}
			return rest[:i], rest[i+1:], nil
		}
	}
	return nil, nil, fmt.Errorf("%s: expected '-' separator before command", cmd)
}

func mergeEnv(base []string, add map[string]string) []string {
	m := map[string]string{}
	for _, kv := range base {
		if k, v, ok := strings.Cut(kv, "="); ok {
			m[k] = v
		}
	}
	for k, v := range add {
		m[k] = v
	}
	out := make([]string, 0, len(m))
	for k, v := range m {
		out = append(out, k+"="+v)
	}
	return out
}

func expandArgVars(args []string, vars map[string]string) []string {
	out := make([]string, len(args))
	for i, a := range args {
		m := envVarPattern.FindStringSubmatch(a)
		if len(m) == 2 {
			if v, ok := vars[m[1]]; ok {
				out[i] = v
				continue
			}
		}
		out[i] = a
	}
	return out
}
