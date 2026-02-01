package main

import (
	"flag"
	"fmt"
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
	if err := fs.Parse(args); err != nil {
		return err
	}
	rest := fs.Args()
	sep := -1
	for i, a := range rest {
		if a == "-" {
			sep = i
			break
		}
	}
	if sep == -1 {
		return fmt.Errorf("run: expected '-' separator before command")
	}
	secretSpecs := rest[:sep]
	cmdArgs := rest[sep+1:]
	if len(secretSpecs) == 0 {
		return fmt.Errorf("run: provide secrets/@env before '-'")
	}
	if len(cmdArgs) == 0 {
		return fmt.Errorf("run: provide command after '-'")
	}

	var c *libcage.Cage
	var err error
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

	vars, err := c.BuildEnvVars(secretSpecs, *raw)
	if err != nil {
		return err
	}

	cmdArgs = expandArgVars(cmdArgs, vars)

	merged := mergeEnv(os.Environ(), vars)
	ex := exec.Command(cmdArgs[0], cmdArgs[1:]...)
	ex.Env = merged
	ex.Stdin = os.Stdin
	ex.Stdout = os.Stdout
	ex.Stderr = os.Stderr
	return ex.Run()
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
