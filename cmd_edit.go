package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sort"
	"strings"

	"github.com/themakers/cage/libcage"
)

// Editing commands print names only — never values.

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func rootCage(logger *slog.Logger, wd string) (*libcage.Cage, error) {
	root, err := resolveRoot(wd)
	if err != nil {
		return nil, err
	}
	return newCage(logger, root)
}

// parseVarRef splits "alias:name.env:KEY" into the secret ref and KEY.
func parseVarRef(s string) (libcage.SecretRef, string, error) {
	i := strings.LastIndex(s, ".env:")
	if i < 0 {
		return libcage.SecretRef{}, "", fmt.Errorf("%q: expected <ref>:KEY (e.g. ops:db.env:PASSWORD)", s)
	}
	ref, err := libcage.ParseSecretRef(s[:i+4])
	if err != nil {
		return libcage.SecretRef{}, "", err
	}
	return ref, s[i+5:], nil
}

// finish encrypts after an edit (unless disabled) and warns about secrets
// that no env references: those are not encrypted.
func finish(c *libcage.Cage, noEncrypt bool, refs ...libcage.SecretRef) error {
	for _, r := range refs {
		if len(c.ReferencedBy(r)) == 0 {
			fmt.Fprintf(os.Stderr, "warning: %s is not referenced by any env in cage.yaml — it is not encrypted until it is\n", r)
		}
	}
	if noEncrypt {
		return nil
	}
	return c.EncryptAll()
}

func cmdSet(logger *slog.Logger, wd string, args []string) error {
	fs := flag.NewFlagSet("set", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	gen := fs.String("gen", "", "generate the value: random:<base64|base64url|hex|alnum>:<bytes>")
	stdin := fs.Bool("stdin", false, "read the value from stdin (one line, trailing newline dropped)")
	plain := fs.String("plain", "", "non-secret value given on the command line (endpoint, bucket, user name)")
	comment := fs.String("comment", "", "comment to put above the variable")
	keep := fs.Bool("keep", false, "with -gen: keep an existing value (generate only if missing)")
	noEncrypt := fs.Bool("no-encrypt", false, "do not run encrypt after the change")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return fmt.Errorf("set: usage: cage set (-gen spec | -stdin | -plain value) [-comment text] <ref> <KEY>")
	}
	sources := 0
	for _, on := range []bool{*gen != "", *stdin, isFlagSet(fs, "plain")} {
		if on {
			sources++
		}
	}
	if sources != 1 {
		return fmt.Errorf("set: exactly one of -gen, -stdin, -plain is required")
	}
	ref, err := libcage.ParseSecretRef(fs.Arg(0))
	if err != nil {
		return err
	}
	key := fs.Arg(1)
	c, err := rootCage(logger, wd)
	if err != nil {
		return err
	}

	var value string
	switch {
	case *gen != "":
		value, err = libcage.Generate(*gen)
	case *stdin:
		var b []byte
		b, err = io.ReadAll(os.Stdin)
		value = strings.TrimRight(string(b), "\r\n")
	default:
		value = *plain
	}
	if err != nil {
		return err
	}

	action := "set"
	if err := c.EditEnv(ref, func(f *libcage.DotenvFile) error {
		if *keep && f.Has(key) {
			action = "kept"
		} else if err := f.Set(key, value); err != nil {
			return err
		}
		if *comment != "" {
			return f.Annotate(key, *comment)
		}
		return nil
	}); err != nil {
		return err
	}
	fmt.Printf("%s %s:%s\n", action, ref, key)
	return finish(c, *noEncrypt, ref)
}

func isFlagSet(fs *flag.FlagSet, name string) bool {
	set := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			set = true
		}
	})
	return set
}

func cmdImport(logger *slog.Logger, wd string, args []string) error {
	fs := flag.NewFlagSet("import", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var with multiFlag
	fs.Var(&with, "with", "secret/@env whose variables the command gets in its environment (repeatable)")
	noEncrypt := fs.Bool("no-encrypt", false, "do not run encrypt after the change")
	if err := fs.Parse(args); err != nil {
		return err
	}
	head, cmdArgs, err := splitAtDash(fs.Args(), "import")
	if err != nil {
		return err
	}
	if len(head) != 1 {
		return fmt.Errorf("import: usage: cage import [-with ref]... <ref> - <cmd...>")
	}
	ref, err := libcage.ParseSecretRef(head[0])
	if err != nil {
		return err
	}
	c, err := rootCage(logger, wd)
	if err != nil {
		return err
	}

	env := map[string]string{}
	var values []string
	if len(with) > 0 {
		vars, err := c.BuildEnv(with, false)
		if err != nil {
			return err
		}
		for _, v := range vars {
			env[v.Name] = v.Value
			values = append(values, v.Value)
		}
	}
	var out bytes.Buffer
	//> stdout is data for cage (never shown); stderr is diagnostics, masked.
	if err := runCommand(expandArgVars(cmdArgs, env), mergeEnv(os.Environ(), env), &out, libcage.MaskPatterns(values)); err != nil {
		return err
	}
	got, err := libcage.ParseDotenv(out.Bytes())
	if err != nil {
		return fmt.Errorf("import: command output is not KEY=VALUE lines: %w", err)
	}
	if len(got) == 0 {
		return fmt.Errorf("import: command printed no KEY=VALUE lines")
	}
	keys := make([]string, 0, len(got))
	for k := range got {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if err := c.EditEnv(ref, func(f *libcage.DotenvFile) error {
		for _, k := range keys {
			if got[k] == "" {
				return fmt.Errorf("import: %s is empty", k)
			}
			if err := f.Set(k, got[k]); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return err
	}
	for _, k := range keys {
		fmt.Printf("set %s:%s\n", ref, k)
	}
	return finish(c, *noEncrypt, ref)
}

func cmdKeygen(logger *slog.Logger, wd string, args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	typ := fs.String("type", "ssh-ed25519", "key type (ssh-ed25519)")
	comment := fs.String("comment", "", "key comment")
	noEncrypt := fs.Bool("no-encrypt", false, "do not run encrypt after the change")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("keygen: usage: cage keygen [-type ssh-ed25519] [-comment c] <ref>")
	}
	if *typ != "ssh-ed25519" {
		return fmt.Errorf("keygen: unsupported type %q", *typ)
	}
	ref, err := libcage.ParseSecretRef(fs.Arg(0))
	if err != nil {
		return err
	}
	c, err := rootCage(logger, wd)
	if err != nil {
		return err
	}
	pub, err := c.KeygenSSHEd25519(ref, *comment)
	if err != nil {
		return err
	}
	//> The public key is not secret: it goes to recipients / deploy keys.
	fmt.Println(pub)
	return finish(c, *noEncrypt, ref)
}

func cmdMv(logger *slog.Logger, wd string, args []string) error {
	fs := flag.NewFlagSet("mv", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	noEncrypt := fs.Bool("no-encrypt", false, "do not run encrypt after the change")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return fmt.Errorf("mv: usage: cage mv <ref>:KEY <ref>[:NEWKEY] | cage mv <ref> <newref>")
	}
	if !strings.Contains(fs.Arg(0), ".env:") {
		//> Whole secret rename.
		src, err := libcage.ParseSecretRef(fs.Arg(0))
		if err != nil {
			return err
		}
		dst, err := libcage.ParseSecretRef(fs.Arg(1))
		if err != nil {
			return err
		}
		c, err := rootCage(logger, wd)
		if err != nil {
			return err
		}
		if err := c.MoveSecret(src, dst); err != nil {
			return err
		}
		fmt.Printf("moved %s -> %s\n", src, dst)
		return finish(c, *noEncrypt, dst)
	}
	src, key, err := parseVarRef(fs.Arg(0))
	if err != nil {
		return err
	}
	var dst libcage.SecretRef
	newKey := key
	if strings.Contains(fs.Arg(1), ".env:") {
		dst, newKey, err = parseVarRef(fs.Arg(1))
	} else {
		dst, err = libcage.ParseSecretRef(fs.Arg(1))
	}
	if err != nil {
		return err
	}
	c, err := rootCage(logger, wd)
	if err != nil {
		return err
	}
	if err := c.MoveVar(src, key, dst, newKey); err != nil {
		return err
	}
	fmt.Printf("moved %s:%s -> %s:%s\n", src, key, dst, newKey)
	return finish(c, *noEncrypt, src, dst)
}

func cmdRm(logger *slog.Logger, wd string, args []string) error {
	fs := flag.NewFlagSet("rm", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	file := fs.Bool("file", false, "remove the whole secret (plaintext and store file)")
	commented := fs.Bool("commented", false, "remove commented-out assignments of KEY instead of the active one")
	noEncrypt := fs.Bool("no-encrypt", false, "do not run encrypt after the change")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("rm: usage: cage rm <ref>:KEY | cage rm -file <ref>")
	}
	c, err := rootCage(logger, wd)
	if err != nil {
		return err
	}
	if *file {
		ref, err := libcage.ParseSecretRef(fs.Arg(0))
		if err != nil {
			return err
		}
		if envs := c.ReferencedBy(ref); len(envs) > 0 {
			return fmt.Errorf("rm: %s is referenced by envs %s — remove it from cage.yaml first", ref, strings.Join(envs, ", "))
		}
		if err := c.RemoveSecretFiles(ref); err != nil {
			return err
		}
		fmt.Printf("removed %s\n", ref)
		return nil
	}
	ref, key, err := parseVarRef(fs.Arg(0))
	if err != nil {
		return err
	}
	removed := false
	if err := c.EditEnv(ref, func(f *libcage.DotenvFile) error {
		if *commented {
			removed = f.RemoveCommented(key)
		} else {
			removed = f.Remove(key)
		}
		return nil
	}); err != nil {
		return err
	}
	if !removed {
		return fmt.Errorf("rm: %s has no such %s", ref, key)
	}
	fmt.Printf("removed %s:%s\n", ref, key)
	return finish(c, *noEncrypt, ref)
}

func cmdComment(logger *slog.Logger, wd string, args []string) error {
	fs := flag.NewFlagSet("comment", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	text := fs.String("text", "", "comment to put above the variable (replaces the comment block above it)")
	disable := fs.Bool("disable", false, "comment out the variable")
	enable := fs.Bool("enable", false, "uncomment the variable")
	noEncrypt := fs.Bool("no-encrypt", false, "do not run encrypt after the change")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 || (*disable && *enable) || (*text == "" && !*disable && !*enable) {
		return fmt.Errorf("comment: usage: cage comment [-text t] [-disable | -enable] <ref>:KEY")
	}
	ref, key, err := parseVarRef(fs.Arg(0))
	if err != nil {
		return err
	}
	c, err := rootCage(logger, wd)
	if err != nil {
		return err
	}
	if err := c.EditEnv(ref, func(f *libcage.DotenvFile) error {
		switch {
		case *disable:
			if err := f.Disable(key); err != nil {
				return err
			}
		case *enable:
			if err := f.Enable(key); err != nil {
				return err
			}
		}
		if *text != "" {
			return f.Annotate(key, *text)
		}
		return nil
	}); err != nil {
		return err
	}
	fmt.Printf("updated %s:%s\n", ref, key)
	return finish(c, *noEncrypt, ref)
}
