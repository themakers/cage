package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"
)

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func cmdInspect(logger *slog.Logger, wd string, args []string) error {
	fs := flag.NewFlagSet("inspect", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	asJSON := fs.Bool("json", false, "JSON output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	c, err := rootCage(logger, wd)
	if err != nil {
		return err
	}
	rep, err := c.Inspect(fs.Args())
	if err != nil {
		return err
	}
	if *asJSON {
		return printJSON(rep)
	}
	for _, f := range rep.Files {
		head := f.Ref + "  [" + f.Source + "]"
		if len(f.Envs) > 0 {
			head += "  envs: " + strings.Join(f.Envs, ", ")
		}
		if f.NotInConfig {
			head += "  NOT IN ANY ENV"
		}
		if f.Error != "" {
			head += "  error: " + f.Error
		}
		fmt.Println(head)
		if f.BlobKind != "" {
			line := fmt.Sprintf("     blob %s size=%d fp=%s", f.BlobKind, f.BlobSize, f.BlobFP)
			if len(f.BlobDups) > 0 {
				line += "  DUP: " + strings.Join(f.BlobDups, ", ")
			}
			fmt.Println(line)
		}
		for _, v := range f.Vars {
			name := v.Key
			if v.Commented {
				name = "#" + name
			}
			line := fmt.Sprintf("  %3d %-36s %s len=%d", v.Line, name, v.Shape, v.Length)
			if v.Charset != "" {
				line += " " + v.Charset
			}
			if v.Fingerprint != "" {
				line += " fp=" + v.Fingerprint
			}
			if v.ParseError != "" {
				line += " PARSE ERROR: " + v.ParseError
			}
			if len(v.Dups) > 0 {
				line += "  DUP: " + strings.Join(v.Dups, ", ")
			}
			fmt.Println(line)
			if u := v.URI; u != nil {
				ul := fmt.Sprintf("        %s://%s@%s%s", u.Scheme, u.User, strings.Join(u.Hosts, ","), u.Path)
				if len(u.QueryKeys) > 0 {
					ul += " ?" + strings.Join(u.QueryKeys, "&")
				}
				if u.PasswordFP != "" {
					ul += fmt.Sprintf(" password(len=%d fp=%s)", u.PasswordLen, u.PasswordFP)
				}
				if len(u.PasswordDups) > 0 {
					ul += "  PASSWORD DUP: " + strings.Join(u.PasswordDups, ", ")
				}
				fmt.Println(ul)
			}
			if v.Comment != "" {
				fmt.Println("        # " + v.Comment)
			}
		}
	}
	return nil
}

func cmdStatus(logger *slog.Logger, wd string, args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	asJSON := fs.Bool("json", false, "JSON output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	c, err := rootCage(logger, wd)
	if err != nil {
		return err
	}
	rep, err := c.Status()
	if err != nil {
		return err
	}
	if *asJSON {
		return printJSON(rep)
	}
	for _, f := range rep.Files {
		r := "readable"
		if !f.Readable {
			r = "NOT READABLE"
		}
		fmt.Printf("%-48s %-15s %-13s recipients: %s\n", f.Ref, f.State, r, strings.Join(f.Recipients, ","))
	}
	for _, s := range rep.NotInConfig {
		fmt.Printf("plaintext not in any env: %s\n", s)
	}
	for _, s := range rep.StoreOrphans {
		fmt.Printf("store file not in any env: %s\n", s)
	}
	for _, cf := range rep.Conflicts {
		fmt.Printf("collision if @%s is run/dumped as a whole: %s defined by %s\n", cf.Env, cf.Var, strings.Join(cf.Sources, ", "))
	}
	return nil
}

func cmdWhoami(logger *slog.Logger, wd string, args []string) error {
	fs := flag.NewFlagSet("whoami", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	asJSON := fs.Bool("json", false, "JSON output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	c, err := rootCage(logger, wd)
	if err != nil {
		return err
	}
	res, err := c.Whoami()
	if err != nil {
		return err
	}
	if *asJSON {
		return printJSON(res)
	}
	fmt.Printf("recipients: %s\n", strings.Join(res.Names, ", "))
	fmt.Printf("groups:     %s\n", strings.Join(res.Groups, ", "))
	for _, k := range res.Keys {
		fmt.Printf("key:        %s\n", k)
	}
	return nil
}
