package main

import (
	_ "embed"
	"fmt"
	"io"
)

//go:embed skill.md
var skillText string

func printUsage(w io.Writer) {
	fmt.Fprint(w, `Usage:
  cage [ -wd <cage-root> ] <command>

LLM agents: read the output of `+"`cage skill`"+` before using cage.

Look (no values are printed):
  cage whoami                 recipients of cage.yaml you are
  cage status                 plaintext vs store, readability, conflicts
  cage inspect [refs|@env]    variables: shape, length, fingerprint, duplicates
  cage skill                  instructions for LLM agents

Change (edits plaintext, then encrypts; -no-encrypt to batch):
  cage set (-gen spec | -stdin | -plain value) [-comment t] <ref> <KEY>
  cage import [-with ref]... <ref> - <cmd...>    store KEY=VALUE lines from cmd stdout
  cage keygen [-comment c] <ref>                 new ssh-ed25519 key; prints public key
  cage mv <ref>:KEY <ref>[:NEWKEY] | cage mv <ref> <newref>
  cage rm [-commented] <ref>:KEY | cage rm -file <ref>
  cage comment [-text t] [-disable | -enable] <ref>:KEY

Use:
  cage run [-raw] [-no-mask] <secrets...> - <cmd...>
      Run command with variables from secrets. Secret values in its
      stdout/stderr are masked unless stdin and stdout are a terminal.
      Secrets: refs, @env, "PREFIX_=ref" (prefixed variables); raw mode:
      *.cage files or directories.
  cage dump -o <file> <items...>
      Write secrets to a file (0600). Items: refs, @env, *.cage files,
      "PREFIX_=item". The same variable from two secrets is an error.

Maintain:
  cage encrypt                publish local changes; refuses if the store is newer
  cage decrypt                update from the store, merging local changes (git-style
                              conflict markers where both sides changed the same lines)
  cage resolve (-local | -store) <ref>   keep one side in every conflict
  cage decrypt -raw <*.cage files or dirs> -o <dir>
  cage init                   create .cage/cage.yaml and .cage/.gitignore

Notes:
  - secret ref: name.env or alias:name.env; variable ref: <ref>:KEY.
  - cage root is a directory containing .cage; without -wd it is searched
    up from the current directory.
`)
}
