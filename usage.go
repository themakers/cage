package main

import (
	"fmt"
	"io"
)

func printUsage(w io.Writer) {
	fmt.Fprintln(w, `Usage:
  cage [ -wd <cage-root> ] <command>

Commands:
  cage encrypt
      Encrypt all secrets and compile environments according to .cage/cage.yaml.

  cage decrypt
      Decrypt all secrets according to .cage/cage.yaml.

  cage decrypt -raw <paths to *.cage files or directories> -o <output dir>
      Decrypt explicit *.cage files/directories outside cage root.

  cage dump <items...>
      Dump specified secrets to stdout.
      Items may be:
        - secret ref: name.env or alias:name.env
        - environment: @env-name
        - explicit file: path/to/file.cage
      Mixing .env secrets and blobs is not allowed.

  cage run [-raw] <secrets...> - <cmd...>
      Run command with environment variables from secrets.
      In non-raw mode, <secrets...> may include secret refs and @env.
      In raw mode, <secrets...> are *.cage files or directories.

  cage init
      Create a base .cage/cage.yaml in the current directory (or -wd).

Notes:
  - cage root is a directory containing the .cage directory.
  - without -wd, cage searches up from the current directory to find the root.
  - in raw mode, input directories are not recursive.
`)
}
