---
name: cage
description: Work with secrets stored in cage (SSH/age-encrypted .env and blob secrets in .cage/) without ever seeing their values — inspect, create, generate, import, move, rename, remove, use in commands.
---

# cage for LLM agents

cage keeps secrets as plaintext files in `.cage/secrets/**` (git-ignored) and
their age-encrypted copies in `.cage/store/**` (committed). `.cage/cage.yaml`
defines dir aliases, recipients (SSH public keys and groups) and envs (bundles
of secrets with their recipients).

## The rule

Secret values must never enter your context. Therefore:

- NEVER read, cat, grep, sed or diff files under `.cage/secrets/` or decrypt
  them yourself. Use the commands below — they print names, shapes and
  fingerprints, never values.
- NEVER put a secret value into a command line argument. Values come from a
  generator (`set -gen`), stdin (`set -stdin`) or another program's stdout
  (`import`), and go into cage files or into a child process environment.
- `****************` (16 asterisks) in output is a masked secret. It is not a
  value: never copy it anywhere. cage refuses to store it.

## Names

- Secret ref: `name.env` (dir alias `default`) or `alias:name.env`; blobs
  (keys, files) have names without `.env`.
- Variable ref: `<ref>:KEY`, e.g. `ops:db.env:PASSWORD`.
- Env: `@env-name`.

## Look

- `cage whoami` — which recipients of cage.yaml you are.
- `cage status` — every secret: plaintext vs store (in-sync / changed /
  plaintext-only / store-only), readable or not, envs, recipients; plaintext
  files not in any env; variable collisions inside envs (they matter only
  for envs that are run/dumped as a whole — envs may also just group
  recipients).
- `cage inspect [refs|@env]` (no args — everything) — per variable: line,
  name (`#NAME` = commented out), comment above it, shape (empty, string,
  number, bool, uri, jwt, pem, ssh-public-key), length, charset and a
  fingerprint. URIs are split: scheme, user, hosts, path, query keys open;
  the password only as length + fingerprint. Equal fingerprints within one
  report mean equal values (`DUP:` lists the other places). Fingerprints are
  keyed per run: they cannot be compared across runs or brute-forced.
- `-json` on all of them for machine-readable output.

## Change

Every change edits the plaintext (comments and order preserved), validates
it and runs `cage encrypt`. Add `-no-encrypt` to batch several edits, then
run `cage encrypt` once. A secret not listed in any env of cage.yaml is not
encrypted — add it to cage.yaml (plain YAML, no values inside) first.

- `cage set -gen random:base64:32 <ref> KEY` — generate (encodings: base64,
  base64url, hex, alnum; size in bytes / characters). `-keep` keeps an
  existing value.
- `cage set -stdin <ref> KEY` — value from stdin (pipe from a program).
- `cage set -plain <value> <ref> KEY` — only for non-secret values
  (endpoint, bucket, region, user name, account id).
- `-comment "text"` on set puts a comment above the variable.
- `cage import [-with <ref|@env>]... <ref> - <cmd...>` — runs the command;
  its stdout must be `KEY=VALUE` lines, they are stored into `<ref>`. stdout
  is never shown; stderr is shown masked. `-with` gives the command existing
  secrets in its environment. Examples:
  - a token created via an API:
    `cage import -with ops:admin.env ops:new.env - sh -c 'curl -s -H "Authorization: Bearer $ADMIN_TOKEN" … | jq -r "\"NEW_TOKEN=\" + .result.value"'`
  - a key pair from any tool:
    `cage import vapid.env - sh -c 'tool keys | jq -r "\"PUB=\"+.pub, \"PRIV=\"+.priv"'`
- `cage keygen [-comment c] <ref>` — new ssh-ed25519 private key as blob
  `<ref>`; prints the public key line (not secret).
- `cage mv <ref>:KEY <ref2>[:NEWKEY]` — move/rename a variable;
  `cage mv <ref> <newref>` — rename a whole secret (update cage.yaml to the
  new name before encrypt).
- `cage rm <ref>:KEY` — delete a variable (`-commented` — its commented-out
  copies); `cage rm -file <ref>` — delete a
  whole secret (remove it from cage.yaml first).
- `cage comment -text "…" <ref>:KEY` (`-commented` — above the first
  commented-out assignment, i.e. a disabled block), `-disable` (comment out),
  `-enable`.

## Use

- `cage run <refs|@env|PREFIX_=ref>... - <cmd...>` — runs the command with
  the variables in its environment. stdout and stderr of the command are
  masked (`****************`) unless stdin and stdout are a terminal.
  `$VAR` as a whole argument is substituted. Use `sh -c '…'` for anything
  more complex; if the command produces data that contains secrets, let the
  command itself write it to a file (`sh -c 'cmd > file'`) — masking applies
  only to what cage prints.
- `PREFIX_=ref` prefixes the variables of that secret (several accounts of
  the same shape for one consumer).
- The same variable name coming from two different secrets is an error.
- `cage dump -o <file> <refs|@env>` — writes values to a file (0600) for
  services that read env files. Do not dump to stdout.

## Don'ts

- Do not `cage run --no-mask` and do not `dump -o /dev/stdout`: both print
  values into your context.
- Do not echo/print variables inside `cage run` (masked output is useless,
  and with `--no-mask` it is a leak).
- Do not create plaintext files under `.cage/secrets/` with your file tools
  if their content would include values — use `set`/`import`.
