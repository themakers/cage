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
- `cage status` — every secret: sync state (in-sync, modified, outdated,
  diverged, conflict, new, local-only) with a hint what to run, readable or
  not, envs, recipients; plaintext files not in any env; compiled envs out
  of date; variable collisions inside envs (they matter only for envs that
  are run/dumped as a whole — envs may also just group recipients).
- `cage inspect [refs|@env]` (no args — everything) — per variable: line,
  name (`#NAME` = commented out), comment above it, shape (empty, string,
  number, bool, uri, jwt, pem, ssh-public-key), length, charset and a
  fingerprint. URIs are split: scheme, user, hosts, path, query keys open;
  the password only as length + fingerprint. Equal fingerprints within one
  report mean equal values (`DUP:` lists the other places). Fingerprints are
  keyed per run: they cannot be compared across runs or brute-forced.
- `-json` on all of them for machine-readable output.

## Working together (plaintext ↔ store)

cage remembers, per working copy, the store version your plaintext was last
synchronized with (the base, in `.cage/local/`, git-ignored). So:

- `cage decrypt` never loses local changes: store newer and your file
  unchanged → updated; your file changed and store unchanged → kept; both
  changed → merged line by line like git, overlapping changes get markers
  `<<<<<<< local` / `=======` / `>>>>>>> store`. All secrets are processed;
  then it exits with an error listing conflicts (variable names, no values).
- `cage encrypt` (and every editing command) refuses, writing nothing, if
  the store has changes you have not merged (`run cage decrypt first`) or a
  file has conflict markers.
- Conflicts: `cage resolve -local <ref>` or `-store <ref>` keeps one side in
  every conflict of the secret (a human may edit the file instead). Binary
  secrets are not merged: the store version is put next to the file as
  `<name>.store`; resolve the same way.
- Routine: `git pull` → `cage decrypt` → change → `cage encrypt` → commit,
  push.
- git conflict in a store file (two people encrypted the same secret):
  `git checkout --theirs <that file>` (also for `.cage/store/envs/*`), then
  `cage decrypt` (merges your change into theirs), `cage encrypt`, commit.
- `run`/`dump` read the store: an unencrypted local change is not in effect;
  others' changes are, right after `git pull`.
- Plaintext dirs must be inside `.cage/`; cage rewrites `.cage/.gitignore`
  on encrypt/decrypt to ignore them and `.cage/local/`.

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

## Best Practices Recommendation

Project-specific rules take precedence over the recommendations in this
section. The secret-handling safety rules above always take precedence,
including over project-specific rules: secret values must never enter
an agent's context, chat, or tool output.

### Organize by credential, compose by consumer

- One file per credential: an account, token, related key pair, or other
  independently managed access, together with its connection parameters
  (endpoint, host, database, bucket, region). Avoid monolithic files holding
  unrelated credentials for an entire deployment.
- Keep each secret value in one source file, including commented-out
  assignments. If several consumers or environments use the same credential,
  reference that file from their envs instead of copying its values.
  Repeated non-secret parameters are fine; encrypted env bundles generated
  by cage are not source duplication.
- Use descriptive names such as `<system>-<consumer>-<environment>.env`,
  omitting parts that do not distinguish the credential. Use aliases such
  as `ops`, `ci`, or an engineer's name to organize files, not as access
  boundaries.
- Compose envs from refs. An env may be either a runnable consumer bundle
  or a group used to grant recipients access. Document which it is:
  access groups need not be runnable as a whole.
- Keep variable names collision-free in bundles consumed together.
  For multiple credentials of the same shape, prefix at consumption:
  `cage dump -o service.env ROOT_=ops:db-root.env APP_=db-app-prod.env`.
  Do not copy a secret merely to give its variables different names.
- Explain purpose and non-obvious choices in comments, without values.
  A retained disabled block should say why it is kept and when it can be
  removed. Prefer revoking and removing obsolete credentials to keeping
  unexplained historical copies.

### Separate identities and limit access

- Use separate credentials for applications, CI, backups, administrators,
  and individual engineers; separate development and production access
  where supported. Give each credential only the permissions it needs.
- Encrypt personal credentials only for their owner unless the project
  explicitly requires recovery or shared access. Keep service credentials
  separate from personal ones.
- Grant each recipient only the files it needs. A source file's recipients
  are the union of recipients from every env referencing it: adding a ref
  to an env can expand access to that file. Review that union, not just
  directory names or one env in isolation.
- When onboarding someone, configure their public identity, personal alias
  and recipient env before provisioning credentials into cage. Keep the
  project's provisioning commands and access matrix in project docs.

### Deliver without exposing values

- For local commands, use `cage run` with the smallest required set of refs
  or a task-specific env. For services requiring env files, use
  `cage dump -o` into a protected runtime location; keep plaintext out of
  source control, build outputs, caches, and deployment artifacts.
- Deliver encrypted store files or compiled env bundles to servers and
  decrypt at runtime with the server's identity. Do not bake plaintext
  secrets or private decryption identities into images or Nix store paths.
- Bootstrap CI with a dedicated cage recipient. Keep its private identity
  in the CI platform's protected secret store; keep application and task
  credentials in cage instead of duplicating them as CI secrets.
  For example, GitHub Actions can hold one `CAGE_SSH_IDENTITY` bootstrap
  secret while workflows consume separate `@ci-deploy` and `@ci-notify`
  bundles.
- Centralize CI loading in a reviewed action or script. Use `cage run`
  directly where possible. If credentials must persist across steps,
  transfer them through protected runner files or the platform's environment
  mechanism without printing values, and register platform log masks before
  any consumer runs. Do not use `--no-mask` or stdout dumps in agent commands.
- Do not expose the CI identity to untrusted pull requests or jobs.
  Remove temporary identity and plaintext files when finished. If a recovery
  copy of the CI identity is kept in cage, encrypt it for authorized
  maintainers, not for the CI recipient itself.

### Verify the result

- Use a consistent cage version across collaborators and automation.
  Follow the synchronization workflow above before editing; remember that
  `run` and `dump` consume the encrypted store, not unencrypted local edits.
- Check `cage status` and `cage inspect` after changes: intended recipients,
  synchronized files and bundles, unreferenced plaintext, duplicate values,
  and collisions in runnable envs.
- Compare fingerprints within one inspect report only. Treat `DUP` as a
  review signal, not an instruction to delete: equal non-secret parameters
  or empty values do not imply duplicated credentials.
- Review and commit configuration and encrypted store changes together.
  Updating cage alone does not rotate a provider credential, revoke an old
  credential, or reload a running service; coordinate those steps with the
  affected consumers.
