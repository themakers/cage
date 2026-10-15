```
!!! ACHTUNG !!!
GPT-wibecoded concept
Hands off production! (…for now)
```
---

# cage

**cage** is a minimal, file-centric secrets manager built on top of **age** and **SSH keys**.

It encrypts `.env` files and binary blobs, keeps ciphertexts in `.cage/`, and lets you **run commands with secrets without committing or exporting them**.

---

## Core ideas

* 🔐 Encryption via **age + SSH public keys**
* 📁 Plaintext secrets live anywhere in the repo, ciphertexts live in `.cage/`
* 🧩 Two secret types:

    * `*.env` — dotenv files
    * everything else — binary blobs
* 🧠 Access control defined declaratively in `.cage/cage.yaml`
* 🚫 No agents, servers, vaults, or background daemons

---

## Install (one-liner)

using `go`:
```bash
curl -fsSL https://raw.githubusercontent.com/themakers/cage/master/curl-install.sh | bash -s -- install-go
```

using `nix`:
```bash
curl -fsSL https://raw.githubusercontent.com/themakers/cage/master/curl-install.sh | bash -s -- install-flake
```

---

## Quick start

```bash
cage init              # create .cage/cage.yaml
cage encrypt           # encrypt all secrets
cage decrypt           # decrypt secrets you are a recipient of (others are skipped)
cage whoami            # which recipients of cage.yaml you are
```

---

## Run with secrets (no export)

```bash
cage run @dev - npm start
cage run secret.env - ./app
```

Secrets are loaded into the process environment only. Secret values in the
command's stdout/stderr are masked (`****************`) unless stdin and
stdout are a terminal; `-no-mask` disables masking.

`PREFIX_=ref` prefixes the variables of a secret (one consumer, several
accounts of the same shape). The same variable name coming from two
different secrets is an error, not a silent override.

---

## Dump secrets

```bash
cage dump -o .env @dev                 # all .env secrets of an env
cage dump -o app.env config.env        # a single secret
cage dump -o file ./file.bin.cage      # a blob (raw bytes)
cage dump -o db.env DB_=ops:db.env     # prefixed variables
```

Values are written only to an explicit file (0600); `-o /dev/stdout` is a
deliberate choice. `.env` and blobs cannot be mixed in one dump.

---

## Inspect and edit without seeing values

Designed for LLM agents (and screen-sharing humans): nothing below prints a
secret value. Agents: read `cage skill`.

```bash
cage status                                # plaintext vs store, readability, env conflicts
cage inspect ops:db.env                    # shape, length, fingerprint, duplicates per variable
cage set -gen random:base64:32 db.env PASSWORD
cage set -plain s3.example.com db.env ENDPOINT
printer | cage set -stdin db.env TOKEN
cage import -with admin.env new.env - sh -c 'curl … | jq -r "\"TOKEN=\"+.token"'
cage keygen -comment ci ops:ci-key         # prints the public key
cage mv old.env:KEY new.env:NEW_KEY
cage rm db.env:LEGACY
cage comment -text "rotated monthly" db.env:PASSWORD
```

Fingerprints are HMACs keyed per run: equal values are visible as equal
within one report, but cannot be checked against a guess. Every edit keeps
comments and order, validates the file and runs `encrypt`.

---

## Working together

Each working copy remembers the store version its plaintext came from (the
base, `.cage/local/`, git-ignored), and every store file lists the hashes
of its previous versions. With that:

* `cage decrypt` updates files you did not change, keeps your changes when
  the store did not change, and merges both line by line otherwise —
  overlapping changes get git-style markers (`<<<<<<< local` … `>>>>>>> store`),
  and the command fails after processing everything;
* `cage encrypt` refuses (and writes nothing) while the store has changes
  you have not merged, or a file has conflict markers — so nobody silently
  reverts someone else's change;
* `cage resolve -local|-store <ref>` settles a conflict;
* a git conflict in a store file: `git checkout --theirs <file>`, then
  `cage decrypt` merges your change, `cage encrypt`, commit;
* revoking access: old versions stay in git history — rotate the secrets.

Everyone in the team should use a cage version with this support: an older
cage drops the version history from store files it rewrites.

---

## Raw mode (outside cage root)

```bash
cage decrypt -raw secrets/*.cage -o ./out
cage run -raw ./config.env.cage - ./app
```

---

## Configuration

All access rules live in:

```
.cage/cage.yaml
```

You define:

* where plaintext secrets live (`dirs`, inside `.cage/`; cage keeps
  `.cage/.gitignore` ignoring them)
* who can decrypt them (`recipients`)
* which secrets belong to which environment (`envs`)

Ciphertexts are stored in:

```
.cage/store/
```

---

## What cage is *not*

* ❌ Not a vault
* ❌ Not a key manager
* ❌ Not a secret sync tool

It’s just **files + crypto + clear rules**.
