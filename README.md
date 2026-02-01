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

```bash
curl -fsSL https://raw.githubusercontent.com/themakers/cage/refs/heads/master/curl-install.sh | bash -s -- install-go
# or
curl -fsSL https://raw.githubusercontent.com/themakers/cage/refs/heads/master/curl-install.sh | bash -s -- install-flake
```

---

## Quick start

```bash
cage init              # create .cage/cage.yaml
cage encrypt           # encrypt all secrets
cage decrypt           # decrypt all secrets (if you have keys)
```

---

## Run with secrets (no export)

```bash
cage run @dev - npm start
cage run secret.env - ./app
```

Secrets are loaded into the process environment only.

---

## Dump secrets

```bash
cage dump @dev                    # dump all .env secrets from env
cage dump config.env              # dump a single secret
cage dump ./file.bin.cage > file  # dump a blob (raw bytes)
```

(`.env` and blobs cannot be mixed in one dump)

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

* where plaintext secrets live (`dirs`)
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
