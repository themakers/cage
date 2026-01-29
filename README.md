```
!!! ACHTUNG !!!
GPT-wibecoded concept
Hands off production! (…for now)
```

# cage — Minimal SSH-based secrets manager

`cage` is a lightweight, transparent secret manager that encrypts files using your existing **SSH Ed25519 keys** and the modern [age](https://github.com/FiloSottile/age) encryption scheme.

---

💡 **Philosophy:** simple, auditable, and secure by default — *just secrets under your SSH control.*

## Features

- 🔐 **Strong crypto** — X25519 + ChaCha20-Poly1305 via `age`
- 🪶 **Uses your SSH keys** — no new key infrastructure or GPG mess
- 🧩 **Declarative config** — `.cage.yaml` defines environments and recipients
- ⚡ **One blob per file** — no ciphertext duplication across recipients
- 🧱 **Git-friendly** — deterministic YAML output, safe to commit
- 🧰 **Simple CLI**
  - `cage encrypt` — encrypt listed files
  - `cage decrypt` — decrypt all `.cage` files for your SSH key
  - `cage dump <env>` — stream decrypted environment files to stdout
- 🧑‍💻 **CI/CD ready** — ideal for self-hosted, GitOps, and minimal workflows

## Example

```bash
# Encrypt secrets for all environments
cage encrypt

# Decrypt locally with your SSH key
cage decrypt

# Export merged plaintext for CI
cage dump dev-local > .env

# Or even
go run github.com/themakers/cage@latest dump dev-local
````

## `.cage.yaml`:
```yaml
recipients:
  john:
    - ssh-ed25519 AAAAC3Nza... easy@peasy
    - ssh-ed25519 AAAAC3Nza... bob@alice
  june:
    - ssh-ed25519 AAAAC3Nza... hello@kitty

envs:
  prod:
    files:
      - s3.prod.env
      - telegram-bot.env
    recipients:
      - john
  dev-local:
    files:
      - s3.mino.env
    recipients:
      - john
      - june
```

## Encrypted `*.cage` file

```yaml
cipher:
  payload: <base64 of age ciphertext>
  recipients:
    - ssh-ed25519 AAAAC3Nza... hello@kitty
    - ssh-ed25519 AAAAC3Nza... bob@alice
    - ssh-ed25519 AAAAC3Nza... easy@peasy
```
