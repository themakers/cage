---
name: cage-infra
description: Integrate cage into infrastructure — deliver secrets to servers and systemd services (pure systemd or the cage NixOS module) without exposing values in environment variables, arguments, logs, the Nix store or on swappable storage.
---

# cage in infrastructure

Read `cage skill` first. Its secret-handling safety rules always take
precedence, including over this document and project-specific rules:
secret values must never enter an agent's context, chat, or tool output.
Project-specific rules take precedence over the recommendations below.

## Model

```text
cage store (ciphertext, in git) ──► server: ciphertext only
  └─ trusted preparer, explicit machine identity
       └─ complete credential set on root-only ramfs
            └─ systemd LoadCredential= ──► service reads $CREDENTIALS_DIRECTORY/<name>
```

- Deliver cage ciphertext (store files or compiled env bundles), never
  plaintext. Decrypt only at runtime, with an explicitly configured machine
  identity: an unencrypted SSH ed25519 key, mode 0600, kept outside
  deployment artifacts and the Nix store and inaccessible to applications.
  Add its public key as a cage recipient of exactly the secrets it needs.
- Run each application under a dedicated unprivileged user. The application
  must not be able to read the identity, choose what is decrypted, or
  influence where privileged code writes.
- Pass secrets as systemd credentials, never through `Environment=`,
  `EnvironmentFile=`, shell exports or command-line values. Paths and
  credential names may appear in environment variables and arguments.
- A credential is one blob or a dotenv bundle (several .env secrets or env
  bundles, optionally prefixed, collision-checked). The application parses
  it into its configuration without modifying its process environment and
  validates required fields before doing any work.
- Keep values out of parser errors, panics, logs, diagnostics and
  configuration dumps; report credential/field names and failure categories.
- `EnvironmentFile=` is only an explicit, documented exception for software
  that cannot read files or credentials: it puts values into the process
  environment and gives weaker isolation.

## The preparer: `cage credentials`

`cage credentials prepare <manifest.json>` decrypts the sources of one unit
with the manifest identity (no other key is ever tried), composes every
credential and atomically publishes the complete set as
`<stagingDir>/<unit>/<name>` (0600). Before composing it removes any
previous set: on failure nothing is published — no partial, no stale set.
`cage credentials clean <manifest.json>` removes the set (idempotent). Both
refuse a staging dir that is not root-owned, private and on ramfs, make
themselves non-dumpable and never print values.

Manifest (no secrets; may live in the Nix store):

```json
{
  "version": 1,
  "unit": "myapp.service",
  "identity": "/etc/ssh/ssh_host_ed25519_key",
  "stagingDir": "/run/cage-credentials",
  "credentials": [
    { "name": "config", "sources": [
        { "path": "/etc/myapp/myapp.cage" },
        { "path": "/var/lib/myapp/extra.cage", "prefix": "EXTRA_" } ] },
    { "name": "tls.key", "sources": [ { "path": "/etc/myapp/tls-key.cage" } ] }
  ]
}
```

Sources are absolute `*.cage` paths. Credential names: `[A-Za-z0-9_][A-Za-z0-9_.-]*`.
Total size per unit is limited to 1 MiB (systemd limit).

## Lifecycle guarantees

- The preparer runs on every start of the consumer, including automatic
  restarts, so a start never uses an older generation than the ciphertext
  on disk. Rotating a runtime source: replace the file, then
  `systemctl restart <unit>`. A reload does not refresh credentials.
- Missing or undecryptable sources fail the preparer and therefore the
  consumer start; there is no fallback to empty or previous values.
- The staging copy exists only between preparation and consumer start: it is
  removed by `ExecStartPost=` (systemd has already copied the credentials)
  and by `ExecStopPost=` (failed starts). If a consumer start job is
  cancelled after preparation, the set stays on the root-only ramfs until
  the next start or stop of that unit.
- The preparer has no start limit of its own; the consumer's start limit
  governs restart rate.

## Memory and disk

- Staging is ramfs (never swapped). systemd credential directories are
  non-swappable where supported. Ordinary tmpfs can be swapped: do not use it.
- The consumer holds values in its heap: forbid swap and core dumps for it
  (`MemorySwapMax=0`, `LimitCORE=0`) and for the preparer.
- A strict "no plaintext ever on disk" policy additionally requires no
  hibernation to persistent storage and no host-level memory/crash dumps of
  these processes. These are host policies: configure them explicitly; the
  integration does not change them silently.

## NixOS + systemd: the cage module

The cage flake exports `nixosModules.cage` (top-level option `cage`;
`services.cage` is an unrelated compositor in nixpkgs). It generates the
manifest, the preparer unit, the ramfs mount and the consumer wiring.

```nix
{ cage, ... }:
{
  imports = [ cage.nixosModules.cage ];

  cage = {
    enable = true;
    identityFile = "/etc/ssh/ssh_host_ed25519_key"; # string: never a Nix path
    services.myapp.credentials = {
      config.sources = [
        ./secrets/myapp.cage                                   # store: ciphertext only
        { path = "/var/lib/myapp/extra.cage"; prefix = "EXTRA_"; } # runtime path
      ];
      "tls.key".sources = [ ./secrets/myapp-tls-key.cage ];
    };
  };

  # The service itself stays yours; the module only adds credential wiring.
  systemd.services.myapp = {
    wantedBy = [ "multi-user.target" ];
    serviceConfig = {
      User = "myapp";
      ExecStart = "/path/to/myapp --config-file %d/config --tls-key %d/tls.key";
    };
  };
}
```

What it generates for `services.<name>`:

- `cage-credentials-<name>.service` — oneshot preparer, root with only
  `CAP_DAC_READ_SEARCH`, sandboxed, writes only the staging dir,
  `MemorySwapMax=0`, `LimitCORE=0`, no start limit;
- `<name>.service` — `Requires=`/`After=` the preparer, `LoadCredential=`
  for every credential, cleanup in `ExecStartPost=`/`ExecStopPost=`, and
  (`memoryProtection`, default on) `MemorySwapMax=0`, `LimitCORE=0`;
- a ramfs mount at `stagingDir` (default `/run/cage-credentials`, mode 0700).

Rules for NixOS configurations:

- Nix evaluation and builds handle only ciphertext, public keys and runtime
  path names. Never `builtins.readFile` a secret, never put values into
  `settings`, scripts or derivation arguments, never reference a private
  key as a Nix path literal (it would be copied into the store).
- Store sources change with the configuration: `nixos-rebuild switch`
  restarts the consumer because its unit changes. Runtime sources are not
  tracked by Nix: rotate them with an explicit restart.
- Keep the consumer unprivileged (the module warns about root units). Do
  not grant it access to the identity or the staging dir.
- For upstream NixOS modules that support `LoadCredential`-style options
  (often `credentials`/`*File` settings pointing at `%d/<name>` or
  `/run/credentials/<unit>/<name>`), wire them to cage credentials instead
  of `EnvironmentFile`.
- `nix flake check` in the cage repository runs a VM test of the module
  (delivery, isolation, automatic restart, rotation, failures, no values in
  env/argv/journal/units). Test your own integration the same way, with
  synthetic secrets only.

## Pure systemd

Same mechanism, written by hand. Install `cage`, the manifest (root-owned,
not writable by others) and the ciphertext, then:

```ini
# /etc/systemd/system/run-cage\x2dcredentials.mount
[Mount]
What=ramfs
Where=/run/cage-credentials
Type=ramfs
Options=mode=0700,nosuid,nodev,noexec
```

```ini
# /etc/systemd/system/cage-credentials-myapp.service
[Unit]
Description=Prepare cage credentials for myapp.service
Before=myapp.service
RequiresMountsFor=/run/cage-credentials
StartLimitIntervalSec=0

[Service]
Type=oneshot
ExecStart=/usr/local/bin/cage credentials prepare /etc/cage/myapp.json
UMask=0077
MemorySwapMax=0
LimitCORE=0
CapabilityBoundingSet=CAP_DAC_READ_SEARCH
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/run/cage-credentials
PrivateTmp=yes
PrivateDevices=yes
PrivateNetwork=yes
RestrictAddressFamilies=AF_UNIX
```

```ini
# /etc/systemd/system/myapp.service.d/cage.conf
[Unit]
Requires=cage-credentials-myapp.service
After=cage-credentials-myapp.service

[Service]
LoadCredential=config:/run/cage-credentials/myapp.service/config
LoadCredential=tls.key:/run/cage-credentials/myapp.service/tls.key
ExecStartPost=+/usr/local/bin/cage credentials clean /etc/cage/myapp.json
ExecStopPost=+/usr/local/bin/cage credentials clean /etc/cage/myapp.json
MemorySwapMax=0
LimitCORE=0
```

- Do not make the preparer `RemainAfterExit=yes`: it must run again on every
  consumer start. Do not prepare credentials in the consumer's own
  `ExecStartPre=`: systemd loads credentials before that.
- `LoadCredential=` paths must be absolute: a missing file then fails the
  start instead of being silently skipped.
- cage ciphertext is not `systemd-creds` ciphertext: never pass a `.cage`
  file to `LoadCredentialEncrypted=`.

## CI and deployment

- Bootstrap CI with a dedicated cage recipient whose private key is the only
  CI-platform secret; everything else comes from cage (see `cage skill`).
- Deployment ships ciphertext and restarts consumers; it never decrypts on
  the deploying machine to upload plaintext.
- Verify after deploying without reading values: unit states
  (`systemctl status`, failed preparers and their journal), credential
  names (`ls /run/credentials/<unit>/` — names only, never read the files),
  and application health checks.
