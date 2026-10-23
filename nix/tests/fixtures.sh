# Synthetic test fixtures for the NixOS credentials test: a machine key, a
# foreign key and cage ciphertext. Never use real secrets here.
# Usage: fixtures.sh <cage-binary> <out-dir>
set -euo pipefail
cage="$1"
out="$2"
mkdir -p "$out"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
export HOME="$work/home"
mkdir -p "$HOME"

ssh-keygen -q -t ed25519 -N "" -C machine -f "$out/machine"
ssh-keygen -q -t ed25519 -N "" -C other -f "$out/other"

mkdir "$work/proj"
cd "$work/proj"
"$cage" init
cat >.cage/cage.yaml <<EOF
kind: cage/v1
dirs:
  default: .cage/secrets
recipients:
  machine:
    - $(cat "$out/machine.pub")
  other:
    - $(cat "$out/other.pub")
envs:
  app:
    files: [db.env, api.env]
    recipients: [machine]
  blob:
    files: [tls-key]
    recipients: [machine]
  foreign:
    files: [foreign.env]
    recipients: [other]
EOF
mkdir -p .cage/secrets
printf 'USER=app\nPASSWORD=SYNTHETIC-db-v1\n' >.cage/secrets/db.env
printf 'TOKEN=SYNTHETIC-api\n' >.cage/secrets/api.env
printf 'SYNTHETIC-blob\n' >.cage/secrets/tls-key
printf 'X=SYNTHETIC-foreign\n' >.cage/secrets/foreign.env
"$cage" encrypt
cp .cage/store/files/default/db.env.cage "$out/db-v1.cage"
cp .cage/store/files/default/api.env.cage "$out/api.cage"
cp .cage/store/files/default/tls-key.cage "$out/tls-key.cage"
cp .cage/store/files/default/foreign.env.cage "$out/foreign.cage"
cp .cage/store/envs/app.cage "$out/app-env.cage"

printf 'USER=app\nPASSWORD=SYNTHETIC-db-v2\n' >.cage/secrets/db.env
"$cage" encrypt
cp .cage/store/files/default/db.env.cage "$out/db-v2.cage"

printf 'not a cage file\n' >"$out/corrupt.cage"
