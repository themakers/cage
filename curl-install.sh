#!/usr/bin/env bash
set -euo pipefail

SCRIPT_NAME="cage-installer"
REPO_URL="https://github.com/themakers/cage"
BIN_NAME="cage"

err() {
  echo "[$SCRIPT_NAME] error: $*" >&2
  exit 1
}

info() {
  echo "[$SCRIPT_NAME] $*" >&2
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || err "required command not found: $1"
}

usage() {
  cat >&2 <<EOF
Usage:
  $SCRIPT_NAME install-go
  $SCRIPT_NAME install-flake

Designed to be run as:
  curl -fsSL <url> | bash -s -- <command>
EOF
  exit 1
}

install_go() {
  need_cmd go
  need_cmd git

  info "installing via go install"

  CGO_ENABLED=0 go install -tags netgo -ldflags '-extldflags "-static"' "${REPO_URL}@latest"

  info "installed to $(go env GOPATH)/bin/${BIN_NAME}"
}

install_flake() {
  need_cmd nix

  info "installing via nix flake"

  if ! nix --version | grep -q "nix (Nix)"; then
    err "unsupported nix version"
  fi

  nix profile install "${REPO_URL}"

  info "installed via nix profile"
}

main() {
  if [[ $# -lt 1 ]]; then
    usage
  fi

  case "$1" in
    install-go)
      install_go
      ;;
    install-flake)
      install_flake
      ;;
    *)
      usage
      ;;
  esac
}

main "$@"
