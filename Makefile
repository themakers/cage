SHELL := /usr/bin/env bash

.PHONY:
build:
	CGO_ENABLED=0 go build -tags netgo -ldflags '-extldflags "-static"'

.PHONY:
flake:
	nix flake update
	nix build .#cage
