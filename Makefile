SHELL := /usr/bin/env bash
default: help


.PHONY:
build:  ## Build static executable
	CGO_ENABLED=0 go build -tags netgo -ldflags '-extldflags "-static"'

.PHONY:
install:  ## Build static executable and install it in $GOBIN
	CGO_ENABLED=0 go install -tags netgo -ldflags '-extldflags "-static"'

.PHONY:
flake:  ## Build nix flake
	nix flake update
	nix build .#cage


.PHONY: help
help: ## show this help
	@awk '\
	/^[a-zA-Z0-9_.-]+:/ { \
		t=$$0; sub(/:.*/,"",t); \
		if (t ~ /^\./) next; \
		h=""; \
		if ($$0 ~ /[[:space:]]##[[:space:]]+[^[:space:]]/) { \
			h=$$0; sub(/.*[[:space:]]##[[:space:]]+/,"",h); \
			sub(/[ \t]+$$/,"",h); \
		} \
		printf "\x1b[36m  %-25s\x1b[0m %s\n", t, h; \
	}' $(MAKEFILE_LIST)
