# huh

SHELL := /bin/bash
LAKE  ?= lake
BIN   := .lake/build/bin

.PHONY: all build test axioms pipe-test pty-test

all: build

build:
	$(LAKE) build --log-level=warning Huh huh huhd huh-keygen huh-test huh-pty-test

test: build
	$(BIN)/huh-test

axioms: build
	@./scripts/check-axioms.sh

# Needs socat and nc.
pipe-test: build
	@./scripts/pipe-test.sh

# Needs socat and nc.
pty-test: build
	@./scripts/pty-test.sh
