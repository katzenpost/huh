# huh

SHELL := /bin/bash
LAKE  ?= lake
BIN   := .lake/build/bin

.PHONY: all build test axioms pipe-test pty-test signal-test

all: build

build:
	$(LAKE) build --log-level=warning Huh huh huhd huh-keygen huh-test huh-pty-test

test: build
	$(BIN)/huh-test

axioms: build
	@./scripts/check-axioms.sh

pipe-test: build
	@./scripts/pipe-test.sh

pty-test: build
	@./scripts/pty-test.sh

signal-test: build
	@./scripts/signal-test.sh
