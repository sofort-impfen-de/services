.PHONY: all test clean build install examples

SHELL := /bin/bash

GOFLAGS ?= $(GOFLAGS:)

export KIEBITZ_TEST = yes

KIEBITZ_TEST_SETTINGS ?= "$(shell pwd)/settings/test"

all: dep install

build:
	@go build $(GOFLAGS) ./...

dep:
	@go get ./...

install:
	@go install $(GOFLAGS) ./...

test: dep
	KIEBITZ_SETTINGS=$(KIEBITZ_TEST_SETTINGS) go test $(testargs) `go list ./...`

test-races: dep
	KIEBITZ_SETTINGS=$(KIEBITZ_TEST_SETTINGS) go test -race $(testargs) `go list ./...`

bench: dep
	KIEBITZ_SETTINGS=$(KIEBITZ_TEST_SETTINGS) go test -run=NONE -bench=. $(GOFLAGS) `go list ./... | grep -v api/`

clean:
	@go clean $(GOFLAGS) -i ./...

copyright:
	python3 .scripts/make_copyright_headers.py

certs:
	rm -rf settings/dev/certs/*
	rm -rf settings/test/certs/*
	(cd settings/dev/certs; ../../../.scripts/make_certs.sh)
	(cd settings/test/certs; ../../../.scripts/make_certs.sh)
