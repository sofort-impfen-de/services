# Kiebitz Services

This repository contains Kiebitz's backend services:

* A **storage** service that stores encrypted user & operator settings and temporary data.
* An **appointments** service that stores encrypted appointment data.
* An **mediator** service that generates signed data for mediators.

## Installation

To build and install all services into your `GOPATH`, simply run

```bash
make
```

To run the development server(s) you also need TLS certificates. You can generate these using

```bash
make certs
```

## Running

To run the development services is easy:

```bash
source .dev-setup
# run the appointments server
kiebitz run appointments
# ...or run the mediator server
kiebitz run mediator
# ...or run the storage server
kiebitz run storage
```

## Testing

Here's how you can send a request to the storage server via `curl` (this assumes you have `jq` installed for parsing of the JSON result):

```bash
curl --cacert settings/dev/certs/root.crt --resolve storage-1:9999:127.0.0.1 https://storage-1:9999/jsonrpc --header "Content-Type: application/json; charset=utf-8" --data '{"method": "getSettings", "id": "2", "params": {"key": "az4df7vjunsd6ad"}, "jsonrpc": "2.0"}' 2>/dev/null | jq 
```

To run all Go tests and benchmarks, simply

```bash
# run normal tests
make test
# run race-condition tests
make test-races
# run benchmarks
make bench
```

## Development

To auto-generate copyright headers for Golang files, simply run

```bash
make copyright
```