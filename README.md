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

## Provisioning

For a working system you will need queue data and cryptographic keys. You can generate queues for all zip codes using the `make_queues.py` command to which you pass a file with the encrypted queue keys:

```bash
python3 .scripts/make_queues.py data/queue-keys.json
```

This will generate `queues.json` files in `settings/dev` and `settings/prod`. You can then sign and upload these to the backend via the `admin` command:

```bash
kiebitz admin queues upload settings/dev/queues.json
```

Likewise, you need to store signed mediator key pairs in the backend, which you can do via

```bash
kiebitz admin mediators upload-keys data/mediator-keys.json
```

This should give you a fully functioning backend system. You can e.g. generate `queue-keys.json` and `mediator-keys.json` using the test frontend app.

You can also upload user & provider codes if you want to restrict who can register on the platform (this requires setting `appointments.user_codes_enabled: true` and `appointments.provider_codes.enabled: true`, respectively):

```bash
# upload user codes from a file
kiebitz admin codes upload data/user-codes.json
# upload provider codes from a file
kiebitz admin codes upload data/provider-codes.json
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