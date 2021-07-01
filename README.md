# Kiebitz Services

This repository contains Kiebitz's backend services:

* A **storage** service that stores encrypted user & operator settings and temporary data.
* An **appointments** service that stores encrypted appointment data.

## Installation

To build and install all services into your `GOPATH`, simply run

```bash
make
```

## Basic Setup

Kiebitz needs cryptographic keys and some helper data to function correctly. All of these can be generated using the `kiebitz` command.

First things first: Kiebitz looks for settings in the path given by the `KIEBITZ_SETTINGS` environment variable. For development, settings are in the `settings/dev` subdirectory of the repository. To set up our development environment, we simply run

```bash
source .dev-setup
```

For the commands below we'll assume that `KIEBITZ_SETTINGS` points to the `settings/dev` directory.

### Cryptographic Keys

First, we need to generate various cryptographic keys for signing and encryption. To do this, we simply run

```bash
kiebitz admin keys setup
```

**Warning:** Running this command will overwrite existing key files, potentially rendering all your development data useless, so be careful.

This will generate two files in the Kiebitz settings directory, `002_admin.json` and `003_appt.json`. The former is only for administration purposes and should remain locked away. The latter is for use with the appointments server.

Now we can then generate mediator keys. To do this, we simply run

```bash
kiebitz admin keys mediator > data/secret-mediator-keys.json
```

This will create a JSON data structure with all necessary keys for the mediator. Please be aware that the `provider` and `queue` keys are just copied from the `002_admin.json` file generated before. These keys enable mediators to decrypt provider and queue data.

For the next steps of the setup process we'll need a running backend, so let's start it via

```bash
kiebitz --level debug run all
```

That should start the appointments and storage services. Now we can tell the backend about the newly created mediator keys, which we do via

```bash
kiebitz admin mediators upload data/secret-mediator-keys.json
```

This will sign the public signing and encryption keys of the mediator with the root key and put the signed key material on the backend for publication. Finally, we need to generate queue keys, which we do via

```bash
kiebitz admin queues generate > data/secret-queue-keys.json
```

The queue keys enable providers to decrypt user tokens. The queue keys file contains the public queue keys as well as the encrypted private keys, which only mediators can decrypt with the respective key. To upload the queue keys to the backend, we simply run

```bash
kiebitz admin queues upload data/secret-queue-keys.json
```

That's it! Now we should be able to go to the `/mediator` URL in the frontend, load our mediator key file and verify providers. Providers should be able to sign up, upload their data for verification and get tokens. Users should also be able to sign up and receive invitations.

### ZIP Code Data

ZIP code data helps Kiebitz to estimate distances between zip code areas. There are two files `data/distances.json` and `data/distances-areas.json` that need to be uploaded. We can do this via

```bash
# upload distances for full ZIP codes (used when matching tokens to providers)
kiebitz admin distances upload data/distances.json
# upload distances for ZIP codes areas (used when selecting queues for providers and users)
kiebitz admin distances upload data/distances-areas.json
```

To generate the distances, we can use the `make_distances.py` and `make_area_distances.py` scripts from the `.scripts` folder (normally this is not necessary though):

```bash
python3 .scripts/make_distances.py
python3 .scripts/make_area_distances.py
```

**Note:** We can test the system without the ZIP code data, but tokens will then only be distributed to matching zip codes.

## Signup Codes

You can also upload user & provider codes if you want to restrict who can register on the platform (this requires setting `appointments.user_codes_enabled: true` and `appointments.provider_codes.enabled: true`, respectively):

```bash
# upload user codes from a file
kiebitz admin codes upload data/secret-user-codes.json
# upload provider codes from a file
kiebitz admin codes upload data/secret-provider-codes.json
```

To generate codes, simply run

```bash
# generate 10.000 user codes
kiebitz admin codes generate --actor user -n 10000 > data/secret-user-codes.json
# generate 10.000 provider codes
kiebitz admin codes generate --actor provider -n 10000 > data/secret-user-codes.json
```

Codes are just random 16 byte values, and the `actor` parameter just tells the backend for which actor the codes should be used.

### TLS Certificates

Finally, if we want to run Kiebitz using a self-signed TLS certificate, we simply run

```bash
make certs
```

to generate these certificates, and then enable them by commenting out the `tls` section in the settings.

## Running

To run the development services is easy:

```bash
# run the appointments service
kiebitz run appointments
# ...or run the storage service
kiebitz run storage
# ...or run all services
kiebitz run all
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