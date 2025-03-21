# Private PKI Demo

## Overview

Private Public Key Infrastructure (PKI) allows organizations to manage and distribute cryptographic keys and certificates internally, ensuring secure communication through mutual authentication.

This demo illustrates how to set up a secure environment using mutual TLS (mTLS), where both server and client authenticate each other using certificates.

## Roles

### Leader (Private CA)

The Leader node acts as a private Certificate Authority (CA) responsible for:

- Generating a self-signed Root CA certificate.
- Receiving, validating, and signing Certificate Signing Requests (CSRs) from Worker nodes.

### Worker

Worker nodes are responsible for:

- Generating CSRs.
- Operating an HTTPS server configured with mutual TLS, validating peer certificates against the Leader's Root CA.

## Usage

### Build the project

```sh
cargo build
```

### Generate a Root CA in the Leader

```console
$ target/debug/leader cert gen --common-name 'Leader CA' -o ./certs --log-level debug
2025-03-21T08:42:41.846461Z  INFO leader::cert: Generating Root Certificate Authority for 'Leader CA
2025-03-21T08:42:41.846886Z  INFO shared::cert: Writing PEM certificate and key pair to 'certs'
2025-03-21T08:42:41.846984Z  INFO leader::cert: Root CA generated successfully

```

### Generate a Certificate Signing Request (CSR) in the Worker

```console
$ target/debug/worker cert csr --common-name 'worker' -o ./certs --log-level debug
2025-03-21T08:46:20.474382Z  INFO worker::cert: Generating Certificate Sign Request (CSR) for 'worker'
2025-03-21T08:46:20.474838Z  INFO shared::cert: Writing PEM certificate and key pair to './certs'
2025-03-21T08:46:20.475568Z  INFO worker::cert: CSR generated successfully

```

### Sign the Worker's CSR using the Leader's Root CA

```console
$ target/debug/leader cert sign --ca-cert ./certs/ca_cert.pem --ca-key ./certs/ca_key.pem --csr ./certs/worker_cert.pem --signed-cert ./certs/worker_cert_signed.pem
2025-03-21T08:48:05.778248Z  INFO shared::cert: Signing CSR
2025-03-21T08:48:05.778456Z  INFO leader::cert: Certificate signed successfully

```

### Start the Worker HTTP server with TLS using the signed certificate

```console
$ target/debug/worker server --cert ./certs/worker_cert_signed.pem --key ./certs/worker_key.pem
2025-03-21T08:50:06.202542Z  INFO worker::server: Starting the worker server...
2025-03-21T08:50:06.202867Z  INFO TlsServer::run{addr=127.0.0.1:3030}: warp::server: listening on https://127.0.0.1:3030

```

### Validate the HTTPS connection using the Leader node

In a new console window:

```console
$ target/debug/leader validate --address https://localhost:3030 --ca-cert ./certs/ca_cert.pem
2025-03-21T08:51:25.487776Z  INFO leader::validate: Validating the worker TLS... address=https://localhost:3030/
2025-03-21T08:51:25.498365Z  INFO leader::validate: Connection successfull! text=OK

```
