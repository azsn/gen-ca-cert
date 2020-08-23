### gen-ca-cert

Programmatically generate CA root certificate using OpenSSL libcrypto.

### Build

1. Install OpenSSL libraries. On Mac, use `brew install openssl`.
2. Edit the first few lines in `Makefile` to point to your OpenSSL installation.
3. Run `make` to build the demo executable.
4. Run `make test` to generate a new private key and turn it into a certificate.
