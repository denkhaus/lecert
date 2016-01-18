# lecert

This tool uses the LE CA and the ACME protocol to generate a certificate, CSR, and sign it. If you already have a CSR that can be used as well.

## Install

Installation can be done with `go get`

```bash
go get -u github.com/denkhaus/lecert
```

## Usage

Note that should you need to include the full certificate chain, the `--chain` option will include ALL LetsEncrypt certificates in the output.

### Generating a new certificate

You will need to temporarily make port 80 available and have sudo/root access to the server your domain(s) point to.

```bash

lecert generate --chain example.com
# example.com.crt.pem and example.com.key.pem should be in the current directory
```

You can now move and/or reference `example.com.crt.pem` and `example.com.key.pem` from your TLS services.


### Using an existing CSR

When using an existing CSR, the tool will automatically use the CommonName, so the domain name doesn't need to be specified.

```bash

lecert sign ./example.csr
# example.com.crt.pem should be in the current directory
```


### Advanced

The full set of options can be printed by running `lecert help`

```
Simple utility for generating signed TLS certificates.

Usage:
  lecert [command]

Available Commands:
  generate    Generate and sign new certificate(s).
  sign        Fulfill existing CSR(s).
  verify      Verify existing certificate(s).
  renew       Renew existing certificate(s).
  ensure      Create non existing certificate(s) or renew if necessary.

Flags:
  -k, --account-key string   ACME account key (PEM format). The account key to use with this CA. If it doesn't exist, one will be generated. (default "acme.key")
  -u, --acme-url string      ACME URL. URL to the ACME directory to use. (default "https://acme-v01.api.letsencrypt.org/directory")
  -b, --bind string          Bind address. The binding address:port for the server. Note, port 80 on the domain(s) must be mapped to this address. (default ":80")
      --bits int             Bits for RSA key generation. (default 4096)
      --chain                Include full chain. If set, download and include all LE certificates in the chain.
  -h, --help                 help for lecert
  -d, --output-dir string    Output directory. Certificates and keys will be stored here. (default ".")
  -v, --verbose              Verbose mode. Logs extra messages for debugging.

Use "lecert [command] --help" for more information about a command.


```
