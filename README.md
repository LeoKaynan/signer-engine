# signer-engine

`signer-engine` is a Go project for building digital signature primitives and
signature formats, with an initial focus on CMS/CAdES and ICP-Brasil policies.

The project is intentionally being built in small steps. The current codebase is
not a complete production signer yet, but it already contains working pieces for
PKCS#12 credentials, CMS `SignedData`, CAdES signed attributes, and ICP-Brasil
certificate policy validation.

## Current Status

Implemented so far:

- PKCS#12 credential loading from bytes or file.
- In-memory credential abstraction for signing digests.
- CMS `SignedData` generation.
- CAdES signing with:
  - `signing-time`;
  - `signing-certificate-v2`;
  - optional signature policy attributes.
- ICP-Brasil ADRB policy metadata.
- ICP-Brasil signing certificate validation for:
  - CPF or CNPJ subject OID;
  - ICP-Brasil certificate policy OID prefix;
  - certificate chain anchored on embedded ICP-Brasil roots;
  - digital signature key usage;
  - SHA-256 mandated hash algorithm.

Not implemented yet:

- CRL/OCSP revocation validation.
- Trusted timestamp / TSA support.
- Full CAdES profile levels beyond the current basic attributes.
- PAdES and XAdES formats.
- Historical signature validation using trusted signing time.

## Package Layout

```text
internal/cryptoutil
```

Shared cryptographic helpers and OIDs, such as RSA and SHA algorithm OIDs.

```text
internal/signer
```

Common credential abstraction used by signature builders.

```text
internal/signer/pkcs12
```

PKCS#12 credential loading using `software.sslmate.com/src/go-pkcs12`.

```text
internal/signature/cms
```

CMS primitives and `SignedData` builder.

```text
internal/signature/cades
```

CAdES signing layer built on top of CMS.

```text
internal/signature/signaturepolicy
```

Common signature policy contract shared by signature formats.

```text
internal/signature/icpbrasil
```

ICP-Brasil policy implementation and certificate validation.

## Tests

Run all tests:

```bash
go test ./internal/...
```

Some CMS/CAdES tests use OpenSSL to verify interoperability of the generated
CMS signatures:

```bash
openssl cms -verify -noverify
```

PKCS#12 tests generate test P12 data at runtime using Go, so the repository does
not require committed `.p12` fixtures.

## ICP-Brasil Roots

ICP-Brasil root certificates are embedded into the binary from:

```text
internal/signature/icpbrasil/roots/
```

They are used only as the trust anchors for ICP-Brasil certificate chain
validation. Intermediates are expected to come from the credential chain.

## Development Notes

- This project currently targets Go `1.25.5`.
- Tests are designed to avoid real user certificates.
- Test certificates are generated in memory.
- OpenSSL is used only where external CMS interoperability is valuable.

## Roadmap

Likely next steps:

- Add tests for detached signatures.
- Parse and validate CAdES attributes semantically, not only by OID presence.
- Add revocation validation through CRL or OCSP.
- Add timestamp support.
- Expand policy support beyond ADRB.
- Introduce PAdES and XAdES packages using the shared `signaturepolicy` layer.
