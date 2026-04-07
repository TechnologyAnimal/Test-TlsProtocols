# FIPS 140-3 Cipher Suite Compliance

This document lists the FIPS 140-3 approved TLS cipher suites used by the `-fips` flag in `test-tls-protocols`. These are derived from the following authoritative NIST publications:

## Authoritative Sources

| Document | Title | Link |
| --- | --- | --- |
| **NIST SP 800-52 Rev 2** | Guidelines for the Selection, Configuration, and Use of TLS Implementations | <https://doi.org/10.6028/NIST.SP.800-52r2> |
| **NIST SP 800-140C** | CMVP Requirements for FIPS 140-3 Validation Testing | <https://doi.org/10.6028/NIST.SP.800-140C> |
| **FIPS 140-3** | Security Requirements for Cryptographic Modules | <https://doi.org/10.6028/NIST.FIPS.140-3> |
| **FIPS 197** | Advanced Encryption Standard (AES) | <https://doi.org/10.6028/NIST.FIPS.197-upd1> |
| **NIST SP 800-38D** | Recommendation for GCM Mode | <https://doi.org/10.6028/NIST.SP.800-38D> |

NIST SP 800-52 Rev 2 (August 2019) is the primary reference for TLS cipher suite selection in FIPS-validated environments. FIPS 140-3 became effective September 22, 2021, replacing FIPS 140-2.

## Approved TLS 1.3 Cipher Suites

All TLS 1.3 cipher suites use AEAD (Authenticated Encryption with Associated Data). The following are FIPS-approved:

| Cipher Suite | IANA Value | FIPS-Approved | Notes |
| --- | --- | --- | --- |
| `TLS_AES_128_GCM_SHA256` | 0x1301 | Yes | AES-128 in GCM mode |
| `TLS_AES_256_GCM_SHA384` | 0x1302 | Yes | AES-256 in GCM mode |
| `TLS_CHACHA20_POLY1305_SHA256` | 0x1303 | **No** | ChaCha20 is not a FIPS-approved algorithm |
| `TLS_AES_128_CCM_SHA256` | 0x1304 | Yes | AES-128 in CCM mode (rarely offered) |

## Approved TLS 1.2 Cipher Suites

Per NIST SP 800-52 Rev 2, Section 3.3.1. Cipher suites are categorized as **required** or **recommended** for FIPS-compliant servers.

### Required (MUST support)

| Cipher Suite | IANA Value | Key Exchange | Encryption | Go Support |
| --- | --- | --- | --- | --- |
| `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` | 0xC02B | ECDHE + ECDSA | AES-128-GCM | Yes |
| `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384` | 0xC02C | ECDHE + ECDSA | AES-256-GCM | Yes |
| `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` | 0xC02F | ECDHE + RSA | AES-128-GCM | Yes |
| `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384` | 0xC030 | ECDHE + RSA | AES-256-GCM | Yes |

### Recommended (SHOULD support)

| Cipher Suite | IANA Value | Key Exchange | Encryption | Go Support |
| --- | --- | --- | --- | --- |
| `TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256` | 0xC023 | ECDHE + ECDSA | AES-128-CBC | Yes |
| `TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256` | 0xC027 | ECDHE + RSA | AES-128-CBC | Yes |
| `TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384` | 0xC024 | ECDHE + ECDSA | AES-256-CBC | No* |
| `TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384` | 0xC028 | ECDHE + RSA | AES-256-CBC | No* |
| `TLS_DHE_RSA_WITH_AES_128_GCM_SHA256` | 0x009E | DHE + RSA | AES-128-GCM | No* |
| `TLS_DHE_RSA_WITH_AES_256_GCM_SHA384` | 0x009F | DHE + RSA | AES-256-GCM | No* |

\* Go's `crypto/tls` does not implement DHE key exchange or AES-256-CBC-SHA384 suites. These are FIPS-approved but cannot be tested with this tool.

## What `-fips` Does

When the `-fips` flag is used:

1. **TLS 1.2**: The client restricts its `ClientHello` to only offer the FIPS-approved cipher suites listed above (those supported by Go).
2. **TLS 1.3**: Go does not allow restricting TLS 1.3 cipher suites via `CipherSuites` config. All three TLS 1.3 suites (including ChaCha20-Poly1305) are always offered. The `FIPSCompliant` output field checks the **negotiated** suite against the FIPS-approved list.
3. **Output**: Every scan (with or without `-fips`) includes a `FIPSCompliant` field indicating whether the negotiated cipher suite is FIPS 140-3 approved.

## Non-FIPS Cipher Suites

The following are explicitly **not** FIPS-approved and will cause `FIPSCompliant: false`:

- Any cipher suite using **ChaCha20-Poly1305** (not a FIPS-approved algorithm)
- Any cipher suite using **RC4** (prohibited by RFC 7465)
- Any cipher suite using **3DES** (deprecated by NIST in 2023)
- Any cipher suite using **NULL** encryption
- Any cipher suite using **export-grade** cryptography
- Any cipher suite without **forward secrecy** (e.g., `TLS_RSA_WITH_*`)

## Deprecated Protocols

FIPS 140-3 does **not** permit:

- SSL 2.0, SSL 3.0 (prohibited)
- TLS 1.0, TLS 1.1 (prohibited per NIST SP 800-52 Rev 2 as of January 2024)

Only **TLS 1.2** and **TLS 1.3** are permitted in FIPS-validated environments.

## Last Updated

This document was last reviewed against NIST SP 800-52 Rev 2 (August 2019) and FIPS 140-3 (effective September 2021). Check the [NIST CMVP page](https://csrc.nist.gov/projects/cryptographic-module-validation-program) for the latest updates.
