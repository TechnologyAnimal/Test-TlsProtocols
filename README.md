# Introduction

TLS 1.0 and TLS 1.1 have been formally deprecated by [RFC 8996](https://datatracker.ietf.org/doc/html/rfc8996) (March 2021). TLS 1.2 is the minimum acceptable protocol for most services, and TLS 1.3 is recommended. SSL 2.0 and SSL 3.0 have been deprecated for even longer (RFC 6176 and RFC 7568 respectively). This tool helps audit supported TLS protocols on both internal and external systems.

This function will output the SSL/TLS protocols that the client is able to successfully use to connect to a server using fqdn or ip. It also reports negotiated cipher suite information (cipher algorithm, key exchange, hash algorithm, and strengths). It can optionally output remote certificate information and export remote certificates in `.cer` format.

**Note:** By default, certificate validation is enforced. Use `-IgnoreCertificateValidation` only when testing systems with self-signed or otherwise untrusted certificates.

## Usage Examples

```powershell
# Basic protocol test
Test-TlsProtocols -Server "github.com"

# Test specific protocols
Test-TlsProtocols -Server "github.com" -ProtocolName "Tls12", "Tls13"

# Include remote certificate details
Test-TlsProtocols -Server "github.com" -IncludeRemoteCertificateInfo

# Skip certificate validation (e.g. for self-signed certs)
Test-TlsProtocols -Server "internal.example.com" -IgnoreCertificateValidation

# Output as JSON
Test-TlsProtocols -Server "github.com" -OutputFormat Json

# Include error messages for failed protocols
Test-TlsProtocols -Server "github.com" -IncludeErrorMessages
```

### Sample Output

```text
Fqdn                  : github.com
IP                    : 140.82.116.4
Port                  : 443
Tls12                 : True
NegotiatedCipherSuite : TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
FIPSCompliant         : True
CipherAlgorithm       : Aes128
CipherStrength        : 128
KeyExchangeAlgorithm  : DiffieHellman
KeyExchangeStrength   : 0
HashAlgorithm         : None
HashStrength          : 0
```

# Getting Started

## PowerShell Module

1. `Install-Module -Name Test-TlsProtocols`
2. `git clone https://github.com/TechnologyAnimal/Test-TlsProtocols.git`
3. [Direct Download](https://github.com/TechnologyAnimal/Test-TlsProtocols/archive/master.zip)
4. Docker (PowerShell):

```bash
docker build -t test-tlsprotocols .
docker run --rm test-tlsprotocols
docker run --rm test-tlsprotocols "Import-Module Test-TlsProtocols; Test-TlsProtocols -Server 'google.com' -IncludeRemoteCertificateInfo"
```

> **Note:** The `powershell:latest` Docker image does not include a native `linux/arm64` variant. On Apple Silicon Macs, the container runs under Rosetta x86 emulation, which has known incompatibilities with .NET's `SslStream`. The Docker image works correctly on native x86/x64 Linux hosts (servers, CI/CD pipelines, etc.).

## Go Binary

A standalone Go binary is also available — zero dependencies, cross-platform, and native ARM64 support.

### Build

```bash
go build -o test-tls-protocols ./cmd/test-tls-protocols
```

### Usage

```bash
# Basic scan
./test-tls-protocols -server github.com

# Specific protocols
./test-tls-protocols -server github.com -protocol Tls12,Tls13

# JSON output with certificate info
./test-tls-protocols -server github.com -format json -include-cert

# CSV output for multiple ports
./test-tls-protocols -server github.com -port 443,8443 -format csv

# Skip cert validation, show error details
./test-tls-protocols -server internal.example.com -ignore-cert -include-errors

# Export remote certificate
./test-tls-protocols -server github.com -export-cert

# Print certificate to stdout (PEM)
./test-tls-protocols -server github.com -cert-only

# Concurrent protocol testing
./test-tls-protocols -server github.com -concurrent

# FIPS 140-3 compliance check — restrict to FIPS-approved ciphers only
./test-tls-protocols -server github.com -fips

# Batch scan from CSV file (Server,Port columns)
./test-tls-protocols -input-file Example/input.csv -protocol Tls12 -format csv

# Normal scan always reports FIPSCompliant in output
./test-tls-protocols -server github.com -protocol Tls12

# List supported protocols
./test-tls-protocols -list-protocols
```

> See [FIPS.md](FIPS.md) for the full list of FIPS 140-3 approved cipher suites and authoritative NIST references.

### Exit Codes

| Code | Meaning |
| --- | --- |
| `0` | Success |
| `1` | Error (invalid arguments, DNS failure, etc.) |
| `2` | FIPS failure — negotiated cipher is not FIPS 140-3 approved (only with `-fips`) |

### Docker (Go)

The Go Docker image supports native ARM64 and AMD64 — works on all platforms including Apple Silicon Macs.

```bash
docker build -f Dockerfile-go -t test-tls-protocols-go .
docker run --rm test-tls-protocols-go
docker run --rm test-tls-protocols-go -server google.com -protocol Tls12,Tls13 -format json
```

# Build and Test

## PowerShell

Tests are written using the [Pester](https://pester.dev/) v5 Test Framework.

```powershell
Install-Module Pester -MinimumVersion 5.0 -Force
Invoke-Pester
```

## Go

```bash
# All tests (unit + integration)
go test ./pkg/scanner/ -v

# Unit tests only (no network required, fast)
go test ./pkg/scanner/ -v -run TestUnit_

# Static analysis (requires golangci-lint)
golangci-lint run ./...
```

# Contribute

I will gladly merge any pull requests that contributes useful features or improves code quality. Some examples could be:

- Add more Pester or Go tests
- Check enabled SSL/TLS protocols that are enabled on the client
- Add runspaces to support concurrent process threads in PowerShell Version <7

# Security

See [SECURITY.md](SECURITY.md) for the vulnerability disclosure policy, dependency information, and supply chain details.

# Read About TLS

If you want to learn more about TLS, here are some great resources:

- [TLS 1.3 - RFC 8446](https://datatracker.ietf.org/doc/html/rfc8446)
- [TLS 1.3 - Everything you need to know](https://www.thesslstore.com/blog/tls-1-3-everything-possibly-needed-know)
- [TLS 1.2 - RFC 5246](https://datatracker.ietf.org/doc/html/rfc5246)
- [TLS 1.0/1.1 Deprecation - RFC 8996](https://datatracker.ietf.org/doc/html/rfc8996)
- [SslStream Class (.NET)](https://learn.microsoft.com/en-us/dotnet/api/system.net.security.sslstream)
- [NIST SP 800-52 Rev 2 — TLS Guidelines](https://doi.org/10.6028/NIST.SP.800-52r2)
- [FIPS 140-3](https://doi.org/10.6028/NIST.FIPS.140-3)
