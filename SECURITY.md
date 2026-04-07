# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please report it using [GitHub's private vulnerability reporting](https://github.com/TechnologyAnimal/Test-TlsProtocols/security/advisories/new). Do not open a public issue.

## Code Review

All contributions to this project are reviewed and approved by the sole maintainer before being merged. No code enters the main branch without review.

## Dependencies

- **Go binary:** Zero external dependencies. Uses only the Go standard library (`crypto/tls`, `net`, `encoding/json`, etc.).
- **PowerShell module:** Zero external dependencies. Uses only built-in .NET libraries (`System.Net.Security.SslStream`, `System.Security.Cryptography`).

## Supply Chain

This project is developed and maintained by an individual in the **United States**. It is published under the [Apache License 2.0](LICENSE). There is no sponsoring organization.

For supply chain or Country of Origin (CoO) inquiries, [open a GitHub issue](https://github.com/TechnologyAnimal/Test-TlsProtocols/issues/new).
