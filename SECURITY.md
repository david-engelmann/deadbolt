# Security Policy

## Supported Versions

Security fixes land on the `0.2.x` release line. Versions prior to `0.2.0` do not receive security patches.

## Security Model

Deadbolt seals credentials, scoped grants, and the audit trail inside an XChaCha20-Poly1305 `deadbolt-envelope/1` envelope on disk under an exclusive advisory lock, gated by owner-only `0600` file permissions on Unix. Unlock keys live in the operating system keychain or derive per invocation from Argon2id in zeroizing memory, and grant tokens stand on disk only as SHA-256 digests. Deadbolt ships zero Python binding and zero network daemon so raw credential material stays isolated from in-process agent runtimes.

## Reporting a Vulnerability

Do not open a public issue for a suspected security vulnerability. Report vulnerabilities privately through [GitHub Security Advisories](https://github.com/david-engelmann/deadbolt/security/advisories/new) with synthetic test values only, the affected version, and the contract obligation involved. Every report receives an initial review within seven days, and confirmed fixes ship with a regression pin in the test suite before public disclosure.
