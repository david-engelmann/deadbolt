# Changelog

All notable changes to deadbolt are recorded in this file.

## 0.2.0 on 2026-11-26

- Non-secret `status` operation (`StoreStatus`, `CredentialSummary`, `GrantSummary`, `GrantStatus`) added across library and command line without modifying sealed stores or exposing credential values, grant tokens, or token hashes under `DK-28`.
- Atomic `rekey` operation added across all four custody route pairs (`keychain` and `passphrase`) with in-memory adoption proof verification, rollback cleanup, `DEADBOLT_NEW_PASSPHRASE` support, and symlink-alias keychain preservation under `DK-28`.
- Top-level `-h`, `--help`, `-V`, and `--version` command line flags and standalone child-process secret injection wrapper `examples/redeem_wrapper.py` added under `DK-28`.
- Cross-platform lock identity, macOS and Windows portability CI, auxiliary Linux Secret Service D-Bus session verification, and automated `v0.2.0` release workflows added under `DK-29`.

## 0.1.0 on 2026-11-15

- Scoped capability-token secrets broker over `deadbolt-state/1` with `enroll`, `grant`, `redeem`, `revoke`, `cutoff`, `retire`, and gapless `audit` logging (`DK-1` through `DK-14`).
- At-rest XChaCha20-Poly1305 `deadbolt-envelope/1` encryption under OS keychain custody (`macOS`, `Windows`, `Linux Secret Service`) and Argon2id passphrase fallback, plaintext adoption proofs, credential rotation (`DK-25`), and same-name incarnation replacement (`DK-27`).
