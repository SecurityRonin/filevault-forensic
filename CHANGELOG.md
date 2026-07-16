# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.2] - Unreleased

### Changed
- `filevault-core` depends on `forensic-vfs` 0.3 (was 0.2) for the `vfs`
  feature. A pure dependency-requirement bump: the 0.3 breaking change was the
  `FsKind` newtype, which affects only `FileSystem` implementations; the
  `CryptoLayer` contract the `FileVaultLayer` adapter implements is unchanged.

## [0.1.1] - 2026-07-16

### Added
- `filevault-core`: optional `vfs` feature exposing a `forensic-vfs`
  `CryptoLayer` adapter (`FileVaultLayer`) that presents a decrypted FileVault /
  CoreStorage logical volume as a `DynSource`. Off by default; the decryption is
  filevault-core's own audited RustCrypto AES-XTS.

### Changed
- `filevault-core` depends on `forensic-vfs` 0.2 (was 0.1) for the `vfs` feature.

## [0.1.0]

### Added
- `filevault-core` (`use filevault`) — CoreStorage / FileVault 2 (FVDE)
  reader/decryptor for AES-XTS-128 password-protected volumes:
  - Physical-volume-header + metadata parsing; AES-XTS decryption of the
    encrypted CoreStorage metadata.
  - Volume-key derivation: PBKDF2-HMAC-SHA256 → RFC 3394 AES key unwrap (KEK,
    then volume master key); AES-XTS-128 logical-volume sector decryption with a
    logical-sector tweak.
  - `FileVaultVolume::unlock_with_password` with `read_at` and a `Read + Seek`
    decrypted view; `parse_info` / `FileVaultInfo` for password-free metadata.
- `filevault-forensic` — severity-graded `forensicnomicon::report::Finding`
  auditor over parsed metadata: `FVDE-PROTECTOR-INVENTORY`,
  `FVDE-ENCRYPTION-STATE`, `FVDE-WEAK-KDF-ITERATIONS`.
- Validated against pyfvde (libyal libfvde) on the dfvfs `fvdetest` volume;
  panic-free (RustCrypto only, `unsafe` forbidden), fuzzed metadata target,
  100% line coverage.

### Deferred
- APFS-native encryption (macOS 10.13+) — a separate format with no reference
  decryptor; see `docs/DEFERRED.md`.
