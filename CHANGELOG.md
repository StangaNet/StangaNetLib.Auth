# Changelog

All notable changes to **StangaNetLib.Auth** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.1] - 2026-10-17

### Fixed
- Depend on `StangaNetLib.Caching` 1.0.1 (ME 8.x graph). The feed's Caching 1.0.0 nuspec pulled ME 10.x and caused NU1605 downgrade errors under `TreatWarningsAsErrors`.

## [1.0.0] - 2026-10-17

### Added
- Self-signed JWT (HMAC-SHA256) with per-device refresh token rotation.
- BCrypt password hashing (SHA-512 pre-hash) via `IPasswordHasher`.
- Cache-backed access-token revocation blacklist (`ITokenRevocationService` + middleware).
- Auth0 RS256 / JWKS validation and optional Management API client.
- DI registration (`AddStangaNetLibAuth` / `AddStangaNetLibAuth0` / …) with options validation.
- Dual targeting `net8.0` / `net9.0`, XML docs, symbols (`snupkg`), package icon, and MSBuild consumer metadata stamp.
- Depends on `StangaNetLib.Caching` 1.0.0 and `StangaNetLib.Resilience` 1.0.0; Microsoft.Extensions.* pinned to 8.x.
- CI via shared StangaNet reusable workflow (push / PR / manual; publish outside PRs).

[Unreleased]: https://github.com/StangaNet/StangaNetLib.Auth/compare/v1.0.1...HEAD
[1.0.1]: https://github.com/StangaNet/StangaNetLib.Auth/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/StangaNet/StangaNetLib.Auth/releases/tag/v1.0.0
