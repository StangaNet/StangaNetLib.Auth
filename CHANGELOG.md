# Changelog

All notable changes to **StangaNetLib.Auth** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- Add `net10.0` target framework alongside `net8.0` and `net9.0`.
- Require .NET SDK 10 (global.json) to multi-target `net8.0` / `net9.0` / `net10.0`; opt in Microsoft.Testing.Platform as the `dotnet test` runner.
- Remove redundant Microsoft.Extensions.* PackageReferences from ASP.NET Core projects (provided by Microsoft.AspNetCore.App; avoids NU1510 under the .NET 10 SDK).

## [1.1.0] - 2026-10-21

### Added
- External identity token exchange: `IExternalIdentityProvider`, `IExternalIdentityService`, and `ExternalIdentity`.
- Providers for Google, Apple, and Microsoft (OIDC ID token / JWKS) and Facebook (Graph `debug_token` + `/me`).
- DI: `AddStangaNetLibAuthExternalGoogle` / `Apple` / `Facebook` / `Microsoft` with options under `Auth:External:*`.
- Package dependency on `Microsoft.IdentityModel.Protocols.OpenIdConnect` 8.23.0.

### Fixed
- README pipeline quick-start now documents `UseStangaNetLibAuth` (replacing the outdated `UseStangaNetLibAuthTokenRevocation` name).

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

[Unreleased]: https://github.com/StangaNet/StangaNetLib.Auth/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/StangaNet/StangaNetLib.Auth/compare/v1.0.1...v1.1.0
[1.0.1]: https://github.com/StangaNet/StangaNetLib.Auth/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/StangaNet/StangaNetLib.Auth/releases/tag/v1.0.0
