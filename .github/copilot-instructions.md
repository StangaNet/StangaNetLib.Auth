# StangaNetLib.Auth — Copilot instructions

- JWT (HMAC self-signed) and Auth0 (RS256 / JWKS) authentication, refresh-token rotation, BCrypt hashing, cache-backed revocation.
- Prefer `Result` / `Result<T>` from `StangaNetLib.Core` for Auth0 Management API failures; reserve exceptions for invalid arguments / configuration.
- Keep public APIs documented (`///`) and provider-agnostic at the call site via abstractions in `StangaNetLib.Auth.Abstractions`.
- DI entry points: `AddStangaNetLibAuth`, `AddStangaNetLibAuth0`, `AddStangaNetLibAuth0ManagementService`, `AddStangaNetLibAuthInMemoryTokenStore`.
- Pipeline: `UseStangaNetLibAuthTokenRevocation` after authentication.
- Optional: inject `IResilientExecutor` from `StangaNetLib.Resilience` for Auth0 Management HTTP calls.
- Match existing naming, file-scoped namespaces, and EditorConfig / Roslyn conventions.
- Tests use xUnit v3 + FluentAssertions; cover both `net8.0` and `net9.0` when changing shared behavior.
