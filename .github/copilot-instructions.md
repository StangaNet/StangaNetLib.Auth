# StangaNetLib.Auth — Copilot instructions

- JWT (HMAC self-signed) and Auth0 (RS256 / JWKS) authentication, refresh-token rotation, BCrypt hashing, cache-backed revocation, and external identity token exchange (Google, Apple, Facebook, Microsoft).
- Prefer `Result` / `Result<T>` from `StangaNetLib.Core` for Auth0 Management API and external identity validation failures; reserve exceptions for invalid arguments / configuration.
- Keep public APIs documented (`///`) and provider-agnostic at the call site via abstractions in `StangaNetLib.Auth.Abstractions`.
- DI entry points: `AddStangaNetLibAuth`, `AddStangaNetLibAuth0`, `AddStangaNetLibAuth0ManagementService`, `AddStangaNetLibAuthInMemoryTokenStore`, `AddStangaNetLibAuthExternalGoogle` / `Apple` / `Facebook` / `Microsoft`.
- Pipeline: `UseStangaNetLibAuth` after routing (authentication + revocation middleware + authorization).
- Optional: inject `IResilientExecutor` from `StangaNetLib.Resilience` for Auth0 Management HTTP calls; Facebook Graph client accepts `configureHttpClient` for Polly handlers.
- Match existing naming, file-scoped namespaces, and EditorConfig / Roslyn conventions.
- Tests use xUnit v3 + FluentAssertions; cover `net8.0`, `net9.0`, and `net10.0` when changing shared behavior.
