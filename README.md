# StangaNetLib.Auth

[![.NET CI](https://github.com/StangaNet/StangaNetLib.Auth/actions/workflows/main.yml/badge.svg)](https://github.com/StangaNet/StangaNetLib.Auth/actions/workflows/main.yml)
![NuGet](https://img.shields.io/badge/nuget-1.2.0-blue)
![.NET](https://img.shields.io/badge/.NET-8.0%20%7C%209.0%20%7C%2010.0-512BD4)

JWT authentication for ASP.NET Core: self-hosted HMAC-SHA256 with per-device refresh rotation, pluggable password hashing (BCrypt default / Argon2id), TOTP MFA, login lockout, cache-backed token revocation, optional Auth0 (RS256 / JWKS + Management API), and **external identity token exchange** (Google, Apple, Facebook, Microsoft). Uses [`StangaNetLib.Caching`](https://github.com/StangaNet/StangaNetLib.Caching) for the revocation blacklist and optionally [`StangaNetLib.Resilience`](https://github.com/StangaNet/StangaNetLib.Resilience) for Auth0 Management HTTP calls. Auth0 Management and external identity methods return `Result` / `Result<T>` from [`StangaNetLib.Core`](https://github.com/StangaNet/StangaNetLib.Core).

## Design Philosophy

- **Self-hosted first**: `AddStangaNetLibAuthSelfHosted` wires JWT + Argon2id + TOTP + lockout without Auth0/IdP.
- **Domain-centric**: tokens, passwords, MFA, lockout, revocation, Auth0, and external IdPs as capabilities.
- **Functional failures**: Auth0 Management API and external identity validation map to `Result` / `Result<T>`.
- **Pluggable storage / hasher**: `IRefreshTokenRepository`; `IPasswordHasher` via `TryAdd` / `AddStangaNetLibAuthArgon2id`.
- **Modern .NET**: `net8.0` / `net9.0` / `net10.0` with ASP.NET Core authentication middleware.
- **Token exchange**: clients send Google/Apple/Microsoft ID tokens or Facebook access tokens; the library verifies them and returns `ExternalIdentity` — your app maps to a local user and issues StangaNet JWTs.

## Installation

The package is hosted on **GitHub Packages** (pulls Caching / Resilience / Core from the same feed).

```xml
<!-- NuGet.config — source key must match your packageSourceCredentials -->
<configuration>
  <packageSources>
    <add key="StangaNet" value="https://nuget.pkg.github.com/StangaNet/index.json" />
  </packageSources>
</configuration>
```

```xml
<!-- .csproj -->
<PackageReference Include="StangaNetLib.Auth" Version="1.1.0" />
```

See [CHANGELOG.md](./CHANGELOG.md) for release history.

## Core Components

| Namespace | Components | Purpose |
|---|---|---|
| `StangaNetLib.Auth.Abstractions` | `IJwtTokenGenerator`, `IPasswordHasher`, `ITotpService`, `ILoginAttemptService`, `IRefreshTokenRepository`, … | Public contracts |
| `StangaNetLib.Auth.Models` | `RefreshToken`, `DeviceInfo`, `JwtClaims`, `ExternalIdentity`, `ExternalAuthProviders`, … | Domain models |
| `StangaNetLib.Auth.Settings` | `JwtSettings`, `Argon2idSettings`, `TotpSettings`, `LoginLockoutSettings`, `Auth0Settings`, … | Configuration |
| `StangaNetLib.Auth.Services` | JWT / BCrypt / Argon2id / TOTP / lockout / Auth0 / external IdPs | Implementations |
| `StangaNetLib.Auth.Middleware` | `TokenRevocationMiddleware` | Per-request jti blacklist |
| `StangaNetLib.Auth.Extensions` | `AddStangaNetLibAuth`, `AddStangaNetLibAuthSelfHosted`, `AddStangaNetLibAuthArgon2id`, … | DI / pipeline |

## Project Structure

```
StangaNetLib.Auth/
├── assets/
│   └── package-icon.png
├── build/
│   └── StangaNetLib.Auth.props
├── src/
│   └── StangaNetLib.Auth/
│       ├── Abstractions/
│       ├── Extensions/
│       ├── Middleware/
│       ├── Models/
│       ├── Services/
│       │   └── External/
│       └── Settings/
└── tests/
    └── StangaNetLib.Auth.Tests/
```

## Quick Start

```csharp
builder.Services.AddStangaNetLibInMemoryCache(); // or Redis via AddStangaNetLibCaching
builder.Services.AddStangaNetLibAuth(builder.Configuration);
builder.Services.AddStangaNetLibAuthInMemoryTokenStore(); // replace in production

app.UseRouting();
app.UseStangaNetLibAuth();
```

## External identity providers (token exchange)

Register only the providers you need. Each call also registers `IExternalIdentityService`.

```csharp
builder.Services.AddStangaNetLibAuth(builder.Configuration);
builder.Services.AddStangaNetLibAuthExternalGoogle(builder.Configuration);
builder.Services.AddStangaNetLibAuthExternalApple(builder.Configuration);
builder.Services.AddStangaNetLibAuthExternalFacebook(builder.Configuration);
builder.Services.AddStangaNetLibAuthExternalMicrosoft(builder.Configuration);
```

```json
{
  "Auth": {
    "External": {
      "Google": { "ClientIds": [ "xxx.apps.googleusercontent.com" ] },
      "Apple": { "ClientIds": [ "com.example.service", "com.example.app" ] },
      "Facebook": { "AppId": "...", "AppSecret": "..." },
      "Microsoft": { "ClientIds": [ "app-guid" ], "TenantId": "common" }
    }
  }
}
```

```csharp
app.MapPost("/auth/external", async (
    ExternalLoginRequest body,
    IExternalIdentityService external,
    IJwtTokenGenerator jwt) =>
{
    var identity = await external.ValidateAsync(body.Provider, body.Token);
    if (identity.IsFailure)
        return Results.Unauthorized();

    // Map identity.Value to your local user, then:
    var access = jwt.GenerateAccessToken(userId, email, roles, body.DeviceId);
    return Results.Ok(new { access });
});
```

| Provider | Token type | Validation |
|---|---|---|
| Google | OIDC ID token | JWKS via Google OpenID configuration |
| Apple | OIDC ID token | JWKS via Apple OpenID configuration |
| Microsoft | OIDC ID token | JWKS via Entra ID v2.0 metadata |
| Facebook | Access token | Graph `debug_token` + `/me` |

Account linking and user persistence stay in the consuming application.

## CI/CD

On push/PR to `main` and `workflow_dispatch`, the shared StangaNet workflow:

1. Restores, builds, and tests on .NET 8 and .NET 9
2. Packs the NuGet package (with symbols)
3. Publishes to GitHub Packages outside pull requests
4. Uploads the `.nupkg` as a build artifact
