# StangaNetLib.Auth

[![.NET CI](https://github.com/StangaNet/StangaNetLib.Auth/actions/workflows/main.yml/badge.svg)](https://github.com/StangaNet/StangaNetLib.Auth/actions/workflows/main.yml)
![NuGet](https://img.shields.io/badge/nuget-1.0.0-blue)
![.NET](https://img.shields.io/badge/.NET-8.0%20%7C%209.0-512BD4)

JWT authentication for ASP.NET Core: self-signed HMAC-SHA256 with per-device refresh rotation, BCrypt password hashing, cache-backed token revocation, and Auth0 (RS256 / JWKS + Management API). Uses [`StangaNetLib.Caching`](https://github.com/StangaNet/StangaNetLib.Caching) for the revocation blacklist and optionally [`StangaNetLib.Resilience`](https://github.com/StangaNet/StangaNetLib.Resilience) for Auth0 Management HTTP calls. Auth0 Management methods return `Result` / `Result<T>` from [`StangaNetLib.Core`](https://github.com/StangaNet/StangaNetLib.Core).

## Design Philosophy

- **Domain-centric**: tokens, passwords, revocation, Auth0 as capabilities.
- **Functional failures**: Auth0 Management API maps to `Result` / `Result<T>`.
- **Pluggable storage**: `IRefreshTokenRepository`; revocation via `ICacheService`.
- **Modern .NET**: `net8.0` / `net9.0` with ASP.NET Core authentication middleware.

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
<PackageReference Include="StangaNetLib.Auth" Version="1.0.1" />
```

See [CHANGELOG.md](./CHANGELOG.md) for release history.

## Core Components

| Namespace | Components | Purpose |
|---|---|---|
| `StangaNetLib.Auth.Abstractions` | `IJwtTokenGenerator`, `IPasswordHasher`, `IRefreshTokenRepository`, … | Public contracts |
| `StangaNetLib.Auth.Models` | `RefreshToken`, `DeviceInfo`, `JwtClaims`, … | Domain models |
| `StangaNetLib.Auth.Settings` | `JwtSettings`, `Auth0Settings` | Configuration |
| `StangaNetLib.Auth.Services` | JWT / BCrypt / Auth0 / in-memory store | Implementations |
| `StangaNetLib.Auth.Middleware` | `TokenRevocationMiddleware` | Per-request jti blacklist |
| `StangaNetLib.Auth.Extensions` | `AddStangaNetLibAuth`, … | DI / pipeline |

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
│       └── Settings/
└── tests/
    └── StangaNetLib.Auth.Tests/
```

## Quick Start

```csharp
builder.Services.AddStangaNetLibInMemoryCache(); // or Redis via AddStangaNetLibCaching
builder.Services.AddStangaNetLibAuth(builder.Configuration);
builder.Services.AddStangaNetLibAuthInMemoryTokenStore(); // replace in production

app.UseAuthentication();
app.UseStangaNetLibAuthTokenRevocation();
app.UseAuthorization();
```

## CI/CD

On push/PR to `main` and `workflow_dispatch`, the shared StangaNet workflow:

1. Restores, builds, and tests on .NET 8 and .NET 9
2. Packs the NuGet package (with symbols)
3. Publishes to GitHub Packages outside pull requests
4. Uploads the `.nupkg` as a build artifact
