namespace StangaNetLib.Auth.Models;

/// <summary>Claim name constants used in StangaNetLib.Auth JWT access tokens.</summary>
public static class JwtClaims
{
    /// <summary>Subject — user ID.</summary>
    public const string UserId = "sub";

    /// <summary>User email address.</summary>
    public const string Email = "email";

    /// <summary>User role (e.g. "User", "Admin", "Partner").</summary>
    public const string Role = "role";

    /// <summary>Device identifier that requested the token.</summary>
    public const string DeviceId = "device_id";

    /// <summary>Unique token ID — used for revocation blacklist lookup.</summary>
    public const string TokenId = "jti";
}
