namespace StangaNetLib.Auth.Models;

/// <summary>
/// Represents a refresh token issued to a specific user device.
/// Each device holds at most one active refresh token at a time — rotation replaces the previous one.
/// </summary>
public sealed class RefreshToken
{
    /// <summary>The opaque token string exchanged for a new access/refresh token pair.</summary>
    public string Token { get; init; } = string.Empty;

    /// <summary>The identifier of the user who owns this token.</summary>
    public string UserId { get; init; } = string.Empty;

    /// <summary>Metadata about the device this token was issued to.</summary>
    public required DeviceInfo Device { get; init; }

    /// <summary>UTC timestamp at which the token ceases to be valid.</summary>
    public DateTime ExpiresAt { get; init; }

    /// <summary>UTC timestamp at which the token was issued. Defaults to <see cref="DateTime.UtcNow"/>.</summary>
    public DateTime CreatedAt { get; init; } = DateTime.UtcNow;

    /// <summary>Whether the token has been explicitly revoked (e.g. via logout).</summary>
    public bool IsRevoked { get; private set; }

    /// <summary>Whether the token has passed its <see cref="ExpiresAt"/> timestamp.</summary>
    public bool IsExpired => DateTime.UtcNow > ExpiresAt;

    /// <summary>True when the token can be exchanged for a new access token.</summary>
    public bool IsActive => !IsRevoked && !IsExpired;

    /// <summary>Marks the token as permanently revoked. Idempotent.</summary>
    public void Revoke() => IsRevoked = true;
}
