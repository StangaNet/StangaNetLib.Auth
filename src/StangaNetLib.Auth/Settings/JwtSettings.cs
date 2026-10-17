using System.ComponentModel.DataAnnotations;

namespace StangaNetLib.Auth.Settings;

/// <summary>Configuration for self-signed HMAC-SHA256 JWT authentication. Bind from <c>JwtSettings</c> in appsettings.</summary>
public sealed class JwtSettings
{
    /// <summary>The configuration section key used to bind this class from <c>appsettings.json</c>.</summary>
    public const string SectionName = "JwtSettings";

    /// <summary>HMAC-SHA256 signing secret. Must be at least 32 characters.</summary>
    [Required, MinLength(32)]
    public string Secret { get; init; } = string.Empty;

    /// <summary>Token issuer (<c>iss</c> claim). Must match the value configured in the consuming API.</summary>
    [Required]
    public string Issuer { get; init; } = string.Empty;

    /// <summary>Token audience (<c>aud</c> claim). Must match the value configured in the consuming API.</summary>
    [Required]
    public string Audience { get; init; } = string.Empty;

    /// <summary>Lifetime of the access token in minutes. Default: 15.</summary>
    [Range(1, 1440)]
    public int AccessTokenExpiryMinutes { get; init; } = 15;

    /// <summary>Lifetime of each refresh token in days. Default: 30.</summary>
    [Range(1, 365)]
    public int RefreshTokenExpiryDays { get; init; } = 30;
}
