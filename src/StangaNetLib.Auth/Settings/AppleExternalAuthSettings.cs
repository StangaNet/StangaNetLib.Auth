using System.ComponentModel.DataAnnotations;

namespace StangaNetLib.Auth.Settings;

/// <summary>Configuration for Sign in with Apple identity-token validation. Bind from <c>Auth:External:Apple</c>.</summary>
public sealed class AppleExternalAuthSettings
{
    /// <summary>Configuration section key.</summary>
    public const string SectionName = "Auth:External:Apple";

    /// <summary>
    /// Accepted <c>aud</c> values — Services ID and/or iOS/macOS Bundle IDs.
    /// </summary>
    [Required, MinLength(1)]
    public IReadOnlyList<string> ClientIds { get; init; } = Array.Empty<string>();
}
