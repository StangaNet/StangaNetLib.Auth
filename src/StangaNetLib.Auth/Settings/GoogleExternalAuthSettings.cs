using System.ComponentModel.DataAnnotations;

namespace StangaNetLib.Auth.Settings;

/// <summary>Configuration for Google ID-token validation. Bind from <c>Auth:External:Google</c>.</summary>
public sealed class GoogleExternalAuthSettings
{
    /// <summary>Configuration section key.</summary>
    public const string SectionName = "Auth:External:Google";

    /// <summary>
    /// Accepted <c>aud</c> values — typically OAuth client IDs for web, iOS, and Android.
    /// </summary>
    [Required, MinLength(1)]
    public IReadOnlyList<string> ClientIds { get; init; } = Array.Empty<string>();
}
