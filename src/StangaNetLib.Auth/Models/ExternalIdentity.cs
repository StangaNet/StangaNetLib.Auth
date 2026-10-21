namespace StangaNetLib.Auth.Models;

/// <summary>
/// Verified identity extracted from an external provider token.
/// The consuming application maps this to a local user and issues StangaNet JWTs.
/// </summary>
public sealed class ExternalIdentity
{
    /// <summary>Provider name (see <see cref="ExternalAuthProviders"/>).</summary>
    public required string Provider { get; init; }

    /// <summary>Stable subject identifier from the provider (<c>sub</c> / user id).</summary>
    public required string Subject { get; init; }

    /// <summary>Email when the provider supplied one; Apple may omit it on subsequent logins.</summary>
    public string? Email { get; init; }

    /// <summary>Whether the provider asserts the email as verified.</summary>
    public bool EmailVerified { get; init; }

    /// <summary>Display name when available.</summary>
    public string? DisplayName { get; init; }

    /// <summary>Profile picture URL when available.</summary>
    public string? PictureUrl { get; init; }

    /// <summary>Flat claim bag from the validated token / profile response.</summary>
    public IReadOnlyDictionary<string, string> RawClaims { get; init; }
        = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
}
