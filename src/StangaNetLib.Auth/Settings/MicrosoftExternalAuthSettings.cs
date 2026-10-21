using System.ComponentModel.DataAnnotations;

namespace StangaNetLib.Auth.Settings;

/// <summary>Configuration for Microsoft identity platform ID-token validation. Bind from <c>Auth:External:Microsoft</c>.</summary>
public sealed class MicrosoftExternalAuthSettings
{
    /// <summary>Configuration section key.</summary>
    public const string SectionName = "Auth:External:Microsoft";

    /// <summary>Accepted <c>aud</c> values — application (client) IDs.</summary>
    [Required, MinLength(1)]
    public IReadOnlyList<string> ClientIds { get; init; } = Array.Empty<string>();

    /// <summary>
    /// Azure AD tenant ID, or <c>common</c> / <c>organizations</c> / <c>consumers</c>.
    /// Default: <c>common</c>.
    /// </summary>
    [Required]
    public string TenantId { get; init; } = "common";
}
