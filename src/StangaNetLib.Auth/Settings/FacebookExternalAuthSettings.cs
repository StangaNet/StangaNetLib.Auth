using System.ComponentModel.DataAnnotations;

namespace StangaNetLib.Auth.Settings;

/// <summary>Configuration for Facebook access-token validation via Graph API. Bind from <c>Auth:External:Facebook</c>.</summary>
public sealed class FacebookExternalAuthSettings
{
    /// <summary>Configuration section key.</summary>
    public const string SectionName = "Auth:External:Facebook";

    /// <summary>Facebook App ID.</summary>
    [Required]
    public string AppId { get; init; } = string.Empty;

    /// <summary>Facebook App Secret (used for <c>debug_token</c> app access token).</summary>
    [Required]
    public string AppSecret { get; init; } = string.Empty;
}
