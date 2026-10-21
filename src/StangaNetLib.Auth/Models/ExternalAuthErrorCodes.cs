namespace StangaNetLib.Auth.Models;

/// <summary>Machine-readable error codes returned by external identity validation.</summary>
public static class ExternalAuthErrorCodes
{
    /// <summary>No registered provider matches the requested name.</summary>
    public const string UnknownProvider = "external_provider.unknown";

    /// <summary>The token failed signature, issuer, audience, or lifetime validation.</summary>
    public const string InvalidToken = "external_token.invalid";

    /// <summary>The token string was missing or empty.</summary>
    public const string EmptyToken = "external_token.empty";

    /// <summary>The provider HTTP call failed or returned an unexpected payload.</summary>
    public const string ProviderError = "external_provider.error";
}
