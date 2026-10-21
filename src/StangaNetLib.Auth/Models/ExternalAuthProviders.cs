namespace StangaNetLib.Auth.Models;

/// <summary>Canonical provider name constants for external identity token exchange.</summary>
public static class ExternalAuthProviders
{
    /// <summary>Google Sign-In / Google Identity Services ID tokens.</summary>
    public const string Google = "google";

    /// <summary>Sign in with Apple identity tokens.</summary>
    public const string Apple = "apple";

    /// <summary>Facebook Login access tokens (Graph API).</summary>
    public const string Facebook = "facebook";

    /// <summary>Microsoft identity platform (Entra ID) ID tokens.</summary>
    public const string Microsoft = "microsoft";
}
