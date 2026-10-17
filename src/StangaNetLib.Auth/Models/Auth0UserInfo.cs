namespace StangaNetLib.Auth.Models;

/// <summary>User profile returned by the Auth0 Management API.</summary>
public sealed class Auth0UserInfo
{
    /// <summary>The Auth0 user ID (e.g. <c>auth0|abc123</c>).</summary>
    public string UserId { get; init; } = string.Empty;

    /// <summary>The user's email address.</summary>
    public string Email { get; init; } = string.Empty;

    /// <summary>Whether the user has verified their email address.</summary>
    public bool EmailVerified { get; init; }

    /// <summary>Whether the user is currently blocked from signing in.</summary>
    public bool Blocked { get; init; }

    /// <summary>UTC timestamp when the Auth0 account was created.</summary>
    public DateTime CreatedAt { get; init; }

    /// <summary>UTC timestamp of the user's most recent sign-in, or <c>null</c> if they have never signed in.</summary>
    public DateTime? LastLogin { get; init; }

    /// <summary>Free-form key/value bag stored by the end-user (user_metadata).</summary>
    public IReadOnlyDictionary<string, object?> UserMetadata { get; init; }
        = new Dictionary<string, object?>();

    /// <summary>Free-form key/value bag stored by the application (app_metadata).</summary>
    public IReadOnlyDictionary<string, object?> AppMetadata { get; init; }
        = new Dictionary<string, object?>();
}
