using System.ComponentModel.DataAnnotations;

namespace StangaNetLib.Auth.Settings;

/// <summary>Configuration for Auth0-delegated JWT authentication. Bind from <c>Auth0Settings</c> in appsettings.</summary>
public sealed class Auth0Settings
{
    /// <summary>The configuration section key used to bind this class from <c>appsettings.json</c>.</summary>
    public const string SectionName = "Auth0Settings";

    /// <summary>Your Auth0 tenant domain, e.g. "your-tenant.auth0.com".</summary>
    [Required]
    public string Domain { get; init; } = string.Empty;

    /// <summary>The API Identifier (audience) configured in the Auth0 dashboard.</summary>
    [Required]
    public string Audience { get; init; } = string.Empty;

    /// <summary>Client ID of the Machine-to-Machine application used for the Management API.</summary>
    public string ManagementClientId { get; init; } = string.Empty;

    /// <summary>Client Secret of the Machine-to-Machine application used for the Management API.</summary>
    public string ManagementClientSecret { get; init; } = string.Empty;
}
