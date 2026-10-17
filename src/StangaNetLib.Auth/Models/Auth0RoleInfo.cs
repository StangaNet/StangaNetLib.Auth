namespace StangaNetLib.Auth.Models;

/// <summary>Role descriptor returned by the Auth0 Management API.</summary>
public sealed class Auth0RoleInfo
{
    /// <summary>The Auth0 role ID (e.g. <c>rol_abc123</c>).</summary>
    public string Id { get; init; } = string.Empty;

    /// <summary>The human-readable role name (e.g. <c>Admin</c>).</summary>
    public string Name { get; init; } = string.Empty;

    /// <summary>Optional description of the role's purpose as configured in the Auth0 dashboard.</summary>
    public string Description { get; init; } = string.Empty;
}
