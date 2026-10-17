using StangaNetLib.Auth.Models;
using StangaNetLib.Core.Common;

namespace StangaNetLib.Auth.Abstractions;

/// <summary>
/// Provides access to the Auth0 Management API for user and role management.
/// Requires <see cref="Settings.Auth0Settings.ManagementClientId"/> and
/// <see cref="Settings.Auth0Settings.ManagementClientSecret"/> to be configured.
/// Register via <c>AddStangaNetLibAuth0ManagementService()</c>.
/// </summary>
public interface IAuth0ManagementService
{
    /// <summary>Retrieves the user's profile from Auth0.</summary>
    /// <param name="userId">The Auth0 user ID (e.g. <c>auth0|abc123</c>).</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>The user profile on success, or a <c>NotFound</c> error if the user does not exist.</returns>
    Task<Result<Auth0UserInfo>> GetUserAsync(string userId, CancellationToken ct = default);

    /// <summary>Returns all roles currently assigned to the specified user.</summary>
    /// <param name="userId">The Auth0 user ID.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>A read-only list of role descriptors, possibly empty.</returns>
    Task<Result<IReadOnlyList<Auth0RoleInfo>>> GetUserRolesAsync(string userId, CancellationToken ct = default);

    /// <summary>Assigns one or more roles to the specified user.</summary>
    /// <param name="userId">The Auth0 user ID.</param>
    /// <param name="roleIds">The Auth0 role IDs to assign.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>Success, or an internal error if the Auth0 API call fails.</returns>
    Task<Result> AssignRolesAsync(string userId, IEnumerable<string> roleIds, CancellationToken ct = default);

    /// <summary>Removes one or more roles from the specified user.</summary>
    /// <param name="userId">The Auth0 user ID.</param>
    /// <param name="roleIds">The Auth0 role IDs to remove.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>Success, or an internal error if the Auth0 API call fails.</returns>
    Task<Result> RemoveRolesAsync(string userId, IEnumerable<string> roleIds, CancellationToken ct = default);

    /// <summary>Blocks the user, preventing sign-in until unblocked.</summary>
    /// <param name="userId">The Auth0 user ID.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>Success, or an internal error if the Auth0 API call fails.</returns>
    Task<Result> BlockUserAsync(string userId, CancellationToken ct = default);

    /// <summary>Removes the block on a previously blocked user.</summary>
    /// <param name="userId">The Auth0 user ID.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>Success, or an internal error if the Auth0 API call fails.</returns>
    Task<Result> UnblockUserAsync(string userId, CancellationToken ct = default);

    /// <summary>Permanently deletes the user from Auth0.</summary>
    /// <param name="userId">The Auth0 user ID.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>Success, or an internal error if the Auth0 API call fails.</returns>
    Task<Result> DeleteUserAsync(string userId, CancellationToken ct = default);

    /// <summary>Merges the given key/value pairs into the user's <c>user_metadata</c>.</summary>
    /// <param name="userId">The Auth0 user ID.</param>
    /// <param name="metadata">Key/value pairs to merge into the existing <c>user_metadata</c> object.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>Success, or an internal error if the Auth0 API call fails.</returns>
    Task<Result> UpdateUserMetadataAsync(string userId, IReadOnlyDictionary<string, object?> metadata, CancellationToken ct = default);
}
