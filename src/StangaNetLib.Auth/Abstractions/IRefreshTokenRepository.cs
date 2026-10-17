using StangaNetLib.Auth.Models;

namespace StangaNetLib.Auth.Abstractions;

/// <summary>
/// Persistence contract for refresh tokens.
/// Implement this interface in the consuming project against your chosen data store.
/// </summary>
public interface IRefreshTokenRepository
{
    /// <summary>Returns the refresh token entity with the given token string, or <c>null</c> if not found.</summary>
    /// <param name="token">The opaque refresh token string.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>The matching <see cref="RefreshToken"/>, or <c>null</c> if it does not exist.</returns>
    Task<RefreshToken?> GetAsync(string token, CancellationToken ct = default);

    /// <summary>Returns all refresh tokens (active and revoked) belonging to the given user.</summary>
    /// <param name="userId">The user whose tokens to retrieve.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>A read-only list of all tokens for the user, possibly empty.</returns>
    Task<IReadOnlyList<RefreshToken>> GetByUserIdAsync(string userId, CancellationToken ct = default);

    /// <summary>
    /// Persists a new refresh token.
    /// Implementations should revoke/replace any existing active token for the same device.
    /// </summary>
    /// <param name="refreshToken">The token entity to persist.</param>
    /// <param name="ct">Cancellation token.</param>
    Task SaveAsync(RefreshToken refreshToken, CancellationToken ct = default);

    /// <summary>Marks the specified refresh token as revoked.</summary>
    /// <param name="token">The opaque refresh token string to revoke.</param>
    /// <param name="ct">Cancellation token.</param>
    Task RevokeAsync(string token, CancellationToken ct = default);

    /// <summary>Revokes all refresh tokens for the given user (e.g. on password change or global logout).</summary>
    /// <param name="userId">The user whose tokens to revoke.</param>
    /// <param name="ct">Cancellation token.</param>
    Task RevokeAllForUserAsync(string userId, CancellationToken ct = default);

    /// <summary>Revokes all refresh tokens issued to a specific device of the given user (per-device logout).</summary>
    /// <param name="userId">The user who owns the tokens.</param>
    /// <param name="deviceId">The device identifier whose tokens to revoke.</param>
    /// <param name="ct">Cancellation token.</param>
    Task RevokeAllForDeviceAsync(string userId, string deviceId, CancellationToken ct = default);

    /// <summary>Permanently deletes expired tokens. Intended to be called by a background housekeeping job.</summary>
    /// <param name="ct">Cancellation token.</param>
    Task DeleteExpiredAsync(CancellationToken ct = default);
}
