namespace StangaNetLib.Auth.Abstractions;

/// <summary>
/// Adds access tokens to a revocation blacklist and checks whether a token has been revoked.
/// Inject this service in logout handlers and other places that need to invalidate a token before its natural expiry.
/// </summary>
public interface ITokenRevocationService
{
    /// <summary>
    /// Adds the token with the given <paramref name="tokenId"/> to the revocation blacklist.
    /// The entry expires automatically after <paramref name="ttl"/>, matching the token's remaining lifetime.
    /// </summary>
    /// <param name="tokenId">The <c>jti</c> claim value of the access token to revoke.</param>
    /// <param name="ttl">How long to keep the blacklist entry — set to the token's remaining lifetime.</param>
    /// <param name="ct">Cancellation token.</param>
    Task RevokeAsync(string tokenId, TimeSpan ttl, CancellationToken ct = default);

    /// <summary>Returns <c>true</c> if the token with the given <paramref name="tokenId"/> has been revoked.</summary>
    /// <param name="tokenId">The <c>jti</c> claim value to check.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns><c>true</c> if the token is on the blacklist; <c>false</c> otherwise.</returns>
    Task<bool> IsRevokedAsync(string tokenId, CancellationToken ct = default);
}
