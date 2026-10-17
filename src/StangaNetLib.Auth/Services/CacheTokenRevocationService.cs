using StangaNetLib.Auth.Abstractions;
using StangaNetLib.Caching.Storage;

namespace StangaNetLib.Auth.Services;

internal sealed class CacheTokenRevocationService : ITokenRevocationService
{
    internal const string BlacklistPrefix = "auth:revoked:";

    private readonly ICacheService _cache;

    public CacheTokenRevocationService(ICacheService cache) => _cache = cache;

    /// <inheritdoc />
    public async Task RevokeAsync(string tokenId, TimeSpan ttl, CancellationToken ct = default)
        => await _cache.SetAsync($"{BlacklistPrefix}{tokenId}", "1", ttl, ct);

    /// <inheritdoc />
    public async Task<bool> IsRevokedAsync(string tokenId, CancellationToken ct = default)
    {
        var result = await _cache.ExistsAsync($"{BlacklistPrefix}{tokenId}", ct);
        return result.IsSuccess && result.Value;
    }
}
