using System.Collections.Concurrent;
using StangaNetLib.Auth.Abstractions;
using StangaNetLib.Auth.Models;

namespace StangaNetLib.Auth.Services;

/// <summary>
/// Thread-safe in-memory implementation of <see cref="IRefreshTokenRepository"/>.
/// For development and unit testing only — data is lost on process restart.
/// </summary>
public sealed class InMemoryRefreshTokenRepository : IRefreshTokenRepository
{
    private readonly ConcurrentDictionary<string, RefreshToken> _store = new();

    /// <inheritdoc />
    public Task<RefreshToken?> GetAsync(string token, CancellationToken ct = default)
    {
        _store.TryGetValue(token, out var result);
        return Task.FromResult(result);
    }

    /// <inheritdoc />
    public Task<IReadOnlyList<RefreshToken>> GetByUserIdAsync(string userId, CancellationToken ct = default)
    {
        IReadOnlyList<RefreshToken> result = _store.Values
            .Where(t => t.UserId == userId)
            .ToList();
        return Task.FromResult(result);
    }

    /// <inheritdoc />
    public Task SaveAsync(RefreshToken refreshToken, CancellationToken ct = default)
    {
        // Revoke and remove existing tokens for the same device before inserting the new one
        var sameDevice = _store.Values
            .Where(t => t.UserId == refreshToken.UserId
                     && t.Device.DeviceId == refreshToken.Device.DeviceId)
            .ToList();

        foreach (var old in sameDevice)
        {
            old.Revoke();
            _store.TryRemove(old.Token, out _);
        }

        _store[refreshToken.Token] = refreshToken;
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task RevokeAsync(string token, CancellationToken ct = default)
    {
        if (_store.TryGetValue(token, out var rt))
            rt.Revoke();
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task RevokeAllForUserAsync(string userId, CancellationToken ct = default)
    {
        foreach (var rt in _store.Values.Where(t => t.UserId == userId))
            rt.Revoke();
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task RevokeAllForDeviceAsync(string userId, string deviceId, CancellationToken ct = default)
    {
        foreach (var rt in _store.Values
                     .Where(t => t.UserId == userId && t.Device.DeviceId == deviceId))
            rt.Revoke();
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task DeleteExpiredAsync(CancellationToken ct = default)
    {
        foreach (var token in _store.Values.Where(t => t.IsExpired).Select(t => t.Token).ToList())
            _store.TryRemove(token, out _);
        return Task.CompletedTask;
    }
}
