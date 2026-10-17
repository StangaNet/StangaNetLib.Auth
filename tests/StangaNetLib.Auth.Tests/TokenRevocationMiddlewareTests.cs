using FluentAssertions;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using StangaNetLib.Auth.Abstractions;
using StangaNetLib.Auth.Middleware;
using StangaNetLib.Auth.Services;
using StangaNetLib.Auth.Settings;
using StangaNetLib.Caching.Storage;
using StangaNetLib.Core.Common;
using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
using Xunit;

namespace StangaNetLib.Auth.Tests;

/// <summary>Minimal in-memory ICacheService — used only in this test file.</summary>
file sealed class FakeCacheService : ICacheService
{
    private readonly ConcurrentDictionary<string, object> _store = new();

    public Task<Result<T?>> GetAsync<T>(string key, CancellationToken ct = default) where T : class
    {
        _store.TryGetValue(key, out var v);
        return Task.FromResult(Result<T?>.Success(v is T t ? t : null));
    }

    public Task<Result> SetAsync<T>(string key, T value, TimeSpan? expiry = null, CancellationToken ct = default) where T : class
    {
        _store[key] = value!;
        return Task.FromResult(Result.Success());
    }

    public Task<Result> RemoveAsync(string key, CancellationToken ct = default)
    {
        _store.TryRemove(key, out _);
        return Task.FromResult(Result.Success());
    }

    public Task<Result<bool>> ExistsAsync(string key, CancellationToken ct = default)
        => Task.FromResult(Result<bool>.Success(_store.ContainsKey(key)));

    public async Task<Result<T>> GetOrSetAsync<T>(string key, Func<CancellationToken, Task<T>> factory,
        TimeSpan? expiry = null, CancellationToken ct = default) where T : class
    {
        if (_store.TryGetValue(key, out var existing) && existing is T t)
            return Result<T>.Success(t);
        var value = await factory(ct);
        _store[key] = value!;
        return Result<T>.Success(value);
    }

    public Task<Result> RemoveByPrefixAsync(string prefix, CancellationToken ct = default)
    {
        foreach (var k in _store.Keys.Where(k => k.StartsWith(prefix)).ToList())
            _store.TryRemove(k, out _);
        return Task.FromResult(Result.Success());
    }

    public async IAsyncEnumerable<string> ScanKeysAsync(string pattern, [EnumeratorCancellation] CancellationToken ct = default)
    {
        foreach (var k in _store.Keys)
            yield return k;
        await Task.CompletedTask;
    }

    public Task<Result<IReadOnlyDictionary<string, T?>>> GetManyAsync<T>(IEnumerable<string> keys, CancellationToken ct = default) where T : class
    {
        var result = keys.ToDictionary(k => k, k => _store.TryGetValue(k, out var v) && v is T t ? t : default(T?));
        return Task.FromResult(Result<IReadOnlyDictionary<string, T?>>.Success(result));
    }

    public Task<Result> SetManyAsync<T>(IEnumerable<KeyValuePair<string, T>> entries, TimeSpan? expiration = null, CancellationToken ct = default) where T : class
    {
        foreach (var (k, v) in entries)
            _store[k] = v!;
        return Task.FromResult(Result.Success());
    }

    public Task<Result> RemoveManyAsync(IEnumerable<string> keys, CancellationToken ct = default)
    {
        foreach (var k in keys)
            _store.TryRemove(k, out _);
        return Task.FromResult(Result.Success());
    }
}

public sealed class TokenRevocationMiddlewareTests
{
    private static JwtTokenGenerator CreateJwt() => new(Options.Create(new JwtSettings
    {
        Secret                   = "test-secret-key-must-be-at-least-32-characters",
        Issuer                   = "test-issuer",
        Audience                 = "test-audience",
        AccessTokenExpiryMinutes = 15,
        RefreshTokenExpiryDays   = 30,
    }));

    private static (TokenRevocationMiddleware Middleware, ITokenRevocationService RevocationService)
        CreateMiddleware(RequestDelegate next, ICacheService? cache = null)
    {
        var cacheService = cache ?? new FakeCacheService();
        var revocation   = new CacheTokenRevocationService(cacheService);
        var middleware   = new TokenRevocationMiddleware(
            next, revocation, NullLogger<TokenRevocationMiddleware>.Instance);
        return (middleware, revocation);
    }

    [Fact]
    public async Task InvokeAsync_NoAuthHeader_CallsNext()
    {
        var nextCalled = false;
        var (sut, _) = CreateMiddleware(_ => { nextCalled = true; return Task.CompletedTask; });

        await sut.InvokeAsync(new DefaultHttpContext());

        nextCalled.Should().BeTrue();
    }

    [Fact]
    public async Task InvokeAsync_ValidNonRevokedToken_CallsNext()
    {
        var jwt        = CreateJwt();
        var nextCalled = false;
        var (sut, _) = CreateMiddleware(_ => { nextCalled = true; return Task.CompletedTask; });

        var token   = jwt.GenerateAccessToken("u1", "u@t.com", ["User"], "dev1");
        var context = new DefaultHttpContext();
        context.Request.Headers.Authorization = $"Bearer {token}";

        await sut.InvokeAsync(context);

        nextCalled.Should().BeTrue();
    }

    [Fact]
    public async Task InvokeAsync_RevokedToken_Returns401AndSkipsNext()
    {
        var jwt        = CreateJwt();
        var nextCalled = false;
        var (sut, revocation) = CreateMiddleware(_ => { nextCalled = true; return Task.CompletedTask; });

        var token   = jwt.GenerateAccessToken("u1", "u@t.com", ["User"], "dev1");
        var tokenId = jwt.GetTokenId(token)!;
        await revocation.RevokeAsync(tokenId, TimeSpan.FromMinutes(15), TestContext.Current.CancellationToken);

        var context = new DefaultHttpContext();
        context.Response.Body = new System.IO.MemoryStream();
        context.Request.Headers.Authorization = $"Bearer {token}";

        await sut.InvokeAsync(context);

        nextCalled.Should().BeFalse();
        context.Response.StatusCode.Should().Be(401);
    }

    [Fact]
    public async Task RevokeAsync_ThenIsRevokedAsync_ReturnsTrue()
    {
        var cache      = new FakeCacheService();
        var revocation = new CacheTokenRevocationService(cache);
        const string tokenId = "test-token-id";

        await revocation.RevokeAsync(tokenId, TimeSpan.FromMinutes(15), TestContext.Current.CancellationToken);

        var isRevoked = await revocation.IsRevokedAsync(tokenId, TestContext.Current.CancellationToken);
        isRevoked.Should().BeTrue();
    }
}
