namespace StangaNetLib.Auth.Services;

/// <summary>
/// Singleton cache for the Auth0 Management API M2M access token.
/// Prevents redundant token requests when <see cref="Auth0ManagementService"/> is transient.
/// </summary>
internal sealed class Auth0ManagementTokenCache
{
    private readonly SemaphoreSlim _lock = new(1, 1);
    private string?  _token;
    private DateTime _expiry = DateTime.MinValue;

    /// <summary>
    /// Returns the cached token if still valid, or calls <paramref name="factory"/> to acquire a new one.
    /// Thread-safe via double-checked locking.
    /// </summary>
    /// <param name="factory">
    /// Async delegate that performs the actual token request and returns the raw token string
    /// plus its <c>expires_in</c> value in seconds. Return <c>(string.Empty, 0)</c> to signal failure.
    /// </param>
    /// <param name="ct">Cancellation token forwarded to the factory.</param>
    /// <returns>The access token string, or <c>null</c>/<c>""</c> if acquisition failed.</returns>
    public async Task<string?> GetOrAcquireAsync(
        Func<CancellationToken, Task<(string Token, int ExpiresIn)>> factory,
        CancellationToken ct)
    {
        if (_token is not null && DateTime.UtcNow < _expiry)
            return _token;

        await _lock.WaitAsync(ct);
        try
        {
            if (_token is not null && DateTime.UtcNow < _expiry)
                return _token;

            var (token, expiresIn) = await factory(ct);
            _token  = token;
            _expiry = DateTime.UtcNow.AddSeconds(expiresIn - 30);
            return _token;
        }
        finally
        {
            _lock.Release();
        }
    }
}
