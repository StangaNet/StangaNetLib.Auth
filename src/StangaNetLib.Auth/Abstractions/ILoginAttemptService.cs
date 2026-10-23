namespace StangaNetLib.Auth.Abstractions;

/// <summary>Tracks failed login attempts and account lockout state.</summary>
public interface ILoginAttemptService
{
    /// <summary>Returns <c>true</c> if <paramref name="accountId"/> is currently locked out.</summary>
    Task<bool> IsLockedOutAsync(string accountId, CancellationToken cancellationToken = default);

    /// <summary>Records a failed login attempt for <paramref name="accountId"/>.</summary>
    Task RecordFailureAsync(string accountId, CancellationToken cancellationToken = default);

    /// <summary>Clears failure history and lockout for <paramref name="accountId"/> (e.g. after success).</summary>
    Task ResetAsync(string accountId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Returns the remaining lockout duration, or <c>null</c> when the account is not locked.
    /// </summary>
    Task<TimeSpan?> GetLockoutRemainingAsync(string accountId, CancellationToken cancellationToken = default);
}
