using System.Collections.Concurrent;
using Microsoft.Extensions.Options;
using StangaNetLib.Auth.Abstractions;
using StangaNetLib.Auth.Settings;

namespace StangaNetLib.Auth.Services;

/// <summary>
/// In-memory login attempt / lockout tracker. Suitable for single-instance deployments and tests.
/// </summary>
public sealed class InMemoryLoginAttemptService : ILoginAttemptService
{
    private readonly LoginLockoutSettings _settings;
    private readonly ConcurrentDictionary<string, AttemptState> _states = new(StringComparer.Ordinal);

    /// <summary>Creates a tracker with the given options.</summary>
    public InMemoryLoginAttemptService(IOptions<LoginLockoutSettings> options)
    {
        _settings = options?.Value ?? new LoginLockoutSettings();
    }

    /// <inheritdoc />
    public Task<bool> IsLockedOutAsync(string accountId, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(accountId);
        cancellationToken.ThrowIfCancellationRequested();

        if (!_states.TryGetValue(accountId, out var state))
            return Task.FromResult(false);

        lock (state.Sync)
        {
            Prune(state);
            return Task.FromResult(state.LockedUntil is { } until && until > DateTimeOffset.UtcNow);
        }
    }

    /// <inheritdoc />
    public Task RecordFailureAsync(string accountId, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(accountId);
        cancellationToken.ThrowIfCancellationRequested();

        var state = _states.GetOrAdd(accountId, static _ => new AttemptState());
        lock (state.Sync)
        {
            Prune(state);
            var now = DateTimeOffset.UtcNow;
            if (state.LockedUntil is { } until && until > now)
                return Task.CompletedTask;

            state.Failures.Add(now);
            if (state.Failures.Count >= _settings.MaxFailedAttempts)
                state.LockedUntil = now + _settings.LockoutDuration;
        }

        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task ResetAsync(string accountId, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(accountId);
        cancellationToken.ThrowIfCancellationRequested();
        _states.TryRemove(accountId, out _);
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task<TimeSpan?> GetLockoutRemainingAsync(string accountId, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(accountId);
        cancellationToken.ThrowIfCancellationRequested();

        if (!_states.TryGetValue(accountId, out var state))
            return Task.FromResult<TimeSpan?>(null);

        lock (state.Sync)
        {
            Prune(state);
            if (state.LockedUntil is not { } until || until <= DateTimeOffset.UtcNow)
                return Task.FromResult<TimeSpan?>(null);

            return Task.FromResult<TimeSpan?>(until - DateTimeOffset.UtcNow);
        }
    }

    private void Prune(AttemptState state)
    {
        var cutoff = DateTimeOffset.UtcNow - _settings.FailureWindow;
        state.Failures.RemoveAll(t => t < cutoff);

        if (state.LockedUntil is { } until && until <= DateTimeOffset.UtcNow)
            state.LockedUntil = null;
    }

    private sealed class AttemptState
    {
        public object Sync { get; } = new();
        public List<DateTimeOffset> Failures { get; } = [];
        public DateTimeOffset? LockedUntil { get; set; }
    }
}
