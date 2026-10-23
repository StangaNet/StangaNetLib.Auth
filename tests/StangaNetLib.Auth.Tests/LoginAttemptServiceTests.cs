using FluentAssertions;
using Microsoft.Extensions.Options;
using StangaNetLib.Auth.Services;
using StangaNetLib.Auth.Settings;

namespace StangaNetLib.Auth.Tests;

public sealed class LoginAttemptServiceTests
{
    private static InMemoryLoginAttemptService CreateSut(int max = 3)
        => new(Options.Create(new LoginLockoutSettings
        {
            MaxFailedAttempts = max,
            FailureWindow = TimeSpan.FromMinutes(15),
            LockoutDuration = TimeSpan.FromMinutes(15),
        }));

    [Fact]
    public async Task RecordFailure_LocksAfterThreshold()
    {
        var ct = TestContext.Current.CancellationToken;
        var sut = CreateSut(max: 3);

        (await sut.IsLockedOutAsync("user-1", ct)).Should().BeFalse();

        await sut.RecordFailureAsync("user-1", ct);
        await sut.RecordFailureAsync("user-1", ct);
        (await sut.IsLockedOutAsync("user-1", ct)).Should().BeFalse();

        await sut.RecordFailureAsync("user-1", ct);
        (await sut.IsLockedOutAsync("user-1", ct)).Should().BeTrue();
        (await sut.GetLockoutRemainingAsync("user-1", ct)).Should().NotBeNull();
    }

    [Fact]
    public async Task Reset_ClearsLockout()
    {
        var ct = TestContext.Current.CancellationToken;
        var sut = CreateSut(max: 1);

        await sut.RecordFailureAsync("user-2", ct);
        (await sut.IsLockedOutAsync("user-2", ct)).Should().BeTrue();

        await sut.ResetAsync("user-2", ct);
        (await sut.IsLockedOutAsync("user-2", ct)).Should().BeFalse();
    }
}
