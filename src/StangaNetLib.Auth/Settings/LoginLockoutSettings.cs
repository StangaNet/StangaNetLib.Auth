using System.ComponentModel.DataAnnotations;

namespace StangaNetLib.Auth.Settings;

/// <summary>Configuration for login attempt lockout.</summary>
public sealed class LoginLockoutSettings
{
    /// <summary>Configuration section name. Value: <c>"LoginLockoutSettings"</c>.</summary>
    public const string SectionName = "LoginLockoutSettings";

    /// <summary>Failed attempts allowed within <see cref="FailureWindow"/> before lockout. Default: 5.</summary>
    [Range(1, 100)]
    public int MaxFailedAttempts { get; set; } = 5;

    /// <summary>Sliding window that counts failed attempts. Default: 15 minutes.</summary>
    public TimeSpan FailureWindow { get; set; } = TimeSpan.FromMinutes(15);

    /// <summary>How long an account stays locked after exceeding the threshold. Default: 15 minutes.</summary>
    public TimeSpan LockoutDuration { get; set; } = TimeSpan.FromMinutes(15);
}
