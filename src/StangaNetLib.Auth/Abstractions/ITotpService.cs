namespace StangaNetLib.Auth.Abstractions;

/// <summary>Generates and verifies TOTP (RFC 6238) codes and recovery codes for MFA.</summary>
public interface ITotpService
{
    /// <summary>Generates a new Base32-encoded shared secret suitable for authenticator apps.</summary>
    string GenerateSecret();

    /// <summary>
    /// Builds an <c>otpauth://</c> URI for QR provisioning.
    /// </summary>
    /// <param name="secret">Base32-encoded TOTP secret.</param>
    /// <param name="accountName">Account label (usually email or username).</param>
    /// <param name="issuer">Optional issuer override; defaults to <c>TotpSettings.Issuer</c>.</param>
    string GetOtpAuthUri(string secret, string accountName, string? issuer = null);

    /// <summary>
    /// Returns <c>true</c> if <paramref name="code"/> is a valid TOTP for <paramref name="secret"/>
    /// within the configured verification window.
    /// </summary>
    bool Verify(string secret, string code);

    /// <summary>Generates a fresh set of one-time recovery codes (plaintext; hash before persisting).</summary>
    IReadOnlyList<string> GenerateRecoveryCodes(int? count = null);
}
