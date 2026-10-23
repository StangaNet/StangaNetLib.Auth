using System.Security.Cryptography;
using Microsoft.Extensions.Options;
using OtpNet;
using StangaNetLib.Auth.Abstractions;
using StangaNetLib.Auth.Settings;

namespace StangaNetLib.Auth.Services;

/// <summary>RFC 6238 TOTP service backed by Otp.NET.</summary>
public sealed class TotpService : ITotpService
{
    private readonly TotpSettings _settings;

    /// <summary>Creates a TOTP service with the given options.</summary>
    public TotpService(IOptions<TotpSettings> options)
    {
        _settings = options?.Value ?? new TotpSettings();
    }

    /// <inheritdoc />
    public string GenerateSecret()
    {
        var key = KeyGeneration.GenerateRandomKey(20);
        return Base32Encoding.ToString(key);
    }

    /// <inheritdoc />
    public string GetOtpAuthUri(string secret, string accountName, string? issuer = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(secret);
        ArgumentException.ThrowIfNullOrEmpty(accountName);

        var effectiveIssuer = string.IsNullOrWhiteSpace(issuer) ? _settings.Issuer : issuer;
        var key = Base32Encoding.ToBytes(secret);
        return new OtpUri(OtpType.Totp, key, accountName, effectiveIssuer).ToString();
    }

    /// <inheritdoc />
    public bool Verify(string secret, string code)
    {
        if (string.IsNullOrWhiteSpace(secret) || string.IsNullOrWhiteSpace(code))
            return false;

        try
        {
            var key = Base32Encoding.ToBytes(secret);
            var totp = new Totp(key);
            var window = new VerificationWindow(_settings.VerificationWindow, _settings.VerificationWindow);
            return totp.VerifyTotp(code.Trim(), out _, window);
        }
        catch (Exception)
        {
            return false;
        }
    }

    /// <inheritdoc />
    public IReadOnlyList<string> GenerateRecoveryCodes(int? count = null)
    {
        var n = count ?? _settings.RecoveryCodeCount;
        if (n < 1)
            throw new ArgumentOutOfRangeException(nameof(count), "Recovery code count must be positive.");

        var codes = new string[n];
        const string alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
        for (var i = 0; i < n; i++)
        {
            var bytes = RandomNumberGenerator.GetBytes(_settings.RecoveryCodeLength);
            var chars = new char[_settings.RecoveryCodeLength];
            for (var j = 0; j < chars.Length; j++)
                chars[j] = alphabet[bytes[j] % alphabet.Length];
            codes[i] = new string(chars);
        }

        return codes;
    }
}
