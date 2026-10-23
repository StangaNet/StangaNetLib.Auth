using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;
using Microsoft.Extensions.Options;
using StangaNetLib.Auth.Abstractions;
using StangaNetLib.Auth.Settings;

namespace StangaNetLib.Auth.Services;

/// <summary>Argon2id password hasher using the PHC string format.</summary>
public sealed class Argon2idPasswordHasher : IPasswordHasher
{
    private readonly Argon2idSettings _settings;

    /// <summary>Creates a hasher with the given options.</summary>
    public Argon2idPasswordHasher(IOptions<Argon2idSettings> options)
    {
        _settings = options?.Value ?? new Argon2idSettings();
    }

    /// <inheritdoc />
    public string Hash(string password)
    {
        ArgumentException.ThrowIfNullOrEmpty(password);

        var salt = RandomNumberGenerator.GetBytes(_settings.SaltLengthBytes);
        var hash = ComputeHash(
            password,
            salt,
            _settings.MemorySizeKb,
            _settings.Iterations,
            _settings.DegreeOfParallelism,
            _settings.HashLengthBytes);

        return FormatPhc(
            _settings.MemorySizeKb,
            _settings.Iterations,
            _settings.DegreeOfParallelism,
            salt,
            hash);
    }

    /// <inheritdoc />
    public bool Verify(string password, string hash)
    {
        if (string.IsNullOrEmpty(password) || string.IsNullOrEmpty(hash))
            return false;

        if (!TryParsePhc(hash, out var memoryKb, out var iterations, out var parallelism, out var salt, out var expected))
            return false;

        var actual = ComputeHash(password, salt, memoryKb, iterations, parallelism, expected.Length);
        return CryptographicOperations.FixedTimeEquals(actual, expected);
    }

    private static byte[] ComputeHash(
        string password,
        byte[] salt,
        int memoryKb,
        int iterations,
        int parallelism,
        int hashLength)
    {
        using var argon = new Argon2id(Encoding.UTF8.GetBytes(password))
        {
            Salt = salt,
            MemorySize = memoryKb,
            Iterations = iterations,
            DegreeOfParallelism = parallelism,
        };
        return argon.GetBytes(hashLength);
    }

    private static string FormatPhc(int memoryKb, int iterations, int parallelism, byte[] salt, byte[] hash)
        => string.Create(
            CultureInfo.InvariantCulture,
            $"$argon2id$v=19$m={memoryKb},t={iterations},p={parallelism}${Convert.ToBase64String(salt).TrimEnd('=')}${Convert.ToBase64String(hash).TrimEnd('=')}");

    private static bool TryParsePhc(
        string encoded,
        out int memoryKb,
        out int iterations,
        out int parallelism,
        out byte[] salt,
        out byte[] hash)
    {
        memoryKb = 0;
        iterations = 0;
        parallelism = 0;
        salt = [];
        hash = [];

        // $argon2id$v=19$m=65536,t=3,p=1$salt$hash
        var parts = encoded.Split('$', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length != 5)
            return false;
        if (!parts[0].Equals("argon2id", StringComparison.Ordinal))
            return false;
        if (!parts[1].Equals("v=19", StringComparison.Ordinal))
            return false;

        var paramsParts = parts[2].Split(',', StringSplitOptions.RemoveEmptyEntries);
        if (paramsParts.Length != 3)
            return false;

        if (!paramsParts[0].StartsWith("m=", StringComparison.Ordinal)
            || !int.TryParse(paramsParts[0].AsSpan(2), NumberStyles.Integer, CultureInfo.InvariantCulture, out memoryKb))
            return false;
        if (!paramsParts[1].StartsWith("t=", StringComparison.Ordinal)
            || !int.TryParse(paramsParts[1].AsSpan(2), NumberStyles.Integer, CultureInfo.InvariantCulture, out iterations))
            return false;
        if (!paramsParts[2].StartsWith("p=", StringComparison.Ordinal)
            || !int.TryParse(paramsParts[2].AsSpan(2), NumberStyles.Integer, CultureInfo.InvariantCulture, out parallelism))
            return false;

        try
        {
            salt = Convert.FromBase64String(PadBase64(parts[3]));
            hash = Convert.FromBase64String(PadBase64(parts[4]));
            return salt.Length > 0 && hash.Length > 0;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private static string PadBase64(string value)
    {
        var pad = 4 - (value.Length % 4);
        return pad is 4 ? value : value + new string('=', pad);
    }
}
