using StangaNetLib.Auth.Abstractions;

namespace StangaNetLib.Auth.Services;

/// <summary>BCrypt implementation with SHA-512 pre-hashing to support passwords longer than 72 bytes.</summary>
public sealed class PasswordHasher : IPasswordHasher
{
    /// <inheritdoc />
    public string Hash(string password)
        => BCrypt.Net.BCrypt.EnhancedHashPassword(password, BCrypt.Net.HashType.SHA512);

    /// <inheritdoc />
    public bool Verify(string password, string hash)
        => BCrypt.Net.BCrypt.EnhancedVerify(password, hash, BCrypt.Net.HashType.SHA512);
}
