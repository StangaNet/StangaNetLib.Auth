namespace StangaNetLib.Auth.Abstractions;

/// <summary>
/// Hashes and verifies passwords. Default DI registration uses BCrypt (SHA-512 pre-hash);
/// call <c>AddStangaNetLibAuthArgon2id</c> (or the self-hosted profile) to switch to Argon2id.
/// </summary>
public interface IPasswordHasher
{
    /// <summary>Produces a salted hash of the given plain-text password.</summary>
    /// <param name="password">The plain-text password to hash.</param>
    /// <returns>An algorithm-specific hash string that includes the embedded salt.</returns>
    string Hash(string password);

    /// <summary>
    /// Returns <c>true</c> if <paramref name="password"/> matches <paramref name="hash"/>.
    /// Timing-safe comparison — safe against timing attacks.
    /// </summary>
    /// <param name="password">The plain-text password to verify.</param>
    /// <param name="hash">The previously stored password hash.</param>
    /// <returns><c>true</c> if the password matches the hash; <c>false</c> otherwise.</returns>
    bool Verify(string password, string hash);
}
