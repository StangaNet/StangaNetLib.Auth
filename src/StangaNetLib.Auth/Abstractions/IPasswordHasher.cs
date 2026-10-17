namespace StangaNetLib.Auth.Abstractions;

/// <summary>Hashes and verifies passwords using BCrypt with SHA-512 pre-hashing.</summary>
public interface IPasswordHasher
{
    /// <summary>Produces a salted BCrypt hash of the given plain-text password.</summary>
    /// <param name="password">The plain-text password to hash.</param>
    /// <returns>A BCrypt hash string that includes the embedded salt.</returns>
    string Hash(string password);

    /// <summary>
    /// Returns <c>true</c> if <paramref name="password"/> matches <paramref name="hash"/>.
    /// Timing-safe comparison — safe against timing attacks.
    /// </summary>
    /// <param name="password">The plain-text password to verify.</param>
    /// <param name="hash">The previously stored BCrypt hash.</param>
    /// <returns><c>true</c> if the password matches the hash; <c>false</c> otherwise.</returns>
    bool Verify(string password, string hash);
}
