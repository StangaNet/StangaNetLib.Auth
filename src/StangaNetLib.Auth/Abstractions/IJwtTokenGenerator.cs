namespace StangaNetLib.Auth.Abstractions;

/// <summary>Generates and validates JWT access tokens, and produces refresh token strings.</summary>
public interface IJwtTokenGenerator
{
    /// <summary>Creates a signed access token embedding the given identity claims.</summary>
    /// <param name="userId">The subject identifier embedded as the <c>sub</c> claim.</param>
    /// <param name="email">The user's email address embedded as the <c>email</c> claim.</param>
    /// <param name="roles">One or more roles assigned to the user; each becomes a separate <c>role</c> claim.</param>
    /// <param name="deviceId">The device identifier embedded as the <c>device_id</c> claim.</param>
    /// <returns>A signed JWT string.</returns>
    string GenerateAccessToken(string userId, string email, IEnumerable<string> roles, string deviceId);

    /// <summary>Creates a cryptographically random refresh token string (not a JWT).</summary>
    /// <returns>A Base64-encoded string of 64 random bytes.</returns>
    string GenerateRefreshToken();

    /// <summary>
    /// Extracts the <c>jti</c> claim from an access token without signature validation.
    /// Use this to look up the token in the revocation blacklist.
    /// </summary>
    /// <param name="accessToken">The JWT string to read.</param>
    /// <returns>The token ID, or <c>null</c> if the string is not a readable JWT.</returns>
    string? GetTokenId(string accessToken);

    /// <summary>
    /// Validates the token signature, issuer, audience, and expiry.
    /// </summary>
    /// <param name="token">The access token to validate.</param>
    /// <param name="tokenId">The <c>jti</c> claim if validation succeeds; <c>null</c> otherwise.</param>
    /// <returns><c>true</c> if the token is valid and not expired.</returns>
    bool ValidateToken(string token, out string? tokenId);
}
