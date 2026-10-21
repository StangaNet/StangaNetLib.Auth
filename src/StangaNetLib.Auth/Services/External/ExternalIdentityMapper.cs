using System.Security.Claims;
using StangaNetLib.Auth.Models;

namespace StangaNetLib.Auth.Services.External;

internal static class ExternalIdentityMapper
{
    public static ExternalIdentity FromPrincipal(string provider, ClaimsPrincipal principal)
    {
        var claims = principal.Claims
            .GroupBy(c => c.Type, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.First().Value, StringComparer.OrdinalIgnoreCase);

        var subject = FindClaim(claims,
            ClaimTypes.NameIdentifier,
            "sub");

        if (string.IsNullOrWhiteSpace(subject))
            throw new InvalidOperationException("Validated token is missing a subject (sub) claim.");

        var email = FindClaim(claims, ClaimTypes.Email, "email");
        var name  = FindClaim(claims, ClaimTypes.Name, "name");
        var picture = FindClaim(claims, "picture");

        return new ExternalIdentity
        {
            Provider      = provider,
            Subject       = subject,
            Email         = string.IsNullOrWhiteSpace(email) ? null : email,
            EmailVerified = ParseEmailVerified(FindClaim(claims, "email_verified")),
            DisplayName   = string.IsNullOrWhiteSpace(name) ? null : name,
            PictureUrl    = string.IsNullOrWhiteSpace(picture) ? null : picture,
            RawClaims     = claims,
        };
    }

    private static string? FindClaim(IReadOnlyDictionary<string, string> claims, params string[] keys)
    {
        foreach (var key in keys)
        {
            if (claims.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value))
                return value;
        }

        return null;
    }

    private static bool ParseEmailVerified(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return false;

        if (bool.TryParse(value, out var b))
            return b;

        return value == "1"
               || string.Equals(value, "true", StringComparison.OrdinalIgnoreCase);
    }
}

