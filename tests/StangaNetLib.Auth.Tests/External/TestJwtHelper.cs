using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

namespace StangaNetLib.Auth.Tests.External;

internal static class TestJwtHelper
{
    public static (RsaSecurityKey Key, SigningCredentials Credentials) CreateRsa()
    {
        var rsa = RSA.Create(2048);
        var key = new RsaSecurityKey(rsa) { KeyId = Guid.NewGuid().ToString("N") };
        return (key, new SigningCredentials(key, SecurityAlgorithms.RsaSha256));
    }

    public static string CreateToken(
        SigningCredentials credentials,
        string             issuer,
        string             audience,
        IEnumerable<Claim> claims,
        DateTime?          expires = null)
    {
        var token = new JwtSecurityToken(
            issuer:             issuer,
            audience:           audience,
            claims:             claims,
            notBefore:          DateTime.UtcNow.AddMinutes(-1),
            expires:            expires ?? DateTime.UtcNow.AddMinutes(10),
            signingCredentials: credentials);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}
