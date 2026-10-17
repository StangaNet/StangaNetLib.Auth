using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using StangaNetLib.Auth.Abstractions;
using StangaNetLib.Auth.Models;
using StangaNetLib.Auth.Settings;

namespace StangaNetLib.Auth.Services;

/// <summary>
/// HMAC-SHA256 JWT implementation of <see cref="IJwtTokenGenerator"/>.
/// Signing credentials and validation parameters are computed once at construction time.
/// </summary>
public sealed class JwtTokenGenerator : IJwtTokenGenerator
{
    private static readonly JwtSecurityTokenHandler _handler = new();

    private readonly JwtSettings                _settings;
    private readonly SigningCredentials         _signingCredentials;
    private readonly TokenValidationParameters  _validationParams;

    /// <summary>Creates a generator bound to the given <see cref="JwtSettings"/>.</summary>
    /// <param name="settings">JWT signing and validation settings.</param>
    public JwtTokenGenerator(IOptions<JwtSettings> settings)
    {
        _settings = settings.Value;

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_settings.Secret));
        _signingCredentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        _validationParams = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey         = key,
            ValidateIssuer           = true,
            ValidIssuer              = _settings.Issuer,
            ValidateAudience         = true,
            ValidAudience            = _settings.Audience,
            ClockSkew                = TimeSpan.Zero,
        };
    }

    /// <inheritdoc />
    public string GenerateAccessToken(string userId, string email, IEnumerable<string> roles, string deviceId)
    {
        var claims = new List<Claim>
        {
            new(JwtClaims.UserId,   userId),
            new(JwtClaims.Email,    email),
            new(JwtClaims.DeviceId, deviceId),
            new(JwtClaims.TokenId,  Guid.NewGuid().ToString()),
        };

        foreach (var role in roles)
            claims.Add(new Claim(JwtClaims.Role, role));

        var token = new JwtSecurityToken(
            issuer:             _settings.Issuer,
            audience:           _settings.Audience,
            claims:             claims,
            expires:            DateTime.UtcNow.AddMinutes(_settings.AccessTokenExpiryMinutes),
            signingCredentials: _signingCredentials);

        return _handler.WriteToken(token);
    }

    /// <inheritdoc />
    public string GenerateRefreshToken()
        => Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));

    /// <inheritdoc />
    public string? GetTokenId(string accessToken)
    {
        if (!_handler.CanReadToken(accessToken)) return null;
        return _handler.ReadJwtToken(accessToken).Claims
            .FirstOrDefault(c => c.Type == JwtClaims.TokenId)?.Value;
    }

    /// <inheritdoc />
    public bool ValidateToken(string token, out string? tokenId)
    {
        tokenId = null;
        try
        {
            _handler.ValidateToken(token, _validationParams, out var validated);
            tokenId = ((JwtSecurityToken)validated).Claims
                .FirstOrDefault(c => c.Type == JwtClaims.TokenId)?.Value;
            return true;
        }
        catch (Exception ex) when (ex is SecurityTokenException or ArgumentException)
        {
            return false;
        }
    }
}
