using FluentAssertions;
using Microsoft.Extensions.Options;
using StangaNetLib.Auth.Services;
using StangaNetLib.Auth.Settings;
using Xunit;

namespace StangaNetLib.Auth.Tests;

public sealed class JwtTokenGeneratorTests
{
    private static JwtTokenGenerator CreateSut() => new(Options.Create(new JwtSettings
    {
        Secret                   = "test-secret-key-must-be-at-least-32-characters",
        Issuer                   = "test-issuer",
        Audience                 = "test-audience",
        AccessTokenExpiryMinutes = 15,
        RefreshTokenExpiryDays   = 30,
    }));

    [Fact]
    public void GenerateAccessToken_ReturnsWellFormedJwt()
    {
        var token = CreateSut().GenerateAccessToken("u1", "u@test.com", ["User"], "dev1");
        token.Should().NotBeNullOrEmpty();
        token.Split('.').Should().HaveCount(3); // header.payload.signature
    }

    [Fact]
    public void GetTokenId_ReturnsJtiClaim()
    {
        var sut   = CreateSut();
        var token = sut.GenerateAccessToken("u1", "u@test.com", ["User"], "dev1");
        sut.GetTokenId(token).Should().NotBeNullOrEmpty();
    }

    [Fact]
    public void GetTokenId_WithNonJwtString_ReturnsNull()
    {
        CreateSut().GetTokenId("not-a-token").Should().BeNull();
    }

    [Fact]
    public void ValidateToken_WithValidToken_ReturnsTrueAndNonNullTokenId()
    {
        var sut   = CreateSut();
        var token = sut.GenerateAccessToken("u1", "u@test.com", ["User"], "dev1");
        var ok    = sut.ValidateToken(token, out var tokenId);
        ok.Should().BeTrue();
        tokenId.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public void ValidateToken_WithTamperedSignature_ReturnsFalse()
    {
        var sut     = CreateSut();
        var token   = sut.GenerateAccessToken("u1", "u@test.com", ["User"], "dev1");
        var tampered = token[..^5] + "XXXXX";
        sut.ValidateToken(tampered, out _).Should().BeFalse();
    }

    [Fact]
    public void GenerateAccessToken_TwoCallsProduceDifferentJti()
    {
        var sut  = CreateSut();
        var jti1 = sut.GetTokenId(sut.GenerateAccessToken("u1", "u@test.com", ["User"], "dev1"));
        var jti2 = sut.GetTokenId(sut.GenerateAccessToken("u1", "u@test.com", ["User"], "dev1"));
        jti1.Should().NotBe(jti2);
    }

    [Fact]
    public void GenerateRefreshToken_EachCallReturnsUniqueBase64()
    {
        var sut    = CreateSut();
        var token1 = sut.GenerateRefreshToken();
        var token2 = sut.GenerateRefreshToken();
        token1.Should().NotBe(token2);
        Convert.FromBase64String(token1).Should().HaveCount(64);
    }

    [Fact]
    public void GenerateAccessToken_MultipleRoles_AllRolesEmbedded()
    {
        var sut   = CreateSut();
        var token = sut.GenerateAccessToken("u1", "u@test.com", ["Admin", "Editor"], "dev1");
        var jti   = sut.GetTokenId(token);

        // Decode without validation to inspect claims
        var handler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
        var jwt     = handler.ReadJwtToken(token);
        var roles   = jwt.Claims.Where(c => c.Type == "role").Select(c => c.Value).ToList();

        roles.Should().Contain("Admin");
        roles.Should().Contain("Editor");
        jti.Should().NotBeNullOrEmpty();
    }
}
