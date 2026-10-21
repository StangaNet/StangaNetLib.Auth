using System.Security.Claims;
using FluentAssertions;
using StangaNetLib.Auth.Models;
using StangaNetLib.Auth.Services.External;
using StangaNetLib.Auth.Settings;

namespace StangaNetLib.Auth.Tests.External;

public sealed class OidcExternalProviderTests
{
    [Fact]
    public async Task Google_ValidToken_ReturnsIdentity()
    {
        var (key, creds) = TestJwtHelper.CreateRsa();
        var token = TestJwtHelper.CreateToken(
            creds,
            issuer: "https://accounts.google.com",
            audience: "google-client",
            claims:
            [
                new Claim("sub", "google-sub-1"),
                new Claim("email", "user@gmail.com"),
                new Claim("email_verified", "true"),
                new Claim("name", "Ada Lovelace"),
                new Claim("picture", "https://example.com/a.png"),
            ]);

        var validator = OidcIdTokenValidator.FromSigningKeys(
            [key],
            ["google-client"],
            ["https://accounts.google.com", "accounts.google.com"]);

        var sut = new GoogleExternalIdentityProvider(validator);
        var result = await sut.ValidateAsync(token, TestContext.Current.CancellationToken);

        result.IsSuccess.Should().BeTrue();
        result.Value!.Provider.Should().Be(ExternalAuthProviders.Google);
        result.Value.Subject.Should().Be("google-sub-1");
        result.Value.Email.Should().Be("user@gmail.com");
        result.Value.EmailVerified.Should().BeTrue();
        result.Value.DisplayName.Should().Be("Ada Lovelace");
        result.Value.PictureUrl.Should().Be("https://example.com/a.png");
    }

    [Fact]
    public async Task Google_WrongAudience_Fails()
    {
        var (key, creds) = TestJwtHelper.CreateRsa();
        var token = TestJwtHelper.CreateToken(
            creds,
            issuer: "https://accounts.google.com",
            audience: "other-client",
            claims: [new Claim("sub", "x")]);

        var validator = OidcIdTokenValidator.FromSigningKeys(
            [key],
            ["google-client"],
            ["https://accounts.google.com"]);

        var sut = new GoogleExternalIdentityProvider(validator);
        var result = await sut.ValidateAsync(token, TestContext.Current.CancellationToken);

        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be(ExternalAuthErrorCodes.InvalidToken);
    }

    [Fact]
    public async Task Apple_ValidToken_WithoutEmail_Succeeds()
    {
        var (key, creds) = TestJwtHelper.CreateRsa();
        var token = TestJwtHelper.CreateToken(
            creds,
            issuer: "https://appleid.apple.com",
            audience: "com.example.app",
            claims: [new Claim("sub", "apple.sub.001")]);

        var validator = OidcIdTokenValidator.FromSigningKeys(
            [key],
            ["com.example.app"],
            ["https://appleid.apple.com"]);

        var sut = new AppleExternalIdentityProvider(validator);
        var result = await sut.ValidateAsync(token, TestContext.Current.CancellationToken);

        result.IsSuccess.Should().BeTrue();
        result.Value!.Provider.Should().Be(ExternalAuthProviders.Apple);
        result.Value.Subject.Should().Be("apple.sub.001");
        result.Value.Email.Should().BeNull();
        result.Value.EmailVerified.Should().BeFalse();
    }

    [Fact]
    public async Task Microsoft_CommonTenant_AcceptsTenantIssuer()
    {
        var (key, creds) = TestJwtHelper.CreateRsa();
        var tenantId = Guid.NewGuid().ToString();
        var token = TestJwtHelper.CreateToken(
            creds,
            issuer: $"https://login.microsoftonline.com/{tenantId}/v2.0",
            audience: "ms-client",
            claims:
            [
                new Claim("sub", "ms-sub"),
                new Claim("email", "user@contoso.com"),
                new Claim("name", "Contoso User"),
            ]);

        var settings = new MicrosoftExternalAuthSettings
        {
            ClientIds = ["ms-client"],
            TenantId  = "common",
        };

        var validator = MicrosoftExternalIdentityProvider.CreateValidatorForTests(settings, [key]);
        var sut = new MicrosoftExternalIdentityProvider(validator);
        var result = await sut.ValidateAsync(token, TestContext.Current.CancellationToken);

        result.IsSuccess.Should().BeTrue();
        result.Value!.Provider.Should().Be(ExternalAuthProviders.Microsoft);
        result.Value.Subject.Should().Be("ms-sub");
        result.Value.Email.Should().Be("user@contoso.com");
    }

    [Fact]
    public async Task Microsoft_SpecificTenant_RejectsOtherIssuer()
    {
        var (key, creds) = TestJwtHelper.CreateRsa();
        var token = TestJwtHelper.CreateToken(
            creds,
            issuer: $"https://login.microsoftonline.com/{Guid.NewGuid()}/v2.0",
            audience: "ms-client",
            claims: [new Claim("sub", "ms-sub")]);

        var settings = new MicrosoftExternalAuthSettings
        {
            ClientIds = ["ms-client"],
            TenantId  = Guid.NewGuid().ToString(),
        };

        var validator = MicrosoftExternalIdentityProvider.CreateValidatorForTests(settings, [key]);
        var sut = new MicrosoftExternalIdentityProvider(validator);
        var result = await sut.ValidateAsync(token, TestContext.Current.CancellationToken);

        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be(ExternalAuthErrorCodes.InvalidToken);
    }

    [Fact]
    public async Task Oidc_EmptyToken_FailsWithEmptyCode()
    {
        var (key, _) = TestJwtHelper.CreateRsa();
        var validator = OidcIdTokenValidator.FromSigningKeys(
            [key],
            ["aud"],
            ["https://accounts.google.com"]);

        var result = await validator.ValidateAsync("  ", TestContext.Current.CancellationToken);

        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be(ExternalAuthErrorCodes.EmptyToken);
    }
}
