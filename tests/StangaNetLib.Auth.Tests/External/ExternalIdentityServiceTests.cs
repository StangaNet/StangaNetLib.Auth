using System.Security.Claims;
using FluentAssertions;
using StangaNetLib.Auth.Abstractions;
using StangaNetLib.Auth.Models;
using StangaNetLib.Auth.Services.External;
using StangaNetLib.Core.Common;

namespace StangaNetLib.Auth.Tests.External;

file sealed class StubProvider : IExternalIdentityProvider
{
    private readonly Result<ExternalIdentity> _result;

    public StubProvider(string name, Result<ExternalIdentity> result)
    {
        ProviderName = name;
        _result      = result;
    }

    public string ProviderName { get; }

    public Task<Result<ExternalIdentity>> ValidateAsync(string token, CancellationToken ct = default)
        => Task.FromResult(_result);
}

public sealed class ExternalIdentityServiceTests
{
    [Fact]
    public async Task ValidateAsync_KnownProvider_Delegates()
    {
        var identity = new ExternalIdentity
        {
            Provider = ExternalAuthProviders.Google,
            Subject  = "sub-1",
        };
        var sut = new ExternalIdentityService(
        [
            new StubProvider(ExternalAuthProviders.Google, Result<ExternalIdentity>.Success(identity)),
        ]);

        var result = await sut.ValidateAsync("Google", "tok", TestContext.Current.CancellationToken);

        result.IsSuccess.Should().BeTrue();
        result.Value!.Subject.Should().Be("sub-1");
    }

    [Fact]
    public async Task ValidateAsync_UnknownProvider_Fails()
    {
        var sut = new ExternalIdentityService(
        [
            new StubProvider(ExternalAuthProviders.Google,
                Result<ExternalIdentity>.Success(new ExternalIdentity
                {
                    Provider = ExternalAuthProviders.Google,
                    Subject  = "x",
                })),
        ]);

        var result = await sut.ValidateAsync("twitter", "tok", TestContext.Current.CancellationToken);

        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be(ExternalAuthErrorCodes.UnknownProvider);
    }

    [Fact]
    public async Task GoogleProvider_EndToEnd_ViaService()
    {
        var (key, creds) = TestJwtHelper.CreateRsa();
        var token = TestJwtHelper.CreateToken(
            creds,
            issuer: "accounts.google.com",
            audience: "c1",
            claims: [new Claim("sub", "g1"), new Claim("email", "a@b.c")]);

        var validator = OidcIdTokenValidator.FromSigningKeys(
            [key], ["c1"], ["https://accounts.google.com", "accounts.google.com"]);

        var sut = new ExternalIdentityService([new GoogleExternalIdentityProvider(validator)]);
        var result = await sut.ValidateAsync(ExternalAuthProviders.Google, token, TestContext.Current.CancellationToken);

        result.IsSuccess.Should().BeTrue();
        result.Value!.Email.Should().Be("a@b.c");
    }
}
