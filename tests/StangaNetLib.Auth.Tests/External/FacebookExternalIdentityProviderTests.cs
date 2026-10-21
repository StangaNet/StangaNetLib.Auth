using System.Net;
using System.Net.Http.Json;
using FluentAssertions;
using Microsoft.Extensions.Options;
using StangaNetLib.Auth.Models;
using StangaNetLib.Auth.Services.External;
using StangaNetLib.Auth.Settings;

namespace StangaNetLib.Auth.Tests.External;

file sealed class FakeHttpHandler : HttpMessageHandler
{
    private readonly Func<HttpRequestMessage, HttpResponseMessage> _handle;

    public FakeHttpHandler(Func<HttpRequestMessage, HttpResponseMessage> handle) => _handle = handle;

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        => Task.FromResult(_handle(request));
}

public sealed class FacebookExternalIdentityProviderTests
{
    private const string AppId     = "fb-app-id";
    private const string AppSecret = "fb-app-secret";

    private static FacebookExternalIdentityProvider CreateSut(
        Func<HttpRequestMessage, HttpResponseMessage> handler)
    {
        var client = new HttpClient(new FakeHttpHandler(handler));
        var settings = Options.Create(new FacebookExternalAuthSettings
        {
            AppId     = AppId,
            AppSecret = AppSecret,
        });
        return new FacebookExternalIdentityProvider(client, settings);
    }

    [Fact]
    public async Task ValidateAsync_ValidToken_ReturnsIdentity()
    {
        var sut = CreateSut(req =>
        {
            var path = req.RequestUri!.AbsolutePath;
            if (path.Contains("debug_token", StringComparison.Ordinal))
            {
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = JsonContent.Create(new
                    {
                        data = new
                        {
                            app_id   = AppId,
                            user_id  = "fb-user-1",
                            is_valid = true,
                        },
                    }),
                };
            }

            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = JsonContent.Create(new
                {
                    id    = "fb-user-1",
                    email = "fb@example.com",
                    name  = "FB User",
                    picture = new
                    {
                        data = new { url = "https://example.com/fb.png" },
                    },
                }),
            };
        });

        var result = await sut.ValidateAsync("user-access-token", TestContext.Current.CancellationToken);

        result.IsSuccess.Should().BeTrue();
        result.Value!.Provider.Should().Be(ExternalAuthProviders.Facebook);
        result.Value.Subject.Should().Be("fb-user-1");
        result.Value.Email.Should().Be("fb@example.com");
        result.Value.EmailVerified.Should().BeTrue();
        result.Value.DisplayName.Should().Be("FB User");
        result.Value.PictureUrl.Should().Be("https://example.com/fb.png");
    }

    [Fact]
    public async Task ValidateAsync_InvalidToken_Fails()
    {
        var sut = CreateSut(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = JsonContent.Create(new
            {
                data = new
                {
                    app_id   = AppId,
                    is_valid = false,
                },
            }),
        });

        var result = await sut.ValidateAsync("bad-token", TestContext.Current.CancellationToken);

        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be(ExternalAuthErrorCodes.InvalidToken);
    }

    [Fact]
    public async Task ValidateAsync_WrongAppId_Fails()
    {
        var sut = CreateSut(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = JsonContent.Create(new
            {
                data = new
                {
                    app_id   = "other-app",
                    is_valid = true,
                },
            }),
        });

        var result = await sut.ValidateAsync("token", TestContext.Current.CancellationToken);

        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be(ExternalAuthErrorCodes.InvalidToken);
    }

    [Fact]
    public async Task ValidateAsync_EmptyToken_Fails()
    {
        var sut = CreateSut(_ => throw new InvalidOperationException("should not call HTTP"));

        var result = await sut.ValidateAsync(" ", TestContext.Current.CancellationToken);

        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be(ExternalAuthErrorCodes.EmptyToken);
    }
}
