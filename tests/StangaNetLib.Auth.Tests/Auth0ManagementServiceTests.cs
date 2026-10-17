using System.Net;
using System.Net.Http.Json;
using FluentAssertions;
using Microsoft.Extensions.Options;
using StangaNetLib.Auth.Services;
using StangaNetLib.Auth.Settings;
using Xunit;

namespace StangaNetLib.Auth.Tests;

file sealed class FakeHttpHandler : HttpMessageHandler
{
    private readonly Func<HttpRequestMessage, HttpResponseMessage> _handle;
    public FakeHttpHandler(Func<HttpRequestMessage, HttpResponseMessage> handle) => _handle = handle;
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        => Task.FromResult(_handle(request));
}

public sealed class Auth0ManagementServiceTests
{
    private const string Domain = "test.auth0.com";

    private static Auth0ManagementService CreateSut(Func<HttpRequestMessage, HttpResponseMessage> handler)
    {
        var client   = new HttpClient(new FakeHttpHandler(handler));
        var settings = Options.Create(new Auth0Settings
        {
            Domain                 = Domain,
            Audience               = "https://api.test.com",
            ManagementClientId     = "mgmt-client",
            ManagementClientSecret = "mgmt-secret",
        });
        return new Auth0ManagementService(client, settings, new Auth0ManagementTokenCache());
    }

    private static HttpResponseMessage TokenOk()
        => new(HttpStatusCode.OK)
        {
            Content = JsonContent.Create(new { access_token = "mgmt-access-token", expires_in = 86400 })
        };

    private static bool IsTokenRequest(HttpRequestMessage req)
        => req.RequestUri!.AbsolutePath.EndsWith("/oauth/token");

    // -----------------------------------------------------------------------

    [Fact]
    public async Task GetUserAsync_UserExists_ReturnsUserInfo()
    {
        var callCount = 0;
        var sut = CreateSut(req =>
        {
            callCount++;
            if (IsTokenRequest(req)) return TokenOk();
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = JsonContent.Create(new
                {
                    user_id        = "auth0|123",
                    email          = "user@test.com",
                    email_verified = true,
                    blocked        = false,
                    created_at     = "2024-01-15T10:00:00.000Z",
                })
            };
        });

        var result = await sut.GetUserAsync("auth0|123", TestContext.Current.CancellationToken);

        result.IsSuccess.Should().BeTrue();
        result.Value!.UserId.Should().Be("auth0|123");
        result.Value.Email.Should().Be("user@test.com");
        result.Value.EmailVerified.Should().BeTrue();
        result.Value.Blocked.Should().BeFalse();
        callCount.Should().Be(2); // token + user
    }

    [Fact]
    public async Task GetUserAsync_TokenCached_SecondCallSkipsTokenRequest()
    {
        var tokenCalls = 0;
        var sut = CreateSut(req =>
        {
            if (IsTokenRequest(req)) { tokenCalls++; return TokenOk(); }
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = JsonContent.Create(new
                {
                    user_id        = "auth0|1",
                    email          = "a@b.com",
                    email_verified = false,
                    blocked        = false,
                    created_at     = "2024-01-01T00:00:00.000Z",
                })
            };
        });

        var ct = TestContext.Current.CancellationToken;
        await sut.GetUserAsync("auth0|1", ct);
        await sut.GetUserAsync("auth0|1", ct);

        tokenCalls.Should().Be(1);
    }

    [Fact]
    public async Task GetUserAsync_UserNotFound_ReturnsNotFoundError()
    {
        var sut = CreateSut(req =>
            IsTokenRequest(req)
                ? TokenOk()
                : new HttpResponseMessage(HttpStatusCode.NotFound));

        var result = await sut.GetUserAsync("auth0|missing", TestContext.Current.CancellationToken);

        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Contain("NotFound");
    }

    [Fact]
    public async Task GetUserAsync_ManagementTokenFails_ReturnsInternalError()
    {
        var sut = CreateSut(_ => new HttpResponseMessage(HttpStatusCode.Unauthorized));

        var result = await sut.GetUserAsync("auth0|123", TestContext.Current.CancellationToken);

        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be("Internal.Error");
    }

    [Fact]
    public async Task GetUserRolesAsync_ReturnsRoles()
    {
        var sut = CreateSut(req =>
        {
            if (IsTokenRequest(req)) return TokenOk();
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = JsonContent.Create(new[]
                {
                    new { id = "rol_1", name = "Admin",  description = "Admin role"  },
                    new { id = "rol_2", name = "Editor", description = "Editor role" },
                })
            };
        });

        var result = await sut.GetUserRolesAsync("auth0|123", TestContext.Current.CancellationToken);

        result.IsSuccess.Should().BeTrue();
        result.Value!.Should().HaveCount(2);
        result.Value[0].Name.Should().Be("Admin");
        result.Value[1].Name.Should().Be("Editor");
    }

    [Fact]
    public async Task AssignRolesAsync_Success_ReturnsOk()
    {
        var sut = CreateSut(req =>
            IsTokenRequest(req)
                ? TokenOk()
                : new HttpResponseMessage(HttpStatusCode.NoContent));

        var result = await sut.AssignRolesAsync("auth0|123", ["rol_1", "rol_2"],
            TestContext.Current.CancellationToken);

        result.IsSuccess.Should().BeTrue();
    }

    [Fact]
    public async Task BlockUserAsync_Success_ReturnsOk()
    {
        var sut = CreateSut(req =>
            IsTokenRequest(req)
                ? TokenOk()
                : new HttpResponseMessage(HttpStatusCode.OK)
                  {
                      Content = JsonContent.Create(new { blocked = true })
                  });

        var result = await sut.BlockUserAsync("auth0|123", TestContext.Current.CancellationToken);

        result.IsSuccess.Should().BeTrue();
    }

    [Fact]
    public async Task DeleteUserAsync_Success_ReturnsOk()
    {
        var sut = CreateSut(req =>
            IsTokenRequest(req)
                ? TokenOk()
                : new HttpResponseMessage(HttpStatusCode.NoContent));

        var result = await sut.DeleteUserAsync("auth0|123", TestContext.Current.CancellationToken);

        result.IsSuccess.Should().BeTrue();
    }

    [Fact]
    public async Task UpdateUserMetadataAsync_SendsPatchRequest()
    {
        HttpRequestMessage? captured = null;
        var sut = CreateSut(req =>
        {
            if (IsTokenRequest(req)) return TokenOk();
            captured = req;
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = JsonContent.Create(new { })
            };
        });

        var result = await sut.UpdateUserMetadataAsync("auth0|123",
            new Dictionary<string, object?> { ["plan"] = "pro" },
            TestContext.Current.CancellationToken);

        result.IsSuccess.Should().BeTrue();
        captured!.Method.Should().Be(HttpMethod.Patch);
    }
}
