using FluentAssertions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using StangaNetLib.Auth.Abstractions;
using StangaNetLib.Auth.Extensions;
using StangaNetLib.Auth.Models;
using StangaNetLib.Auth.Services;
using StangaNetLib.Auth.Services.External;
using StangaNetLib.Caching.Extensions;

namespace StangaNetLib.Auth.Tests.Extensions;

public sealed class ServiceCollectionExtensionsTests
{
    [Fact]
    public void AddStangaNetLibAuth_RegistersExpectedServices()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["JwtSettings:Secret"] = "test-secret-key-must-be-at-least-32-characters",
                ["JwtSettings:Issuer"] = "test-issuer",
                ["JwtSettings:Audience"] = "test-audience",
            })
            .Build();

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddStangaNetLibInMemoryCache();
        services.AddStangaNetLibAuth(configuration);
        services.AddStangaNetLibAuthInMemoryTokenStore();

        using var provider = services.BuildServiceProvider();

        provider.GetRequiredService<IJwtTokenGenerator>().Should().BeOfType<JwtTokenGenerator>();
        provider.GetRequiredService<IPasswordHasher>().Should().BeOfType<PasswordHasher>();
        provider.GetRequiredService<ITokenRevocationService>().Should().BeOfType<CacheTokenRevocationService>();
        provider.GetRequiredService<IRefreshTokenRepository>().Should().BeOfType<InMemoryRefreshTokenRepository>();
    }

    [Fact]
    public void AddStangaNetLibAuthInMemoryTokenStore_RegistersRepository()
    {
        var services = new ServiceCollection();
        services.AddStangaNetLibAuthInMemoryTokenStore();

        using var provider = services.BuildServiceProvider();
        provider.GetRequiredService<IRefreshTokenRepository>().Should().BeOfType<InMemoryRefreshTokenRepository>();
    }

    [Fact]
    public void AddStangaNetLibAuthExternalProviders_RegistersServiceAndProviders()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Auth:External:Google:ClientIds:0"] = "google-client",
                ["Auth:External:Apple:ClientIds:0"] = "apple.services.id",
                ["Auth:External:Facebook:AppId"] = "fb-app",
                ["Auth:External:Facebook:AppSecret"] = "fb-secret",
                ["Auth:External:Microsoft:ClientIds:0"] = "ms-client",
                ["Auth:External:Microsoft:TenantId"] = "common",
            })
            .Build();

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddStangaNetLibAuthExternalGoogle(configuration);
        services.AddStangaNetLibAuthExternalApple(configuration);
        services.AddStangaNetLibAuthExternalFacebook(configuration);
        services.AddStangaNetLibAuthExternalMicrosoft(configuration);

        using var provider = services.BuildServiceProvider();

        provider.GetRequiredService<IExternalIdentityService>().Should().BeOfType<ExternalIdentityService>();

        var providers = provider.GetServices<IExternalIdentityProvider>().ToList();
        providers.Should().HaveCount(4);
        providers.Select(p => p.ProviderName).Should().BeEquivalentTo(
        [
            ExternalAuthProviders.Google,
            ExternalAuthProviders.Apple,
            ExternalAuthProviders.Facebook,
            ExternalAuthProviders.Microsoft,
        ]);
    }

    [Fact]
    public void AddStangaNetLibAuthExternalGoogle_CalledTwice_RegistersSingleProvider()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Auth:External:Google:ClientIds:0"] = "google-client",
            })
            .Build();

        var services = new ServiceCollection();
        services.AddStangaNetLibAuthExternalGoogle(configuration);
        services.AddStangaNetLibAuthExternalGoogle(configuration);

        using var provider = services.BuildServiceProvider();
        provider.GetServices<IExternalIdentityProvider>().Should().ContainSingle();
        provider.GetServices<IExternalIdentityService>().Should().ContainSingle();
    }
}

