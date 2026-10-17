using FluentAssertions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using StangaNetLib.Auth.Abstractions;
using StangaNetLib.Auth.Extensions;
using StangaNetLib.Auth.Services;
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
}
