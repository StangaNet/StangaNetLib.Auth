using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using StangaNetLib.Auth.Abstractions;
using StangaNetLib.Auth.Services;
using StangaNetLib.Auth.Services.External;
using StangaNetLib.Auth.Settings;
using StangaNetLib.Resilience.Execution;

namespace StangaNetLib.Auth.Extensions;

/// <summary>Extension methods for registering StangaNetLib.Auth services into an <see cref="Microsoft.Extensions.DependencyInjection.IServiceCollection"/>.</summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers JWT Bearer authentication (self-signed, HMAC-SHA256), <see cref="IJwtTokenGenerator"/>,
    /// <see cref="IPasswordHasher"/>, and <see cref="ITokenRevocationService"/>.
    /// </summary>
    /// <remarks>
    /// The consuming project must register its own <see cref="IRefreshTokenRepository"/> implementation,
    /// or call <see cref="AddStangaNetLibAuthInMemoryTokenStore"/> for dev/test environments.
    /// </remarks>
    /// <param name="services">The service collection to register into.</param>
    /// <param name="configuration">Application configuration used to bind <see cref="JwtSettings"/>.</param>
    /// <returns>The same <see cref="IServiceCollection"/> for chaining.</returns>
    public static IServiceCollection AddStangaNetLibAuth(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        services.AddOptions<JwtSettings>()
            .Bind(configuration.GetSection(JwtSettings.SectionName))
            .ValidateDataAnnotations()
            .ValidateOnStart();

        var settings = configuration
            .GetSection(JwtSettings.SectionName)
            .Get<JwtSettings>()
            ?? throw new InvalidOperationException(
                $"Missing required configuration section '{JwtSettings.SectionName}'.");

        services.AddSingleton<IJwtTokenGenerator, JwtTokenGenerator>();
        services.TryAddSingleton<IPasswordHasher, PasswordHasher>();
        services.AddSingleton<ITokenRevocationService, CacheTokenRevocationService>();

        services
            .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer(options =>
            {
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey         = new SymmetricSecurityKey(
                                                   Encoding.UTF8.GetBytes(settings.Secret)),
                    ValidateIssuer           = true,
                    ValidIssuer              = settings.Issuer,
                    ValidateAudience         = true,
                    ValidAudience            = settings.Audience,
                    ClockSkew                = TimeSpan.Zero,
                };
            });

        services.AddAuthorization();

        return services;
    }

    /// <summary>
    /// Registers JWT Bearer authentication delegated to Auth0 (RS256, JWKS endpoint),
    /// <see cref="IPasswordHasher"/>, and <see cref="ITokenRevocationService"/>.
    /// </summary>
    /// <remarks>
    /// Token generation is handled by Auth0 — <see cref="IJwtTokenGenerator"/> is not registered.
    /// To also enable user/role management via the Auth0 Management API,
    /// call <see cref="AddStangaNetLibAuth0ManagementService"/> after this.
    /// </remarks>
    /// <param name="services">The service collection to register into.</param>
    /// <param name="configuration">Application configuration used to bind <see cref="Auth0Settings"/>.</param>
    /// <returns>The same <see cref="IServiceCollection"/> for chaining.</returns>
    public static IServiceCollection AddStangaNetLibAuth0(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        services.AddOptions<Auth0Settings>()
            .Bind(configuration.GetSection(Auth0Settings.SectionName))
            .ValidateDataAnnotations()
            .ValidateOnStart();

        var settings = configuration
            .GetSection(Auth0Settings.SectionName)
            .Get<Auth0Settings>()
            ?? throw new InvalidOperationException(
                $"Missing required configuration section '{Auth0Settings.SectionName}'.");

        services.TryAddSingleton<IPasswordHasher, PasswordHasher>();
        services.AddSingleton<ITokenRevocationService, CacheTokenRevocationService>();

        services
            .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer(options =>
            {
                // Auth0 exposes its JWKS at https://{domain}/.well-known/jwks.json.
                // Setting Authority tells the JwtBearer middleware to discover it automatically.
                options.Authority = $"https://{settings.Domain}/";
                options.Audience  = settings.Audience;
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateAudience = true,
                    ValidateIssuer   = true,
                    ClockSkew        = TimeSpan.Zero,
                };
            });

        services.AddAuthorization();

        return services;
    }

    /// <summary>
    /// Registers <see cref="IAuth0ManagementService"/> for interacting with the Auth0 Management API.
    /// Requires <c>Auth0Settings.ManagementClientId</c> and <c>ManagementClientSecret</c>.
    /// Can be called standalone or after <see cref="AddStangaNetLibAuth0"/>.
    /// </summary>
    /// <param name="services">The service collection to register into.</param>
    /// <param name="configuration">Application configuration used to bind <see cref="Auth0Settings"/>.</param>
    /// <param name="configureHttpClient">
    /// Optional callback to further configure the <see cref="IHttpClientBuilder"/> for the Auth0 management
    /// <see cref="System.Net.Http.HttpClient"/>.
    /// Use this hook to attach resilience handlers, delegating handlers, or logging.
    /// Example using <c>Microsoft.Extensions.Http.Resilience</c> (Polly 8):
    /// <code>
    /// services.AddStangaNetLibAuth0ManagementService(config,
    ///     b => b.AddResilienceHandler("Auth0", p =>
    ///     {
    ///         p.AddRetry(new HttpRetryStrategyOptions { MaxRetryAttempts = 3 });
    ///         p.AddCircuitBreaker(new HttpCircuitBreakerStrategyOptions());
    ///         p.AddTimeout(TimeSpan.FromSeconds(10));
    ///     }));
    /// </code>
    /// </param>
    /// <returns>The same <see cref="IServiceCollection"/> for chaining.</returns>
    public static IServiceCollection AddStangaNetLibAuth0ManagementService(
        this IServiceCollection services,
        IConfiguration configuration,
        Action<IHttpClientBuilder>? configureHttpClient = null)
    {
        services.AddOptions<Auth0Settings>()
            .Bind(configuration.GetSection(Auth0Settings.SectionName))
            .ValidateDataAnnotations()
            .ValidateOnStart();

        services.AddSingleton<Auth0ManagementTokenCache>();

        const string ClientName = "StangaNetLibAuth0Management";
        var builder = services.AddHttpClient(ClientName);
        configureHttpClient?.Invoke(builder);

        services.AddSingleton<IAuth0ManagementService>(sp =>
            new Auth0ManagementService(
                sp.GetRequiredService<IHttpClientFactory>().CreateClient(ClientName),
                sp.GetRequiredService<IOptions<Auth0Settings>>(),
                sp.GetRequiredService<Auth0ManagementTokenCache>(),
                sp.GetService<IResilientExecutor>()));

        return services;
    }

    /// <summary>
    /// Registers <see cref="InMemoryRefreshTokenRepository"/> as <see cref="IRefreshTokenRepository"/>.
    /// Use only for development and testing — data is not persisted across restarts.
    /// </summary>
    /// <param name="services">The service collection to register into.</param>
    /// <returns>The same <see cref="IServiceCollection"/> for chaining.</returns>
    public static IServiceCollection AddStangaNetLibAuthInMemoryTokenStore(
        this IServiceCollection services)
    {
        services.AddSingleton<IRefreshTokenRepository, InMemoryRefreshTokenRepository>();
        return services;
    }

    /// <summary>
    /// Replaces the password hasher with Argon2id (PHC string format).
    /// Call after <see cref="AddStangaNetLibAuth"/> or <see cref="AddStangaNetLibAuth0"/>.
    /// </summary>
    public static IServiceCollection AddStangaNetLibAuthArgon2id(
        this IServiceCollection services,
        IConfiguration? configuration = null,
        Action<Argon2idSettings>? configure = null)
    {
        var options = services.AddOptions<Argon2idSettings>();
        if (configuration is not null)
            options.Bind(configuration.GetSection(Argon2idSettings.SectionName));
        if (configure is not null)
            options.Configure(configure);
        options.ValidateDataAnnotations().ValidateOnStart();

        services.RemoveAll<IPasswordHasher>();
        services.AddSingleton<IPasswordHasher, Argon2idPasswordHasher>();
        return services;
    }

    /// <summary>
    /// Registers <see cref="ITotpService"/> for RFC 6238 TOTP MFA and recovery codes.
    /// </summary>
    public static IServiceCollection AddStangaNetLibAuthTotp(
        this IServiceCollection services,
        IConfiguration? configuration = null,
        Action<TotpSettings>? configure = null)
    {
        var options = services.AddOptions<TotpSettings>();
        if (configuration is not null)
            options.Bind(configuration.GetSection(TotpSettings.SectionName));
        if (configure is not null)
            options.Configure(configure);
        options.ValidateDataAnnotations().ValidateOnStart();

        services.TryAddSingleton<ITotpService, TotpService>();
        return services;
    }

    /// <summary>
    /// Registers <see cref="ILoginAttemptService"/> (in-memory) with lockout settings.
    /// </summary>
    public static IServiceCollection AddStangaNetLibAuthLoginLockout(
        this IServiceCollection services,
        IConfiguration? configuration = null,
        Action<LoginLockoutSettings>? configure = null)
    {
        var options = services.AddOptions<LoginLockoutSettings>();
        if (configuration is not null)
            options.Bind(configuration.GetSection(LoginLockoutSettings.SectionName));
        if (configure is not null)
            options.Configure(configure);
        options.ValidateDataAnnotations().ValidateOnStart();

        services.TryAddSingleton<ILoginAttemptService, InMemoryLoginAttemptService>();
        return services;
    }

    /// <summary>
    /// Self-hosted profile: HMAC JWT + refresh primitives, Argon2id hasher, TOTP, and login lockout.
    /// Does not register Auth0 or external IdP providers.
    /// </summary>
    /// <remarks>
    /// Register an <see cref="IRefreshTokenRepository"/> (or call
    /// <see cref="AddStangaNetLibAuthInMemoryTokenStore"/>) separately.
    /// </remarks>
    public static IServiceCollection AddStangaNetLibAuthSelfHosted(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        services.AddStangaNetLibAuth(configuration);
        services.AddStangaNetLibAuthArgon2id(configuration);
        services.AddStangaNetLibAuthTotp(configuration);
        services.AddStangaNetLibAuthLoginLockout(configuration);
        return services;
    }

    /// <summary>
    /// Registers Google ID-token validation as an <see cref="IExternalIdentityProvider"/>
    /// and ensures <see cref="IExternalIdentityService"/> is available.
    /// Bind settings from <see cref="GoogleExternalAuthSettings.SectionName"/>.
    /// </summary>
    public static IServiceCollection AddStangaNetLibAuthExternalGoogle(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        services.AddOptions<GoogleExternalAuthSettings>()
            .Bind(configuration.GetSection(GoogleExternalAuthSettings.SectionName))
            .ValidateDataAnnotations()
            .ValidateOnStart();

        EnsureExternalIdentityService(services);
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IExternalIdentityProvider, GoogleExternalIdentityProvider>());

        return services;
    }

    /// <summary>
    /// Registers Sign in with Apple identity-token validation as an <see cref="IExternalIdentityProvider"/>
    /// and ensures <see cref="IExternalIdentityService"/> is available.
    /// Bind settings from <see cref="AppleExternalAuthSettings.SectionName"/>.
    /// </summary>
    public static IServiceCollection AddStangaNetLibAuthExternalApple(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        services.AddOptions<AppleExternalAuthSettings>()
            .Bind(configuration.GetSection(AppleExternalAuthSettings.SectionName))
            .ValidateDataAnnotations()
            .ValidateOnStart();

        EnsureExternalIdentityService(services);
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IExternalIdentityProvider, AppleExternalIdentityProvider>());

        return services;
    }

    /// <summary>
    /// Registers Facebook access-token validation (Graph <c>debug_token</c> + <c>/me</c>)
    /// as an <see cref="IExternalIdentityProvider"/> and ensures <see cref="IExternalIdentityService"/> is available.
    /// Bind settings from <see cref="FacebookExternalAuthSettings.SectionName"/>.
    /// </summary>
    /// <param name="services">The service collection to register into.</param>
    /// <param name="configuration">Application configuration used to bind <see cref="FacebookExternalAuthSettings"/>.</param>
    /// <param name="configureHttpClient">
    /// Optional callback to attach resilience handlers or logging to the Facebook Graph <see cref="HttpClient"/>.
    /// </param>
    /// <returns>The same <see cref="IServiceCollection"/> for chaining.</returns>
    public static IServiceCollection AddStangaNetLibAuthExternalFacebook(
        this IServiceCollection services,
        IConfiguration configuration,
        Action<IHttpClientBuilder>? configureHttpClient = null)
    {
        services.AddOptions<FacebookExternalAuthSettings>()
            .Bind(configuration.GetSection(FacebookExternalAuthSettings.SectionName))
            .ValidateDataAnnotations()
            .ValidateOnStart();

        var builder = services.AddHttpClient(FacebookExternalIdentityProvider.HttpClientName);
        configureHttpClient?.Invoke(builder);

        EnsureExternalIdentityService(services);
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IExternalIdentityProvider, FacebookExternalIdentityProvider>());

        return services;
    }

    /// <summary>
    /// Registers Microsoft identity platform ID-token validation as an <see cref="IExternalIdentityProvider"/>
    /// and ensures <see cref="IExternalIdentityService"/> is available.
    /// Bind settings from <see cref="MicrosoftExternalAuthSettings.SectionName"/>.
    /// </summary>
    public static IServiceCollection AddStangaNetLibAuthExternalMicrosoft(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        services.AddOptions<MicrosoftExternalAuthSettings>()
            .Bind(configuration.GetSection(MicrosoftExternalAuthSettings.SectionName))
            .ValidateDataAnnotations()
            .ValidateOnStart();

        EnsureExternalIdentityService(services);
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IExternalIdentityProvider, MicrosoftExternalIdentityProvider>());

        return services;
    }

    private static void EnsureExternalIdentityService(IServiceCollection services)
    {
        services.TryAddSingleton<IExternalIdentityService, ExternalIdentityService>();
    }
}

