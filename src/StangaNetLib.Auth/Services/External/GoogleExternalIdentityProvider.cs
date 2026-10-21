using Microsoft.Extensions.Options;
using StangaNetLib.Auth.Abstractions;
using StangaNetLib.Auth.Models;
using StangaNetLib.Auth.Settings;
using StangaNetLib.Core.Common;

namespace StangaNetLib.Auth.Services.External;

internal sealed class GoogleExternalIdentityProvider : IExternalIdentityProvider
{
    internal const string MetadataAddress =
        "https://accounts.google.com/.well-known/openid-configuration";

    private static readonly string[] ValidIssuers =
    [
        "https://accounts.google.com",
        "accounts.google.com",
    ];

    private readonly OidcIdTokenValidator _validator;

    public GoogleExternalIdentityProvider(IOptions<GoogleExternalAuthSettings> settings)
        : this(OidcIdTokenValidator.FromOpenIdConfiguration(
            MetadataAddress,
            settings.Value.ClientIds,
            ValidIssuers))
    {
    }

    /// <summary>Test constructor — inject a validator with static signing keys.</summary>
    internal GoogleExternalIdentityProvider(OidcIdTokenValidator validator)
    {
        _validator = validator;
    }

    public string ProviderName => ExternalAuthProviders.Google;

    public async Task<Result<ExternalIdentity>> ValidateAsync(string token, CancellationToken ct = default)
    {
        var result = await _validator.ValidateAsync(token, ct).ConfigureAwait(false);
        if (result.IsFailure)
            return Result<ExternalIdentity>.Failure(result.Error);

        try
        {
            return Result<ExternalIdentity>.Success(
                ExternalIdentityMapper.FromPrincipal(ProviderName, result.Value!));
        }
        catch (InvalidOperationException ex)
        {
            return Result<ExternalIdentity>.Failure(ExternalAuthErrors.InvalidToken(ex.Message));
        }
    }
}
