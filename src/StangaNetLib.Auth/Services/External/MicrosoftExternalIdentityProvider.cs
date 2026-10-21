using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using StangaNetLib.Auth.Abstractions;
using StangaNetLib.Auth.Models;
using StangaNetLib.Auth.Settings;
using StangaNetLib.Core.Common;

namespace StangaNetLib.Auth.Services.External;

internal sealed class MicrosoftExternalIdentityProvider : IExternalIdentityProvider
{
    private readonly OidcIdTokenValidator _validator;

    public MicrosoftExternalIdentityProvider(IOptions<MicrosoftExternalAuthSettings> settings)
        : this(CreateValidator(settings.Value))
    {
    }

    /// <summary>Test constructor — inject a validator with static signing keys.</summary>
    internal MicrosoftExternalIdentityProvider(OidcIdTokenValidator validator)
    {
        _validator = validator;
    }

    public string ProviderName => ExternalAuthProviders.Microsoft;

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

    internal static string MetadataAddress(string tenantId)
        => $"https://login.microsoftonline.com/{tenantId}/v2.0/.well-known/openid-configuration";

    internal static OidcIdTokenValidator CreateValidator(MicrosoftExternalAuthSettings settings)
    {
        var tenant = string.IsNullOrWhiteSpace(settings.TenantId) ? "common" : settings.TenantId;
        var multiTenant = IsMultiTenantAlias(tenant);

        IssuerValidator? issuerValidator = multiTenant
            ? (issuer, _, _) =>
            {
                if (IsMicrosoftV2Issuer(issuer))
                    return issuer;
                throw new SecurityTokenInvalidIssuerException($"Issuer '{issuer}' is not a Microsoft v2.0 issuer.");
            }
            : null;

        var validIssuers = multiTenant
            ? Array.Empty<string>()
            : [$"https://login.microsoftonline.com/{tenant}/v2.0"];

        return OidcIdTokenValidator.FromOpenIdConfiguration(
            MetadataAddress(tenant),
            settings.ClientIds,
            validIssuers,
            issuerValidator);
    }

    /// <summary>Builds a test validator with static keys and the same issuer rules as production.</summary>
    internal static OidcIdTokenValidator CreateValidatorForTests(
        MicrosoftExternalAuthSettings settings,
        IEnumerable<SecurityKey>      signingKeys,
        string?                       tokenIssuerTenantId = null)
    {
        var tenant = string.IsNullOrWhiteSpace(settings.TenantId) ? "common" : settings.TenantId;
        var multiTenant = IsMultiTenantAlias(tenant);

        IssuerValidator? issuerValidator = multiTenant
            ? (issuer, _, _) =>
            {
                if (IsMicrosoftV2Issuer(issuer))
                    return issuer;
                throw new SecurityTokenInvalidIssuerException($"Issuer '{issuer}' is not a Microsoft v2.0 issuer.");
            }
            : null;

        var validIssuers = multiTenant
            ? Array.Empty<string>()
            : [$"https://login.microsoftonline.com/{tokenIssuerTenantId ?? tenant}/v2.0"];

        return OidcIdTokenValidator.FromSigningKeys(
            signingKeys,
            settings.ClientIds,
            validIssuers,
            issuerValidator);
    }

    private static bool IsMultiTenantAlias(string tenant)
        => tenant is "common" or "organizations" or "consumers";

    private static bool IsMicrosoftV2Issuer(string issuer)
        => issuer.StartsWith("https://login.microsoftonline.com/", StringComparison.OrdinalIgnoreCase)
           && issuer.EndsWith("/v2.0", StringComparison.OrdinalIgnoreCase);
}
