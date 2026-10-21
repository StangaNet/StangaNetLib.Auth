using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using StangaNetLib.Core.Common;

namespace StangaNetLib.Auth.Services.External;

/// <summary>
/// Validates OIDC ID tokens against JWKS (via OpenID configuration) or static signing keys (tests).
/// </summary>
internal sealed class OidcIdTokenValidator
{
    private readonly ConfigurationManager<OpenIdConnectConfiguration>? _configurationManager;
    private readonly IReadOnlyList<SecurityKey>?                       _staticSigningKeys;
    private readonly string[]                                          _validAudiences;
    private readonly string[]                                          _validIssuers;
    private readonly IssuerValidator?                                  _issuerValidator;

    private OidcIdTokenValidator(
        ConfigurationManager<OpenIdConnectConfiguration>? configurationManager,
        IReadOnlyList<SecurityKey>?                       staticSigningKeys,
        IEnumerable<string>                               validAudiences,
        IEnumerable<string>                               validIssuers,
        IssuerValidator?                                  issuerValidator)
    {
        _configurationManager = configurationManager;
        _staticSigningKeys    = staticSigningKeys;
        _validAudiences       = validAudiences.ToArray();
        _validIssuers         = validIssuers.ToArray();
        _issuerValidator      = issuerValidator;
    }

    /// <summary>Creates a validator that discovers signing keys from an OpenID Connect metadata document.</summary>
    public static OidcIdTokenValidator FromOpenIdConfiguration(
        string              metadataAddress,
        IEnumerable<string> validAudiences,
        IEnumerable<string> validIssuers,
        IssuerValidator?    issuerValidator = null)
    {
        var manager = new ConfigurationManager<OpenIdConnectConfiguration>(
            metadataAddress,
            new OpenIdConnectConfigurationRetriever(),
            new HttpDocumentRetriever { RequireHttps = true });

        return new OidcIdTokenValidator(manager, null, validAudiences, validIssuers, issuerValidator);
    }

    /// <summary>Creates a validator that uses fixed signing keys (unit tests — no network).</summary>
    public static OidcIdTokenValidator FromSigningKeys(
        IEnumerable<SecurityKey> signingKeys,
        IEnumerable<string>      validAudiences,
        IEnumerable<string>      validIssuers,
        IssuerValidator?         issuerValidator = null)
        => new(null, signingKeys.ToList(), validAudiences, validIssuers, issuerValidator);

    public async Task<Result<ClaimsPrincipal>> ValidateAsync(string idToken, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(idToken))
            return Result<ClaimsPrincipal>.Failure(ExternalAuthErrors.EmptyToken());

        try
        {
            IEnumerable<SecurityKey> signingKeys;
            if (_staticSigningKeys is not null)
            {
                signingKeys = _staticSigningKeys;
            }
            else
            {
                var config = await _configurationManager!.GetConfigurationAsync(ct).ConfigureAwait(false);
                signingKeys = config.SigningKeys;
            }

            var parameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKeys        = signingKeys,
                ValidateAudience         = true,
                ValidAudiences           = _validAudiences,
                ValidateLifetime         = true,
                ClockSkew                = TimeSpan.FromMinutes(2),
                ValidateIssuer           = true,
            };

            if (_issuerValidator is not null)
            {
                parameters.IssuerValidator = _issuerValidator;
            }
            else
            {
                parameters.ValidIssuers = _validIssuers;
            }

            var handler   = new JwtSecurityTokenHandler();
            var principal = handler.ValidateToken(idToken, parameters, out _);
            return Result<ClaimsPrincipal>.Success(principal);
        }
        catch (SecurityTokenException ex)
        {
            return Result<ClaimsPrincipal>.Failure(ExternalAuthErrors.InvalidToken(ex.Message));
        }
        catch (ArgumentException ex)
        {
            return Result<ClaimsPrincipal>.Failure(ExternalAuthErrors.InvalidToken(ex.Message));
        }
        catch (HttpRequestException ex)
        {
            return Result<ClaimsPrincipal>.Failure(
                ExternalAuthErrors.ProviderError($"Failed to retrieve OpenID configuration: {ex.Message}"));
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return Result<ClaimsPrincipal>.Failure(
                ExternalAuthErrors.ProviderError($"OIDC token validation failed: {ex.Message}"));
        }
    }
}
