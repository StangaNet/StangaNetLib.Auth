using StangaNetLib.Auth.Abstractions;
using StangaNetLib.Auth.Models;
using StangaNetLib.Core.Common;

namespace StangaNetLib.Auth.Services.External;

internal sealed class ExternalIdentityService : IExternalIdentityService
{
    private readonly IReadOnlyDictionary<string, IExternalIdentityProvider> _providers;

    public ExternalIdentityService(IEnumerable<IExternalIdentityProvider> providers)
    {
        _providers = providers.ToDictionary(
            p => p.ProviderName,
            StringComparer.OrdinalIgnoreCase);
    }

    public Task<Result<ExternalIdentity>> ValidateAsync(
        string provider,
        string token,
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(provider))
        {
            return Task.FromResult(Result<ExternalIdentity>.Failure(
                ExternalAuthErrors.UnknownProvider(provider ?? string.Empty)));
        }

        if (!_providers.TryGetValue(provider, out var identityProvider))
        {
            return Task.FromResult(Result<ExternalIdentity>.Failure(
                ExternalAuthErrors.UnknownProvider(provider)));
        }

        return identityProvider.ValidateAsync(token, ct);
    }
}
