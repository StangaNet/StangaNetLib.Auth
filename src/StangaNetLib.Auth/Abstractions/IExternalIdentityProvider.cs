using StangaNetLib.Auth.Models;
using StangaNetLib.Core.Common;

namespace StangaNetLib.Auth.Abstractions;

/// <summary>
/// Validates a token issued by a single external identity provider
/// and maps it to a verified <see cref="ExternalIdentity"/>.
/// </summary>
public interface IExternalIdentityProvider
{
    /// <summary>Canonical provider name (see <see cref="ExternalAuthProviders"/>).</summary>
    string ProviderName { get; }

    /// <summary>
    /// Validates <paramref name="token"/> (ID token or access token, depending on the provider)
    /// and returns the verified identity.
    /// </summary>
    /// <param name="token">Opaque token string from the client SDK.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>Success with <see cref="ExternalIdentity"/>, or a structured <see cref="Error"/>.</returns>
    Task<Result<ExternalIdentity>> ValidateAsync(string token, CancellationToken ct = default);
}
