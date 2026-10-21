using StangaNetLib.Auth.Models;
using StangaNetLib.Core.Common;

namespace StangaNetLib.Auth.Abstractions;

/// <summary>
/// Resolves a registered <see cref="IExternalIdentityProvider"/> by name and validates the token.
/// Register providers via <c>AddStangaNetLibAuthExternalGoogle</c> / Apple / Facebook / Microsoft.
/// </summary>
public interface IExternalIdentityService
{
    /// <summary>
    /// Validates an external identity token for the given provider name.
    /// </summary>
    /// <param name="provider">Provider name (e.g. <see cref="ExternalAuthProviders.Google"/>).</param>
    /// <param name="token">ID token or access token from the client SDK.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>
    /// Success with <see cref="ExternalIdentity"/>, or failure with
    /// <see cref="ExternalAuthErrorCodes.UnknownProvider"/> / <see cref="ExternalAuthErrorCodes.InvalidToken"/> / etc.
    /// </returns>
    Task<Result<ExternalIdentity>> ValidateAsync(string provider, string token, CancellationToken ct = default);
}
