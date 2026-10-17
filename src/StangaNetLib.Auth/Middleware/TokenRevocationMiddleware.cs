using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using StangaNetLib.Auth.Abstractions;

namespace StangaNetLib.Auth.Middleware;

/// <summary>
/// Checks each incoming Bearer token against the revocation blacklist before passing the request downstream.
/// Responds with <c>401 Unauthorized</c> if the token's <c>jti</c> is found in the blacklist.
/// Register via <see cref="Extensions.ApplicationBuilderExtensions.UseStangaNetLibAuth"/>.
/// </summary>
public sealed class TokenRevocationMiddleware
{
    // Thread-safe; reuse across all requests to avoid repeated allocation.
    private static readonly JwtSecurityTokenHandler _jtiHandler = new();

    private readonly RequestDelegate                    _next;
    private readonly ITokenRevocationService            _revocation;
    private readonly ILogger<TokenRevocationMiddleware> _logger;

    /// <summary>Initializes the middleware with its pipeline delegate, revocation service, and logger.</summary>
    /// <param name="next">The next middleware in the request pipeline.</param>
    /// <param name="revocation">Service used to check whether a token has been revoked.</param>
    /// <param name="logger">Logger for emitting revocation warnings.</param>
    public TokenRevocationMiddleware(
        RequestDelegate                    next,
        ITokenRevocationService            revocation,
        ILogger<TokenRevocationMiddleware> logger)
    {
        _next       = next;
        _revocation = revocation;
        _logger     = logger;
    }

    /// <summary>Processes the request, short-circuiting with 401 if the Bearer token has been revoked.</summary>
    /// <param name="context">The current HTTP context.</param>
    public async Task InvokeAsync(HttpContext context)
    {
        var authHeader = context.Request.Headers.Authorization.FirstOrDefault();
        if (authHeader?.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase) == true)
        {
            var token   = authHeader["Bearer ".Length..].Trim();
            var tokenId = ExtractJti(token);

            if (tokenId is not null)
            {
                var isRevoked = await _revocation.IsRevokedAsync(tokenId);
                if (isRevoked)
                {
                    _logger.LogWarning("Revoked token {TokenId} was used from {RemoteIp}",
                        tokenId, context.Connection.RemoteIpAddress);

                    context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                    await context.Response.WriteAsJsonAsync(new { error = "Token has been revoked." });
                    return;
                }
            }
        }

        await _next(context);
    }

    // Reads jti without signature validation — works for both self-signed and Auth0 tokens.
    private static string? ExtractJti(string token)
    {
        if (!_jtiHandler.CanReadToken(token)) return null;
        return _jtiHandler.ReadJwtToken(token).Claims
            .FirstOrDefault(c => c.Type == "jti")?.Value;
    }
}
