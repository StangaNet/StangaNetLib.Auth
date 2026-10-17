using Microsoft.AspNetCore.Builder;
using StangaNetLib.Auth.Middleware;

namespace StangaNetLib.Auth.Extensions;

/// <summary>Extension methods for adding StangaNetLib.Auth middleware to an <see cref="Microsoft.AspNetCore.Builder.IApplicationBuilder"/> pipeline.</summary>
public static class ApplicationBuilderExtensions
{
    /// <summary>
    /// Adds in order: <c>UseAuthentication</c>, <see cref="TokenRevocationMiddleware"/>, <c>UseAuthorization</c>.
    /// Must be called after <c>UseRouting</c> and before endpoint mapping.
    /// </summary>
    /// <param name="app">The application builder to configure.</param>
    /// <returns>The same <see cref="IApplicationBuilder"/> for chaining.</returns>
    public static IApplicationBuilder UseStangaNetLibAuth(this IApplicationBuilder app)
    {
        app.UseAuthentication();
        app.UseMiddleware<TokenRevocationMiddleware>();
        app.UseAuthorization();
        return app;
    }
}
