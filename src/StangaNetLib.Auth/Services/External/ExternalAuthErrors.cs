using StangaNetLib.Auth.Models;
using StangaNetLib.Core.Common;

namespace StangaNetLib.Auth.Services.External;

internal static class ExternalAuthErrors
{
    public static Error UnknownProvider(string provider)
        => new(ExternalAuthErrorCodes.UnknownProvider,
            $"Unknown external identity provider '{provider}'.",
            ErrorType.NotFound);

    public static Error EmptyToken()
        => new(ExternalAuthErrorCodes.EmptyToken,
            "External identity token is required.",
            ErrorType.Validation);

    public static Error InvalidToken(string description)
        => new(ExternalAuthErrorCodes.InvalidToken, description, ErrorType.Unauthorized);

    public static Error ProviderError(string description)
        => new(ExternalAuthErrorCodes.ProviderError, description, ErrorType.Internal);
}
