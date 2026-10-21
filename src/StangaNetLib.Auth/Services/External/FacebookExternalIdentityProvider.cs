using System.Net.Http.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Options;
using StangaNetLib.Auth.Abstractions;
using StangaNetLib.Auth.Models;
using StangaNetLib.Auth.Settings;
using StangaNetLib.Core.Common;

namespace StangaNetLib.Auth.Services.External;

internal sealed class FacebookExternalIdentityProvider : IExternalIdentityProvider
{
    internal const string HttpClientName = "StangaNetLibAuthFacebook";

    private readonly HttpClient                   _http;
    private readonly FacebookExternalAuthSettings _settings;

    public FacebookExternalIdentityProvider(
        IHttpClientFactory                     httpClientFactory,
        IOptions<FacebookExternalAuthSettings> settings)
    {
        _http     = httpClientFactory.CreateClient(HttpClientName);
        _settings = settings.Value;
    }

    /// <summary>Test constructor — inject a dedicated <see cref="HttpClient"/>.</summary>
    internal FacebookExternalIdentityProvider(
        HttpClient                             http,
        IOptions<FacebookExternalAuthSettings> settings)
    {
        _http     = http;
        _settings = settings.Value;
    }

    public string ProviderName => ExternalAuthProviders.Facebook;

    public async Task<Result<ExternalIdentity>> ValidateAsync(string token, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(token))
            return Result<ExternalIdentity>.Failure(ExternalAuthErrors.EmptyToken());

        try
        {
            return await ValidateCoreAsync(token, ct).ConfigureAwait(false);
        }
        catch (HttpRequestException ex)
        {
            return Result<ExternalIdentity>.Failure(
                ExternalAuthErrors.ProviderError($"Facebook Graph API network error: {ex.Message}"));
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return Result<ExternalIdentity>.Failure(
                ExternalAuthErrors.ProviderError($"Facebook token validation failed: {ex.Message}"));
        }
    }

    private async Task<Result<ExternalIdentity>> ValidateCoreAsync(string token, CancellationToken ct)
    {
        var appAccessToken = $"{_settings.AppId}|{_settings.AppSecret}";
        var debugUrl =
            $"https://graph.facebook.com/debug_token?input_token={Uri.EscapeDataString(token)}&access_token={Uri.EscapeDataString(appAccessToken)}";

        using var debugResponse = await _http.GetAsync(debugUrl, ct).ConfigureAwait(false);
        if (!debugResponse.IsSuccessStatusCode)
        {
            return Result<ExternalIdentity>.Failure(ExternalAuthErrors.ProviderError(
                $"Facebook debug_token failed with status {(int)debugResponse.StatusCode}."));
        }

        var debug = await debugResponse.Content
            .ReadFromJsonAsync<DebugTokenResponse>(cancellationToken: ct)
            .ConfigureAwait(false);

        if (debug?.Data is null)
            return Result<ExternalIdentity>.Failure(ExternalAuthErrors.InvalidToken("Facebook debug_token returned an empty payload."));

        if (!debug.Data.IsValid)
            return Result<ExternalIdentity>.Failure(ExternalAuthErrors.InvalidToken("Facebook access token is not valid."));

        if (!string.Equals(debug.Data.AppId, _settings.AppId, StringComparison.Ordinal))
            return Result<ExternalIdentity>.Failure(ExternalAuthErrors.InvalidToken("Facebook access token was not issued for this app."));

        var meUrl =
            $"https://graph.facebook.com/me?fields=id,email,name,picture.type(large)&access_token={Uri.EscapeDataString(token)}";

        using var meResponse = await _http.GetAsync(meUrl, ct).ConfigureAwait(false);
        if (!meResponse.IsSuccessStatusCode)
        {
            return Result<ExternalIdentity>.Failure(ExternalAuthErrors.ProviderError(
                $"Facebook /me failed with status {(int)meResponse.StatusCode}."));
        }

        var me = await meResponse.Content
            .ReadFromJsonAsync<MeResponse>(cancellationToken: ct)
            .ConfigureAwait(false);

        if (me?.Id is null or "")
            return Result<ExternalIdentity>.Failure(ExternalAuthErrors.InvalidToken("Facebook /me response is missing user id."));

        var raw = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["id"] = me.Id,
        };
        if (!string.IsNullOrWhiteSpace(me.Email))
            raw["email"] = me.Email;
        if (!string.IsNullOrWhiteSpace(me.Name))
            raw["name"] = me.Name;
        if (!string.IsNullOrWhiteSpace(me.Picture?.Data?.Url))
            raw["picture"] = me.Picture.Data.Url;
        if (debug.Data.UserId is not null)
            raw["user_id"] = debug.Data.UserId;

        return Result<ExternalIdentity>.Success(new ExternalIdentity
        {
            Provider      = ProviderName,
            Subject       = me.Id,
            Email         = string.IsNullOrWhiteSpace(me.Email) ? null : me.Email,
            EmailVerified = !string.IsNullOrWhiteSpace(me.Email),
            DisplayName   = string.IsNullOrWhiteSpace(me.Name) ? null : me.Name,
            PictureUrl    = me.Picture?.Data?.Url,
            RawClaims     = raw,
        });
    }

    private sealed class DebugTokenResponse
    {
        [JsonPropertyName("data")]
        public DebugTokenData? Data { get; init; }
    }

    private sealed class DebugTokenData
    {
        [JsonPropertyName("app_id")]
        public string? AppId { get; init; }

        [JsonPropertyName("user_id")]
        public string? UserId { get; init; }

        [JsonPropertyName("is_valid")]
        public bool IsValid { get; init; }
    }

    private sealed class MeResponse
    {
        [JsonPropertyName("id")]
        public string? Id { get; init; }

        [JsonPropertyName("email")]
        public string? Email { get; init; }

        [JsonPropertyName("name")]
        public string? Name { get; init; }

        [JsonPropertyName("picture")]
        public PictureWrapper? Picture { get; init; }
    }

    private sealed class PictureWrapper
    {
        [JsonPropertyName("data")]
        public PictureData? Data { get; init; }
    }

    private sealed class PictureData
    {
        [JsonPropertyName("url")]
        public string? Url { get; init; }
    }
}
