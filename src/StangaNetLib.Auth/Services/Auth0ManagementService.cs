using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Options;
using StangaNetLib.Auth.Abstractions;
using StangaNetLib.Auth.Models;
using StangaNetLib.Auth.Settings;
using StangaNetLib.Core.Common;
using StangaNetLib.Resilience.Execution;

namespace StangaNetLib.Auth.Services;

internal sealed class Auth0ManagementService : IAuth0ManagementService
{
    /// <summary>Resilience pipeline name consumed from <c>ResilienceSettings.Pipelines</c> when <see cref="IResilientExecutor"/> is active.</summary>
    internal const string PipelineName = "Auth0";

    private readonly HttpClient                _http;
    private readonly Auth0Settings             _settings;
    private readonly Auth0ManagementTokenCache _tokenCache;
    private readonly IResilientExecutor?        _resilience;

    public Auth0ManagementService(
        HttpClient                 http,
        IOptions<Auth0Settings>    settings,
        Auth0ManagementTokenCache  tokenCache,
        IResilientExecutor?        resilience = null)
    {
        _http       = http;
        _settings   = settings.Value;
        _tokenCache = tokenCache;
        _resilience = resilience;
    }

    // -----------------------------------------------------------------------
    // Token acquisition
    // -----------------------------------------------------------------------

    private async Task<Result<string>> GetManagementTokenAsync(CancellationToken ct)
    {
        string? errorMessage = null;

        try
        {
            var token = await _tokenCache.GetOrAcquireAsync(async innerCt =>
            {
                var body = new FormUrlEncodedContent(new Dictionary<string, string>
                {
                    ["grant_type"]    = "client_credentials",
                    ["client_id"]     = _settings.ManagementClientId,
                    ["client_secret"] = _settings.ManagementClientSecret,
                    ["audience"]      = $"https://{_settings.Domain}/api/v2/",
                });

                var response = await _http.PostAsync($"https://{_settings.Domain}/oauth/token", body, innerCt);
                if (!response.IsSuccessStatusCode)
                {
                    errorMessage = $"Auth0 management token request failed with status {(int)response.StatusCode}.";
                    return (string.Empty, 0);
                }

                var dto = await response.Content.ReadFromJsonAsync<TokenDto>(cancellationToken: innerCt);
                if (dto?.AccessToken is null or "")
                {
                    errorMessage = "Auth0 returned an empty management token.";
                    return (string.Empty, 0);
                }

                return (dto.AccessToken, dto.ExpiresIn);
            }, ct);

            if (errorMessage is not null)
                return Result<string>.Failure(Error.Internal(errorMessage));

            return token is null or ""
                ? Result<string>.Failure(Error.Internal("Failed to acquire Auth0 management token."))
                : Result<string>.Success(token);
        }
        catch (HttpRequestException ex)
        {
            return Result<string>.Failure(Error.Internal($"Auth0 network error acquiring management token: {ex.Message}"));
        }
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    private string Url(string path) => $"https://{_settings.Domain}/api/v2/{path}";

    private static HttpRequestMessage Request(HttpMethod method, string url, string token)
    {
        var req = new HttpRequestMessage(method, url);
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return req;
    }

    /// <summary>
    /// Throws <see cref="Auth0HttpException"/> for any non-success response so Polly can observe
    /// the failure. Configure the <c>"Auth0"</c> pipeline's <c>ShouldHandle</c> predicate to
    /// exclude <see cref="Auth0HttpException"/> with 4xx status codes if retry is not desired for them.
    /// </summary>
    private static void EnsureSuccess(HttpResponseMessage response)
    {
        if (!response.IsSuccessStatusCode)
            throw new Auth0HttpException(response.StatusCode);
    }

    private async Task<Result> PatchUserAsync(string userId, object body, CancellationToken ct)
    {
        var tokenResult = await GetManagementTokenAsync(ct);
        if (tokenResult.IsFailure) return Result.Failure(tokenResult.Error);

        var req = Request(HttpMethod.Patch, Url($"users/{Uri.EscapeDataString(userId)}"), tokenResult.Value!);
        req.Content = JsonContent.Create(body);

        if (_resilience is not null)
            return await _resilience.ExecuteAsync(PipelineName, async innerCt =>
            {
                var response = await _http.SendAsync(req, innerCt);
                EnsureSuccess(response);
            }, ct);

        try
        {
            var response = await _http.SendAsync(req, ct);
            return response.IsSuccessStatusCode
                ? Result.Success()
                : Result.Failure(Error.Internal($"Auth0 update user error {(int)response.StatusCode}."));
        }
        catch (HttpRequestException ex)
        {
            return Result.Failure(Error.Internal($"Auth0 network error: {ex.Message}"));
        }
    }

    // -----------------------------------------------------------------------
    // IAuth0ManagementService
    // -----------------------------------------------------------------------

    public async Task<Result<Auth0UserInfo>> GetUserAsync(string userId, CancellationToken ct = default)
    {
        var tokenResult = await GetManagementTokenAsync(ct);
        if (tokenResult.IsFailure) return Result<Auth0UserInfo>.Failure(tokenResult.Error);

        var req = Request(HttpMethod.Get, Url($"users/{Uri.EscapeDataString(userId)}"), tokenResult.Value!);

        if (_resilience is not null)
            return await _resilience.ExecuteAsync<Auth0UserInfo>(PipelineName, async innerCt =>
            {
                var response = await _http.SendAsync(req, innerCt);
                EnsureSuccess(response);
                var dto = await response.Content.ReadFromJsonAsync<UserDto>(cancellationToken: innerCt);
                return dto is null
                    ? throw new InvalidOperationException("Auth0 returned an empty user payload.")
                    : dto.ToModel();
            }, ct);

        try
        {
            var response = await _http.SendAsync(req, ct);

            if (response.StatusCode == HttpStatusCode.NotFound)
                return Result<Auth0UserInfo>.Failure(Error.NotFound("Auth0User", userId));
            if (!response.IsSuccessStatusCode)
                return Result<Auth0UserInfo>.Failure(Error.Internal($"Auth0 API error {(int)response.StatusCode}."));

            var dto = await response.Content.ReadFromJsonAsync<UserDto>(cancellationToken: ct);
            return dto is null
                ? Result<Auth0UserInfo>.Failure(Error.Internal("Auth0 returned an empty user payload."))
                : Result<Auth0UserInfo>.Success(dto.ToModel());
        }
        catch (HttpRequestException ex)
        {
            return Result<Auth0UserInfo>.Failure(Error.Internal($"Auth0 network error: {ex.Message}"));
        }
    }

    public async Task<Result<IReadOnlyList<Auth0RoleInfo>>> GetUserRolesAsync(string userId, CancellationToken ct = default)
    {
        var tokenResult = await GetManagementTokenAsync(ct);
        if (tokenResult.IsFailure) return Result<IReadOnlyList<Auth0RoleInfo>>.Failure(tokenResult.Error);

        var req = Request(HttpMethod.Get, Url($"users/{Uri.EscapeDataString(userId)}/roles"), tokenResult.Value!);

        if (_resilience is not null)
            return await _resilience.ExecuteAsync<IReadOnlyList<Auth0RoleInfo>>(PipelineName, async innerCt =>
            {
                var response = await _http.SendAsync(req, innerCt);
                EnsureSuccess(response);
                var dtos = await response.Content.ReadFromJsonAsync<RoleDto[]>(cancellationToken: innerCt);
                return (IReadOnlyList<Auth0RoleInfo>)((dtos ?? []).Select(r => r.ToModel()).ToList().AsReadOnly());
            }, ct);

        try
        {
            var response = await _http.SendAsync(req, ct);

            if (!response.IsSuccessStatusCode)
                return Result<IReadOnlyList<Auth0RoleInfo>>.Failure(
                    Error.Internal($"Auth0 API error {(int)response.StatusCode}."));

            var dtos  = await response.Content.ReadFromJsonAsync<RoleDto[]>(cancellationToken: ct);
            IReadOnlyList<Auth0RoleInfo> roles = (dtos ?? []).Select(r => r.ToModel()).ToList().AsReadOnly();
            return Result<IReadOnlyList<Auth0RoleInfo>>.Success(roles);
        }
        catch (HttpRequestException ex)
        {
            return Result<IReadOnlyList<Auth0RoleInfo>>.Failure(Error.Internal($"Auth0 network error: {ex.Message}"));
        }
    }

    public async Task<Result> AssignRolesAsync(string userId, IEnumerable<string> roleIds, CancellationToken ct = default)
    {
        var tokenResult = await GetManagementTokenAsync(ct);
        if (tokenResult.IsFailure) return Result.Failure(tokenResult.Error);

        var req = Request(HttpMethod.Post, Url($"users/{Uri.EscapeDataString(userId)}/roles"), tokenResult.Value!);
        req.Content = JsonContent.Create(new { roles = roleIds.ToArray() });

        if (_resilience is not null)
            return await _resilience.ExecuteAsync(PipelineName, async innerCt =>
            {
                var response = await _http.SendAsync(req, innerCt);
                EnsureSuccess(response);
            }, ct);

        try
        {
            var response = await _http.SendAsync(req, ct);
            return response.IsSuccessStatusCode
                ? Result.Success()
                : Result.Failure(Error.Internal($"Auth0 assign roles error {(int)response.StatusCode}."));
        }
        catch (HttpRequestException ex)
        {
            return Result.Failure(Error.Internal($"Auth0 network error: {ex.Message}"));
        }
    }

    public async Task<Result> RemoveRolesAsync(string userId, IEnumerable<string> roleIds, CancellationToken ct = default)
    {
        var tokenResult = await GetManagementTokenAsync(ct);
        if (tokenResult.IsFailure) return Result.Failure(tokenResult.Error);

        var req = Request(HttpMethod.Delete, Url($"users/{Uri.EscapeDataString(userId)}/roles"), tokenResult.Value!);
        req.Content = JsonContent.Create(new { roles = roleIds.ToArray() });

        if (_resilience is not null)
            return await _resilience.ExecuteAsync(PipelineName, async innerCt =>
            {
                var response = await _http.SendAsync(req, innerCt);
                EnsureSuccess(response);
            }, ct);

        try
        {
            var response = await _http.SendAsync(req, ct);
            return response.IsSuccessStatusCode
                ? Result.Success()
                : Result.Failure(Error.Internal($"Auth0 remove roles error {(int)response.StatusCode}."));
        }
        catch (HttpRequestException ex)
        {
            return Result.Failure(Error.Internal($"Auth0 network error: {ex.Message}"));
        }
    }

    public Task<Result> BlockUserAsync(string userId, CancellationToken ct = default)
        => PatchUserAsync(userId, new { blocked = true }, ct);

    public Task<Result> UnblockUserAsync(string userId, CancellationToken ct = default)
        => PatchUserAsync(userId, new { blocked = false }, ct);

    public async Task<Result> DeleteUserAsync(string userId, CancellationToken ct = default)
    {
        var tokenResult = await GetManagementTokenAsync(ct);
        if (tokenResult.IsFailure) return Result.Failure(tokenResult.Error);

        var req = Request(HttpMethod.Delete, Url($"users/{Uri.EscapeDataString(userId)}"), tokenResult.Value!);

        if (_resilience is not null)
            return await _resilience.ExecuteAsync(PipelineName, async innerCt =>
            {
                var response = await _http.SendAsync(req, innerCt);
                EnsureSuccess(response);
            }, ct);

        try
        {
            var response = await _http.SendAsync(req, ct);
            return response.IsSuccessStatusCode
                ? Result.Success()
                : Result.Failure(Error.Internal($"Auth0 delete user error {(int)response.StatusCode}."));
        }
        catch (HttpRequestException ex)
        {
            return Result.Failure(Error.Internal($"Auth0 network error: {ex.Message}"));
        }
    }

    public Task<Result> UpdateUserMetadataAsync(
        string userId, IReadOnlyDictionary<string, object?> metadata, CancellationToken ct = default)
        => PatchUserAsync(userId, new { user_metadata = metadata }, ct);

    // -----------------------------------------------------------------------
    // Private DTOs
    // -----------------------------------------------------------------------

    private sealed record TokenDto(
        [property: JsonPropertyName("access_token")] string AccessToken,
        [property: JsonPropertyName("expires_in")]   int    ExpiresIn);

    private sealed record UserDto(
        [property: JsonPropertyName("user_id")]        string?                               UserId,
        [property: JsonPropertyName("email")]          string?                               Email,
        [property: JsonPropertyName("email_verified")] bool                                  EmailVerified,
        [property: JsonPropertyName("blocked")]        bool                                  Blocked,
        [property: JsonPropertyName("created_at")]     DateTime                              CreatedAt,
        [property: JsonPropertyName("last_login")]     DateTime?                             LastLogin,
        [property: JsonPropertyName("user_metadata")]  IReadOnlyDictionary<string, object?>? UserMetadata,
        [property: JsonPropertyName("app_metadata")]   IReadOnlyDictionary<string, object?>? AppMetadata)
    {
        public Auth0UserInfo ToModel() => new()
        {
            UserId        = UserId        ?? string.Empty,
            Email         = Email         ?? string.Empty,
            EmailVerified = EmailVerified,
            Blocked       = Blocked,
            CreatedAt     = CreatedAt,
            LastLogin     = LastLogin,
            UserMetadata  = UserMetadata  ?? new Dictionary<string, object?>(),
            AppMetadata   = AppMetadata   ?? new Dictionary<string, object?>(),
        };
    }

    private sealed record RoleDto(
        [property: JsonPropertyName("id")]          string? Id,
        [property: JsonPropertyName("name")]        string? Name,
        [property: JsonPropertyName("description")] string? Description)
    {
        public Auth0RoleInfo ToModel() => new()
        {
            Id          = Id          ?? string.Empty,
            Name        = Name        ?? string.Empty,
            Description = Description ?? string.Empty,
        };
    }

    /// <summary>
    /// Thrown inside resilience lambdas so Polly can observe non-success HTTP responses.
    /// Carries the <see cref="HttpStatusCode"/> for fine-grained pipeline configuration.
    /// </summary>
    internal sealed class Auth0HttpException(HttpStatusCode statusCode) : Exception
    {
        public HttpStatusCode StatusCode { get; } = statusCode;
    }
}
