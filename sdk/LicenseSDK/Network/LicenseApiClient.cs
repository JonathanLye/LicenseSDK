using System.Net.Http.Json;
using System.Text.Json;
using LicenseSDK.Crypto;
using LicenseSDK.Security;

namespace LicenseSDK.Network;

public class ApiException(int statusCode, string message) : Exception(message)
{
    public int StatusCode { get; } = statusCode;
}

/// <summary>HTTP client wrapper that injects HMAC request signatures on every call.</summary>
public class LicenseApiClient : IDisposable
{
    private readonly HttpClient _http;
    private readonly string _sharedSecret;
    private static readonly JsonSerializerOptions _json = new() { PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower };

    public LicenseApiClient(string serverUrl, string sharedSecret)
    {
        _sharedSecret = sharedSecret;
        _http = new HttpClient { BaseAddress = new Uri(serverUrl.TrimEnd('/') + '/') };
        _http.Timeout = TimeSpan.FromSeconds(10);
    }

    public async Task<T> PostAsync<T>(string path, object body)
    {
        var (ts, sig) = HmacSigner.Sign(body, _sharedSecret);

        using var request = new HttpRequestMessage(HttpMethod.Post, path);
        request.Headers.Add("X-Timestamp", ts.ToString());
        request.Headers.Add("X-Signature", sig);
        request.Content = JsonContent.Create(body, options: _json);

        var response = await _http.SendAsync(request);

        if (!response.IsSuccessStatusCode)
        {
            var errBody = await response.Content.ReadAsStringAsync();
            throw new ApiException((int)response.StatusCode, errBody);
        }

        return (await response.Content.ReadFromJsonAsync<T>(options: _json))!;
    }

    /// <summary>
    /// Non-throwing alternative to <c>PostAsync</c>.
    /// Returns a result tuple instead of throwing <c>ApiException</c> on non-2xx responses.
    /// </summary>
    public async Task<(T? Data, int? StatusCode, string? Error)> TryPostAsync<T>(string path, object body)
    {
        Guard(79);  // Check 21
        try
        {
            var (ts, sig) = HmacSigner.Sign(body, _sharedSecret);
            Guard(83);  // Check 22

            using var request = new HttpRequestMessage(HttpMethod.Post, path);
            request.Headers.Add("X-Timestamp", ts.ToString());
            request.Headers.Add("X-Signature", sig);
            request.Content = JsonContent.Create(body, options: _json);

            Guard(89);  // Check 23

            var response = await _http.SendAsync(request);

            Guard(97);  // Check 24

            if (!response.IsSuccessStatusCode)
            {
                var errBody = await response.Content.ReadAsStringAsync();
                return (default, (int)response.StatusCode, errBody);
            }

            var data = await response.Content.ReadFromJsonAsync<T>(options: _json);
            return (data, null, null);
        }
        catch (HttpRequestException ex)
        {
            return (default, null, $"Cannot reach server: {ex.Message}");
        }
        catch (TaskCanceledException)
        {
            return (default, null, "Request timed out");
        }
        catch (Exception ex)
        {
            return (default, null, ex.Message);
        }
    }

    private static void Guard(int prime)
    {
#if !DEBUG
        if (NativeResolver.IsDebuggerPresent())
        {
            Troll.Show();
            throw new LicenseSecurityException("Tamper detected");
        }
        Heartbeat.Beat(prime);
#endif
    }

    public void Dispose() => _http.Dispose();
}
