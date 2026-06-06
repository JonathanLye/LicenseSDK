using System.Text.Json;
using LicenseSDK.Cache;
using LicenseSDK.Fingerprint;
using LicenseSDK.Network;
using LicenseSDK.Security;

namespace LicenseSDK;

public class LicenseConfig
{
    /// <summary>Base URL of the license server, e.g. https://license.example.com</summary>
    public required string ServerUrl { get; init; }

    /// <summary>Shared HMAC secret — must match server SHARED_SECRET env var.</summary>
    public required string SharedSecret { get; init; }

    /// <summary>Product ID (UUID) from the products table.</summary>
    public required string ProductId { get; init; }

    /// <summary>Offline grace period in hours before verification is required. Default: 72.</summary>
    public int GracePeriodHours { get; init; } = 72;
}

public class ActivationResult
{
    public bool Success { get; init; }
    public string? ActivationId { get; init; }
    public string? ExpiresAt { get; init; }
    public string? Error { get; init; }
}

public class VerificationResult
{
    public bool Valid { get; init; }
    public bool IsOffline { get; init; }
    public string? ExpiresAt { get; init; }
    public string? Error { get; init; }
}

/// <summary>Thrown when anti-tamper checks detect a debugger at runtime.</summary>
public class LicenseSecurityException(string message) : Exception(message);

/// <summary>
/// Main entry point for the License SDK.
/// Embed an instance in your application and call VerifyAsync() on startup.
/// </summary>
public class LicenseManager : IDisposable
{
    private readonly LicenseConfig _config;
    private readonly LicenseApiClient _api;
    private readonly OfflineCache _cache;
    private readonly FingerprintData _fingerprint;
    private readonly Dictionary<string, object?> _fpDict;

    public FingerprintData Fingerprint => _fingerprint;

    public LicenseManager(LicenseConfig config)
    {
        _config      = config;
        _api         = new LicenseApiClient(config.ServerUrl, config.SharedSecret);
        _fingerprint = FingerprintCollector.Collect();
        _fpDict      = FingerprintHasher.ToDict(_fingerprint);
        _cache       = new OfflineCache(config.ProductId, _fingerprint.MachineGuid ?? "unknown");

        // Check 1: constructor guard
        AntiTamperGuard(3);

        // Apply process-wide anti-dumping mitigations (disabled — see DumpProtection.cs)
        // DumpProtection.Apply();

        // Check 2: post-mitigation guard
        AntiTamperGuard(5);
    }

    // ── Distributed guard helper ────────────────────────────────
    // Inline check that calls NativeResolver directly. Each call site
    // passes a unique prime so Heartbeat can verify every check ran.
    private static void AntiTamperGuard(int prime)
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

    // ── Public API ───────────────────────────────────────────────

    /// <summary>Activate this machine with the given license key.</summary>
    public async Task<ActivationResult> ActivateAsync(string licenseKey)
    {
        Heartbeat.Reset();
        AntiTamperGuard(7);   // Check 3

        try
        {
            if (string.IsNullOrWhiteSpace(licenseKey))
                return new ActivationResult { Success = false, Error = "License key is empty" };

            AntiTamperGuard(11);  // Check 4

            var body = new { license_key = licenseKey, fingerprint = _fpDict };

            AntiTamperGuard(13);  // Check 5

            var (data, statusCode, error) = await _api.TryPostAsync<ActivateResponse>("api/v1/activate", body);

            AntiTamperGuard(17);  // Check 6

            if (data is not null)
            {
                _cache.Save(new CacheEntry
                {
                    LicenseKey       = licenseKey,
                    ActivationId     = data.ActivationId,
                    ExpiresAt        = data.ExpiresAt,
                    LastVerifiedAt   = DateTime.UtcNow,
                    GracePeriodHours = _config.GracePeriodHours,
                });

                AntiTamperGuard(19);  // Check 7

                Heartbeat.VerifyTotal();
                return new ActivationResult { Success = true, ActivationId = data.ActivationId, ExpiresAt = data.ExpiresAt };
            }

            // Extract the error message from the server response body
            var message = error ?? "Unknown error";
            try
            {
                using var doc = JsonDocument.Parse(message);
                var errMsg = doc.RootElement.TryGetProperty("error", out var e) ? e.GetString() : null;
                if (errMsg is not null) message = errMsg;
            }
            catch { /* Not JSON — use raw message */ }

            AntiTamperGuard(23);  // Check 8
            return new ActivationResult { Success = false, Error = message };
        }
        catch (LicenseSecurityException)
        {
            throw; // Don't swallow security exceptions
        }
    }

    /// <summary>
    /// Verify the current license status.
    /// Falls back to the local encrypted cache when offline, respecting the grace period.
    /// </summary>
    public async Task<VerificationResult> VerifyAsync()
    {
        Heartbeat.Reset();
        AntiTamperGuard(29);  // Check 9

        var cached = _cache.Load();

        AntiTamperGuard(31);  // Check 10

        try
        {
            if (cached == null)
                return new VerificationResult { Valid = false, Error = "Not activated on this machine" };

            AntiTamperGuard(37);  // Check 11

            var body = new
            {
                license_key   = cached.LicenseKey,
                activation_id = cached.ActivationId,
                fingerprint   = _fpDict,
            };

            AntiTamperGuard(41);  // Check 12

            var (data, _, error) = await _api.TryPostAsync<VerifyResponse>("api/v1/verify", body);

            AntiTamperGuard(43);  // Check 13

            if (data is not null)
            {
                cached.LastVerifiedAt = DateTime.UtcNow;
                cached.ExpiresAt = data.ExpiresAt;
                _cache.Save(cached);

                AntiTamperGuard(47);  // Check 14
                Heartbeat.VerifyTotal();
                return new VerificationResult { Valid = true, ExpiresAt = data.ExpiresAt };
            }

            AntiTamperGuard(53);  // Check 15
            return new VerificationResult { Valid = false, Error = error ?? "Verification rejected" };
        }
        catch (LicenseSecurityException)
        {
            throw;
        }
        catch
        {
            AntiTamperGuard(59);  // Check 16
            if (cached != null && _cache.IsWithinGracePeriod(cached))
            {
                Heartbeat.VerifyTotal();
                return new VerificationResult { Valid = true, IsOffline = true, ExpiresAt = cached.ExpiresAt };
            }
            return new VerificationResult { Valid = false, Error = "Offline and grace period has expired. Please connect to the internet to verify your license." };
        }
    }

    /// <summary>Deactivate this machine, freeing the activation slot.</summary>
    public async Task<bool> DeactivateAsync()
    {
        Heartbeat.Reset();
        AntiTamperGuard(61);  // Check 17

        var cached = _cache.Load();
        if (cached == null) return false;

        AntiTamperGuard(67);  // Check 18

        try
        {
            var body = new
            {
                license_key   = cached.LicenseKey,
                activation_id = cached.ActivationId,
                fingerprint   = _fpDict,
            };

            AntiTamperGuard(71);  // Check 19

            var (_, statusCode, _) = await _api.TryPostAsync<object>("api/v1/deactivate", body);

            if (statusCode is null)
            {
                AntiTamperGuard(73);  // Check 20
                _cache.Clear();
                Heartbeat.VerifyTotal();
                return true;
            }

            return false;
        }
        catch (LicenseSecurityException)
        {
            throw;
        }
        catch
        {
            return false;
        }
    }

    public void Dispose() => _api.Dispose();

    // Response shapes (private — consumers use the public result types)
    private record ActivateResponse(string ActivationId, string? ExpiresAt, string Status);
    private record VerifyResponse(bool Valid, string? ExpiresAt, string? LicenseType);
}
