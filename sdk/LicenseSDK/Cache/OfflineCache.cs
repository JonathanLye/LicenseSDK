using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using LicenseSDK.Crypto;
using LicenseSDK.Security;

namespace LicenseSDK.Cache;

public class CacheEntry
{
    public string LicenseKey    { get; set; } = "";
    public string ActivationId  { get; set; } = "";
    public string? ExpiresAt    { get; set; }
    public DateTime LastVerifiedAt { get; set; }
    public int GracePeriodHours { get; set; } = 72;
}

/// <summary>
/// Persists verification state to AppData with double-layer encryption:
///   Layer 1 — AES-256-GCM (key derived from MachineGuid via PBKDF2)
///   Layer 2 — Windows DPAPI Machine Scope (key bound to this OS install)
///
/// Copying the cache file to another machine → DPAPI Unprotect fails.
/// Copying + cracking MachineGuid → still need DPAPI Machine key.
/// </summary>
public class OfflineCache
{
    private readonly string _path;
    private readonly byte[] _key;
    private readonly byte[] _entropy;   // Binds DPAPI blob to this product

    public OfflineCache(string productId, string machineGuid)
    {
        var dir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "LicenseSDK",
            productId);
        Directory.CreateDirectory(dir);
        _path    = Path.Combine(dir, "license.cache");
        _key     = AesCache.DeriveKey(machineGuid);
        _entropy = Encoding.UTF8.GetBytes(productId);
    }

    public void Save(CacheEntry entry)
    {
#if !DEBUG
        Guard(); // Check 29
#endif
        try
        {
            var json = JsonSerializer.Serialize(entry);
#if !DEBUG
            Guard(); // Check 30
#endif
            var aesBlob = AesCache.Encrypt(json, _key);                // Layer 1: AES-GCM
            var dpBlob = ProtectedData.Protect(aesBlob, _entropy,      // Layer 2: DPAPI Machine
                                DataProtectionScope.LocalMachine);
            File.WriteAllBytes(_path, dpBlob);
        }
        catch
        {
            // Save failure is non-fatal — the activation itself succeeded.
        }
    }

    public CacheEntry? Load()
    {
        if (!File.Exists(_path)) return null;
#if !DEBUG
        Guard(); // Check 31
#endif
        try
        {
            var dpBlob  = File.ReadAllBytes(_path);
            var aesBlob = ProtectedData.Unprotect(dpBlob, _entropy,   // Layer 2: DPAPI unseal
                                DataProtectionScope.LocalMachine);
#if !DEBUG
            Guard(); // Check 32
#endif
            var json    = AesCache.Decrypt(aesBlob, _key);            // Layer 1: AES decrypt
            return JsonSerializer.Deserialize<CacheEntry>(json);
        }
        catch
        {
            return null;
        }
    }

    public void Clear()
    {
        if (File.Exists(_path)) File.Delete(_path);
    }

#if !DEBUG
    private static void Guard(int prime = 101)
    {
        if (NativeResolver.IsDebuggerPresent())
        {
            Troll.Show();
            throw new LicenseSecurityException("Tamper detected");
        }
        Heartbeat.Beat(prime);
    }
#endif

    /// <summary>True if the cached entry is within its grace period.</summary>
    public bool IsWithinGracePeriod(CacheEntry entry) =>
        DateTime.UtcNow - entry.LastVerifiedAt < TimeSpan.FromHours(entry.GracePeriodHours);
}
