using System.Security.Cryptography;
using System.Text;

namespace LicenseSDK.Fingerprint;

public static class FingerprintHasher
{
    // Must match server-side FINGERPRINT_WEIGHTS in config.ts
    // Total = 100, threshold = 60
    internal static readonly Dictionary<string, int> Weights = new()
    {
        ["motherboard"]      = 32,
        ["disk"]             = 28,   // array — any match scores
        ["bios"]             = 18,
        ["volumeSerial"]     = 10,
        ["cpu"]              = 6,
        ["machineGuid"]      = 4,
        ["windowsProductId"] = 1,
        ["mac"]              = 1,    // array — any match scores
    };

    /// <summary>Produces a deterministic SHA-256 hash of the fingerprint for server comparison.</summary>
    public static string ComputeHash(FingerprintData fp)
    {
        var canonical = string.Join("|", Weights.Keys.Select(k => $"{k}={GetField(fp, k) ?? ""}"));
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(canonical));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    /// <summary>
    /// Converts FingerprintData to the JSON-serializable dictionary the server expects.
    /// Only non-null string and non-empty list fields are included — null values are omitted
    /// entirely so that JSON serialization never produces <c>"field": null</c>, which would
    /// cause Zod's .optional() on the server to reject the payload.
    /// </summary>
    public static Dictionary<string, object?> ToDict(FingerprintData fp)
    {
        var dict = new Dictionary<string, object?>();
        if (fp.Motherboard is not null)         dict["motherboard"]      = fp.Motherboard;
        if (fp.Disks is { Count: > 0 })         dict["disk"]             = fp.Disks;
        if (fp.Bios is not null)                dict["bios"]             = fp.Bios;
        if (fp.VolumeSerial is not null)         dict["volumeSerial"]    = fp.VolumeSerial;
        if (fp.Cpu is not null)                 dict["cpu"]              = fp.Cpu;
        if (fp.MachineGuid is not null)          dict["machineGuid"]     = fp.MachineGuid;
        if (fp.WindowsProductId is not null)     dict["windowsProductId"] = fp.WindowsProductId;
        if (fp.Macs is { Count: > 0 })          dict["mac"]             = fp.Macs;
        return dict;
    }

    private static string? GetField(FingerprintData fp, string key) => key switch
    {
        "motherboard"      => fp.Motherboard,
        "disk"             => fp.Disks is { Count: > 0 }
                              ? string.Join(",", fp.Disks) : null,
        "bios"             => fp.Bios,
        "volumeSerial"     => fp.VolumeSerial,
        "cpu"              => fp.Cpu,
        "machineGuid"      => fp.MachineGuid,
        "windowsProductId" => fp.WindowsProductId,
        "mac"              => fp.Macs is { Count: > 0 }
                              ? string.Join(",", fp.Macs) : null,
        _                  => null,
    };
}
