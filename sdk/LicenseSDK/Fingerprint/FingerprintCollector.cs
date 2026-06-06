using System.Management;
using System.Net.NetworkInformation;
using Microsoft.Win32;
using LicenseSDK.Security;

namespace LicenseSDK.Fingerprint;

/// <summary>Raw hardware fingerprint data collected from this machine.</summary>
public class FingerprintData
{
    public string? Motherboard { get; init; }
    public List<string>? Disks { get; init; }
    public string? Bios { get; init; }
    public string? VolumeSerial { get; init; }
    public string? Cpu { get; init; }
    public string? MachineGuid { get; init; }
    public string? WindowsProductId { get; init; }
    public List<string>? Macs { get; init; }
}

/// <summary>Collects hardware fingerprints using WMI and system APIs.</summary>
public static class FingerprintCollector
{
    // GetVolumeInformation is resolved via NativeResolver — no [DllImport]

    public static FingerprintData Collect()
    {
#if !DEBUG
        Guard(); // Check 38
#endif
        var fp = new FingerprintData
        {
            Motherboard     = GetMotherboardSerial(),
            Disks           = GetAllDiskSerials(),
            Bios            = GetBiosSerial(),
            VolumeSerial    = GetVolumeSerial(),
            Cpu             = GetCpuId(),
            MachineGuid     = GetMachineGuid(),
            WindowsProductId = GetWindowsProductId(),
            Macs            = GetAllPhysicalMacs(),
        };

#if !DEBUG
        Guard(); // Check 39
#endif
        return fp;
    }

#if !DEBUG
    private static void Guard(int prime = 113)
    {
        if (NativeResolver.IsDebuggerPresent())
        {
            Troll.Show();
            throw new LicenseSecurityException("Tamper detected");
        }
        Heartbeat.Beat(prime);
    }
#endif

    // ── WMI helpers ──────────────────────────────────────────────

    private static string? QueryWmi(string wmiClass, string property)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher($"SELECT {property} FROM {wmiClass}");
            foreach (ManagementObject obj in searcher.Get())
            {
                var val = obj[property]?.ToString()?.Trim();
                var cleaned = FingerprintNormalizer.Normalize(val);
                if (cleaned is not null) return cleaned;
            }
        }
        catch { /* WMI unavailable or no data */ }
        return null;
    }

    private static List<string> QueryWmiAll(string wmiClass, string property)
    {
        var results = new List<string>();
        try
        {
            using var searcher = new ManagementObjectSearcher($"SELECT {property} FROM {wmiClass}");
            foreach (ManagementObject obj in searcher.Get())
            {
                var cleaned = FingerprintNormalizer.Normalize(obj[property]?.ToString()?.Trim());
                if (cleaned is not null && !results.Contains(cleaned))
                    results.Add(cleaned);
            }
        }
        catch { /* WMI unavailable */ }
        return results;
    }

    // ── Individual collectors ────────────────────────────────────

    private static string? GetMotherboardSerial()
    {
        // SMBIOS UUID (most stable) → BaseBoard SerialNumber (fallback)
        return QueryWmi("Win32_ComputerSystemProduct", "UUID")
            ?? QueryWmi("Win32_BaseBoard", "SerialNumber");
    }

    /// <summary>Returns all non-junk disk serial numbers (up to 16 drives).</summary>
    private static List<string> GetAllDiskSerials()
    {
        var all = QueryWmiAll("Win32_DiskDrive", "SerialNumber");
        // Sort for deterministic hashing
        all.Sort(StringComparer.Ordinal);
        return all;
    }

    private static string? GetBiosSerial() =>
        QueryWmi("Win32_BIOS", "SerialNumber");

    /// <summary>C: drive NTFS volume serial, with WMI fallback.</summary>
    private static string? GetVolumeSerial()
    {
        // Primary: kernel32.GetVolumeInformationW via NativeResolver
        try
        {
            if (NativeResolver.GetVolumeInformationW("C:\\", IntPtr.Zero, 0,
                    out uint serial, out _, out _, IntPtr.Zero, 0))
            {
                var result = FingerprintNormalizer.Normalize(serial.ToString("X8"));
                if (result is not null) return result;
            }
        }
        catch { }
        // Fallback: WMI Win32_LogicalDisk
        try
        {
            return QueryWmi("Win32_LogicalDisk WHERE DeviceID='C:'", "VolumeSerialNumber");
        }
        catch { }
        return null;
    }

    private static string? GetCpuId() =>
        QueryWmi("Win32_Processor", "ProcessorId");

    private static string? GetMachineGuid()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Cryptography", writable: false);
            return FingerprintNormalizer.Normalize(key?.GetValue("MachineGuid")?.ToString());
        }
        catch { return null; }
    }

    /// <summary>Windows Product ID from registry, with WMI fallback.</summary>
    private static string? GetWindowsProductId()
    {
        // Primary: registry HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductId
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion", writable: false);
            var result = FingerprintNormalizer.Normalize(key?.GetValue("ProductId")?.ToString());
            if (result is not null) return result;
        }
        catch { }
        // Fallback: WMI Win32_OperatingSystem
        try
        {
            return QueryWmi("Win32_OperatingSystem", "SerialNumber");
        }
        catch { }
        return null;
    }

    /// <summary>Returns all physical MAC addresses (sorted, deduped).</summary>
    private static List<string> GetAllPhysicalMacs()
    {
        try
        {
            var macs = NetworkInterface.GetAllNetworkInterfaces()
                .Where(n => n.NetworkInterfaceType != NetworkInterfaceType.Loopback
                         && n.NetworkInterfaceType != NetworkInterfaceType.Tunnel
                         && n.OperationalStatus == OperationalStatus.Up
                         && !n.Description.Contains("Virtual", StringComparison.OrdinalIgnoreCase)
                         && !n.Description.Contains("Hyper-V", StringComparison.OrdinalIgnoreCase))
                .Select(n => n.GetPhysicalAddress()
                    .ToString()
                    .ToUpperInvariant())
                .Where(mac => mac.Length >= 12 && mac != "000000000000")
                .Distinct()
                .ToList();

            macs.Sort(StringComparer.Ordinal);
            return macs;
        }
        catch { return new List<string>(); }
    }
}
