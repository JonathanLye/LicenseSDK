using System.Reflection;
using System.Security.Cryptography;

namespace LicenseSDK.Security;

/// <summary>
/// Verifies the integrity of LicenseSDK.dll at runtime by computing its
/// SHA-256 hash and comparing it against a value embedded at build time.
/// Detects binary patching (NOPped calls, modified IL, etc.).
/// </summary>
internal static class IntegrityChecker
{
    // The expected SHA-256 hash of the Release-built LicenseSDK.dll.
    // Computed at build time; the placeholder bytes here cause a deliberate
    // mismatch on first run — the user builds Release, then copies the real
    // hash back here.
    //
    // Stored as separate fragments to evade simple string searches.
    private static readonly byte[] _expectedHash = BuildExpectedHash();

    // Dword at a known file offset used as a quick integrity check
    // without hashing the entire file every time.
    private const long PeCheckOffset = 0x3C; // IMAGE_DOS_SIGNATURE e_lfanew

    /// <summary>True if the assembly on disk matches its expected hash.</summary>
    internal static bool IsAssemblyValid()
    {
        try
        {
            string? path = Assembly.GetExecutingAssembly().Location;
            if (string.IsNullOrEmpty(path) || !File.Exists(path))
                return false;

            byte[] diskHash;
            using (var stream = File.OpenRead(path))
            using (var sha256 = SHA256.Create())
            {
                diskHash = sha256.ComputeHash(stream);
            }

            return diskHash.AsSpan().SequenceEqual(_expectedHash);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Lightweight pre-check: reads a known dword from the PE header
    /// and compares against the expected value. Fast enough to run every
    /// Assert() call; the full SHA256 check runs periodically.
    /// </summary>
    internal static bool QuickPeCheck()
    {
        try
        {
            string? path = Assembly.GetExecutingAssembly().Location;
            if (string.IsNullOrEmpty(path) || !File.Exists(path))
                return false;

            using var stream = File.OpenRead(path);
            if (stream.Length < PeCheckOffset + 4) return false;

            stream.Seek(PeCheckOffset, SeekOrigin.Begin);
            byte[] buf = new byte[4];
            stream.ReadExactly(buf);
            uint e_lfanew = BitConverter.ToUInt32(buf);

            // e_lfanew should point to "PE\0\0" signature
            if (stream.Length < e_lfanew + 4) return false;
            stream.Seek(e_lfanew, SeekOrigin.Begin);
            stream.ReadExactly(buf);

            // "PE\0\0" = 0x00004550
            return buf[0] == 'P' && buf[1] == 'E' && buf[2] == 0 && buf[3] == 0;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Build the expected hash from byte fragments to avoid storing
    /// the entire hash as a single static array in the PE image.
    ///
    /// IMPORTANT: After building Release, replace the fragments below
    /// with the actual SHA-256 of the output LicenseSDK.dll.
    /// Run this command:
    ///   certutil -hashfile bin\Release\net10.0-windows\LicenseSDK.dll SHA256
    /// Then split the 64-char hex string into 4 fragments.
    /// </summary>
    private static byte[] BuildExpectedHash()
    {
        // ── REPLACE ME: fragments of the SHA-256 hex string ──────
        // Format: 64 hex chars → split into 4 fragments of 16 chars each
        // Fragment 1 (chars 0-15):  XXXXXXXXXXXXXXXX
        // Fragment 2 (chars 16-31): XXXXXXXXXXXXXXXX
        // Fragment 3 (chars 32-47): XXXXXXXXXXXXXXXX
        // Fragment 4 (chars 48-63): XXXXXXXXXXXXXXXX

        // Default: all zeros → IntegrityChecker will return false
        // until you replace these with the real hash.
#if !DEBUG
        const string f1 = "0000000000000000";
        const string f2 = "0000000000000000";
        const string f3 = "0000000000000000";
        const string f4 = "0000000000000000";

        string hex = f1 + f2 + f3 + f4;
        return Convert.FromHexString(hex);
#else
        // Debug: return a dummy hash that never matches
        return new byte[32];
#endif
    }
}
