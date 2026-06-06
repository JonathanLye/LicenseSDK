namespace LicenseSDK.Fingerprint;

/// <summary>
/// Cleans raw hardware values: filters OEM junk strings, enforces minimum length,
/// and rejects all-zero/identical-character strings.
/// Used by FingerprintCollector before values enter the hash pipeline.
/// </summary>
internal static class FingerprintNormalizer
{
    // Known OEM / BIOS filler strings that carry no identifying information
    private static readonly string[] JunkPatterns =
    [
        "TO BE FILLED",
        "TO_BE_FILL",
        "DEFAULT STRING",
        "NOT APPLICABLE",
        "NOT AVAILABLE",
        "NONE",
        "O.E.M.",
        "OEM",
        "SERIAL",
        "SYSTEM SERIAL",
        "CHASSIS SERIAL",
        "SYSTEM SERIAL NUMBER",
        "BASE BOARD SERIAL",
        "0123456789",               // Fake numeric
        "UNDEFINED",
        "UNKNOWN",
        "RESERVED",
        "TBD",
        "123456789",
        "CHANGE_ME",
    ];

    /// <summary>
    /// Normalize a raw hardware string. Returns null when the value is junk.
    /// </summary>
    internal static string? Normalize(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
            return null;

        raw = raw.Trim().ToUpperInvariant();

        // Reject values shorter than 4 meaningful characters
        if (raw.Length < 4)
            return null;

        // Reject OEM junk patterns
        if (JunkPatterns.Any(j => raw.Contains(j)))
            return null;

        // Reject all-same-character strings (e.g. "00000000", "FFFFFFFFFF")
        if (raw.Length >= 6 && raw.Distinct().Count() <= 2)
            return null;

        return raw;
    }
}
