using System.Text;

namespace LicenseSDK.Security;

/// <summary>
/// Protects the HMAC shared secret by storing it as XOR-obfuscated byte
/// fragments. At runtime the fragments are concatenated and de-XOR'd to
/// recover the plaintext string.
///
/// This raises the bar against casual ILSpy inspection — the secret no
/// longer appears as a single string literal in the IL.
/// </summary>
internal static class KeyProtector
{
    // The secret "licensesdk-hmac-secret-vymhxjwornzu-2026" split into
    // 3 fragments, each byte XOR'd with 0xA3.
    // Store as separate fields so Obfuscar renames them to random gibberish.
    //
    // Fragment 1:  "licensesdk-hmac-"
    private static readonly byte[] _fragment1 =
    [
        0xCF, 0xCA, 0xC0, 0xC6, 0xCD, 0xD0, 0xC6, 0xD0,
        0xC7, 0xC8, 0x8E, 0xCB, 0xCE, 0xC2,
    ];

    // Fragment 2:  "secret-vymhxj"
    private static readonly byte[] _fragment2 =
    [
        0xC0, 0x8E, 0xD0, 0xC6, 0xC0, 0xD1, 0xC6, 0xD7,
        0x8E, 0xD5, 0xDA, 0xCE, 0xCB,
    ];

    // Fragment 3:  "wornzu-2026"
    private static readonly byte[] _fragment3 =
    [
        0xDB, 0xC9, 0xD4, 0xCC, 0xD1, 0xCD, 0xD9, 0xD6,
        0x8E, 0x91, 0x93, 0x91, 0x95,
    ];

    private const byte XorKey = 0xA3;

    /// <summary>Recovers the original HMAC shared secret.</summary>
    internal static string Reveal()
    {
        var combined = new byte[_fragment1.Length + _fragment2.Length + _fragment3.Length];
        Buffer.BlockCopy(_fragment1, 0, combined, 0, _fragment1.Length);
        Buffer.BlockCopy(_fragment2, 0, combined, _fragment1.Length, _fragment2.Length);
        Buffer.BlockCopy(_fragment3, 0, combined, _fragment1.Length + _fragment2.Length, _fragment3.Length);

        for (int i = 0; i < combined.Length; i++)
            combined[i] ^= XorKey;

        return Encoding.UTF8.GetString(combined);
    }
}
