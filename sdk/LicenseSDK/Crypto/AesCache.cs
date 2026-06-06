using System.Security.Cryptography;
using System.Text;

namespace LicenseSDK.Crypto;

/// <summary>AES-256-GCM encryption for the local cache file.</summary>
public static class AesCache
{
    // Derive a machine-specific key from MachineGuid so the cache file is non-portable
    public static byte[] DeriveKey(string machineGuid)
    {
        // PBKDF2 with a fixed salt tied to this application
        const string appSalt = "LicenseSDK-v1-cache-salt";
        return Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes(machineGuid),
            Encoding.UTF8.GetBytes(appSalt),
            iterations: 100_000,
            HashAlgorithmName.SHA256,
            outputLength: 32);
    }

    public static byte[] Encrypt(string plaintext, byte[] key)
    {
        var nonce = RandomNumberGenerator.GetBytes(AesGcm.NonceByteSizes.MaxSize); // 12 bytes
        var tag = new byte[AesGcm.TagByteSizes.MaxSize];                           // 16 bytes
        var data = Encoding.UTF8.GetBytes(plaintext);
        var ciphertext = new byte[data.Length];

        using var aes = new AesGcm(key, AesGcm.TagByteSizes.MaxSize);
        aes.Encrypt(nonce, data, ciphertext, tag);

        // Layout: [nonce(12)][tag(16)][ciphertext]
        return [.. nonce, .. tag, .. ciphertext];
    }

    public static string Decrypt(byte[] blob, byte[] key)
    {
        int nonceLen = AesGcm.NonceByteSizes.MaxSize;
        int tagLen   = AesGcm.TagByteSizes.MaxSize;

        var nonce      = blob[..nonceLen];
        var tag        = blob[nonceLen..(nonceLen + tagLen)];
        var ciphertext = blob[(nonceLen + tagLen)..];
        var plaintext  = new byte[ciphertext.Length];

        using var aes = new AesGcm(key, AesGcm.TagByteSizes.MaxSize);
        aes.Decrypt(nonce, ciphertext, tag, plaintext);
        return Encoding.UTF8.GetString(plaintext);
    }
}
