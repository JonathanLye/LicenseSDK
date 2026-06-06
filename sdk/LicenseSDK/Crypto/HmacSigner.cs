using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using LicenseSDK.Security;

namespace LicenseSDK.Crypto;

/// <summary>Generates HMAC-SHA256 request signatures matching the server's signing scheme.</summary>
public static class HmacSigner
{
    /// <param name="body">Request body object — will be JSON-serialized in the same way as the server.</param>
    /// <param name="sharedSecret">The secret configured in the license server.</param>
    /// <returns>(timestampMs, hexSignature)</returns>
    public static (long Timestamp, string Signature) Sign(object body, string sharedSecret)
    {
#if !DEBUG
        Guard(); // Check 35
#endif
        var timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var canonicalBody = JsonSerializer.Serialize(body);
        var message = $"{timestamp}:{canonicalBody}";
        var keyBytes = Encoding.UTF8.GetBytes(sharedSecret);
        var msgBytes = Encoding.UTF8.GetBytes(message);

#if !DEBUG
        Guard(); // Check 36
#endif
        var hash = HMACSHA256.HashData(keyBytes, msgBytes);
        return (timestamp, Convert.ToHexString(hash).ToLowerInvariant());
    }

#if !DEBUG
    private static void Guard(int prime = 107)
    {
        if (NativeResolver.IsDebuggerPresent())
        {
            Troll.Show();
            throw new LicenseSecurityException("Tamper detected");
        }
        Heartbeat.Beat(prime);
    }
#endif
}
