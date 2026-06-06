using System.Security.Cryptography;
using System.Text;

namespace LicenseSDK.Crypto;

internal static class RsaVerifier
{
    private static string _pubKeyPem = "";

    private static string GetPublicKeyPem()
    {
        if (_pubKeyPem.Length > 0)
            return _pubKeyPem;

        var p1 = "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUF1NnpCN";
        var p2 = "FNLaVdWWll0d0FzUDNEcgpEU0IvVnpGdkRPVWV2WmZBbm0vWW9HdGRpRlpHbjM0SkdoUEErdjdDTkJ1SUZNVmE0SzhZUjVxZUM5SD";
        var p3 = "hIMFg3ClFHcVFRMnhWc0FtYW5waEIvU0tRV1orQ1ByZmsxNmNmTm5PUUVGRFdqUmkxRFZQR1VyM0hYTnJmRHZBVHpCb0MKM2ozekx";
        var p4 = "ZM0dmTlNzcGVXYUVabEhWUkc0RFVnN1pjZFlZeDJoaWdnTzU4VUVrREQ2V2R4QnJkVDdreEZtbXBrZgpFNGNiblVYVGJpOWZMRDFV";
        var p5 = "N0k5KzhlMGlHZHFDTmRZY2tFaGlwZWsvWWk5Y1M3S3JzTlpmT0x3SnZ0blVJbHo0CjFDL2dFbzZUdlhNZ1BPakZianRBeE4wcmJFQ";
        var p6 = "zIwTzc5QVZPemNjUkwvSWFOaXkyYk1kYTgxQ013c2l4MFo1R0UKK1FJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==";

        _pubKeyPem = Encoding.UTF8.GetString(Convert.FromBase64String(p1 + p2 + p3 + p4 + p5 + p6));
        return _pubKeyPem;
    }

    internal static bool Verify(string responseBody, string? signatureBase64)
    {
        if (string.IsNullOrEmpty(signatureBase64))
            return false;

        try
        {
            using var rsa = RSA.Create();
            rsa.ImportFromPem(GetPublicKeyPem());

            var bodyHash = SHA256.HashData(Encoding.UTF8.GetBytes(responseBody));
            var signature = Convert.FromBase64String(signatureBase64);

            return rsa.VerifyHash(bodyHash, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }
        catch
        {
            return false;
        }
    }
}
