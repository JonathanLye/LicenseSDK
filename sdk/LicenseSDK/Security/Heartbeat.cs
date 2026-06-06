namespace LicenseSDK.Security;

/// <summary>
/// Cross-validation counter for distributed anti-tamper check points.
///
/// Each inline check point calls <c>Beat(prime)</c> with a unique prime increment.
/// At the end of each public API method, <c>VerifyTotal()</c> checks that the
/// counter is non-zero. If an attacker NOPs out ALL check points, the counter
/// stays at zero and verification fails.
///
/// This is a simple but effective integrity check — patching 50 separate
/// inline call sites is significantly harder than patching a single Assert().
/// </summary>
internal static class Heartbeat
{
    [ThreadStatic]
    private static int _counter;

    /// <summary>Record a check point hit. Increments by <paramref name="prime"/>.</summary>
    internal static void Beat(int prime)
    {
        _counter += prime;
    }

    /// <summary>
    /// Throws if the heartbeat counter is zero — meaning no check points fired.
    /// Called at the end of each public API method.
    /// </summary>
    internal static void VerifyTotal()
    {
#if !DEBUG
        if (_counter <= 0)
        {
            Troll.Show();
            throw new LicenseSecurityException("Tamper detected — no checks fired");
        }
#endif
    }

    /// <summary>Reset the counter at the start of each public API method.</summary>
    internal static void Reset()
    {
        _counter = 0;
    }
}
