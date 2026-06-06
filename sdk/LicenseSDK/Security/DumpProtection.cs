using System.Runtime.InteropServices;

namespace LicenseSDK.Security;

/// <summary>
/// Applies Windows process mitigation policies via NativeResolver.
///
/// NOTE: Both NtSetInformationProcess and SetProcessMitigationPolicy are
/// DISABLED by default because they cause native-level crashes on some
/// Windows configurations (.NET 10 WPF process termination).
///
/// The crash occurs because:
/// 1. MEM_EXECUTE_OPTION_PERMANENT can conflict with .NET JIT behaviour
/// 2. MicrosoftSignedOnly blocks required .NET resource DLLs
///
/// These features can be re-enabled for specific hardened environments
/// where the target Windows version and .NET runtime are well-known.
/// </summary>
internal static class DumpProtection
{
    internal static void Apply()
    {
        // Disabled — see class doc for explanation.
        // Uncomment the following lines only if you've verified on your
        // target Windows version that neither call crashes the process.
        //
        // #if !DEBUG
        // LockExecuteFlags();
        // EnableSignaturePolicy();
        // #endif
    }

    // private static void LockExecuteFlags() { ... }
    // private static void EnableSignaturePolicy() { ... }
}
