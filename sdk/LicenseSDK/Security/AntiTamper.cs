using System.Diagnostics;
using System.Runtime.InteropServices;

namespace LicenseSDK.Security;

/// <summary>
/// Multi-layered anti-tamper detection. All native API calls go through
/// <see cref="NativeResolver"/> — zero [DllImport] declarations remain,
/// so x64dbg's import table shows nothing.
///
/// Detection chain (Release builds only):
///   1. Debugger.IsAttached          — managed debugger
///   2. IsDebuggerPresent()          — kernel32 via NativeResolver
///   3. NtQueryInformationProcess    — ProcessDebugPort (ntdll)
///   4. NtQueryInformationProcess    — ProcessDebugFlags (ntdll)
///   5. NtQueryInformationProcess    — ProcessDebugObjectHandle (ntdll)
///   6. RtlGetNtGlobalFlags          — PEB flags (0x70)
///   7. DebuggerWindowDetector       — window class enumeration (20+ tools)
///   8. DebuggerWindowDetector       — process name enumeration (20+ tools)
/// </summary>
internal static class AntiTamper
{
    private const int ProcessDebugPort = 7;
    private const int ProcessDebugFlags = 31;
    private const int ProcessDebugObjectHandle = 30;
    private const int NtGlobalFlagDebugMask = 0x70;

    /// <summary>Runs the full detection chain. Throws LicenseSecurityException on detection.</summary>
    internal static void Assert()
    {
#if !DEBUG
        // ── 1. Managed debugger ──
        if (Debugger.IsAttached)
        {
            Troll.Show();
            throw new LicenseSecurityException("Debugger detected — execution blocked.");
        }

        // ── 2. Kernel32 IsDebuggerPresent (no DllImport) ──
        if (NativeResolver.IsDebuggerPresent())
        {
            Troll.Show();
            throw new LicenseSecurityException("Debugger detected — execution blocked.");
        }

        // ── 3-5. NtQueryInformationProcess (3 checks, no DllImport) ──
        if (CheckNtQueryInformationProcess())
        {
            Troll.Show();
            throw new LicenseSecurityException("Debugger detected — execution blocked.");
        }

        // ── 6. PEB NtGlobalFlag (no DllImport) ──
        if (CheckNtGlobalFlag())
        {
            Troll.Show();
            throw new LicenseSecurityException("Debugger detected — execution blocked.");
        }

        // ── 7-8. Tool window/process enumeration ──
        if (DebuggerWindowDetector.IsDebuggerWindowPresent() ||
            DebuggerWindowDetector.IsDebuggerProcessRunning())
        {
            Troll.Show();
            throw new LicenseSecurityException("Reverse-engineering tool detected — execution blocked.");
        }
#endif
    }

    private static bool CheckNtQueryInformationProcess()
    {
        IntPtr hProcess = Process.GetCurrentProcess().Handle;
        int retLen;

        // Check 3a: ProcessDebugPort
        IntPtr buf = Marshal.AllocHGlobal(IntPtr.Size);
        try
        {
            int status = NativeResolver.NtQueryInformationProcess(
                hProcess, ProcessDebugPort, buf, IntPtr.Size, out retLen);
            if (status == 0 && Marshal.ReadIntPtr(buf) == new IntPtr(-1))
                return true;
        }
        finally { Marshal.FreeHGlobal(buf); }

        // Check 3b: ProcessDebugFlags
        buf = Marshal.AllocHGlobal(4);
        try
        {
            int status = NativeResolver.NtQueryInformationProcess(
                hProcess, ProcessDebugFlags, buf, 4, out retLen);
            if (status == 0 && Marshal.ReadInt32(buf) == 0)
                return true;
        }
        finally { Marshal.FreeHGlobal(buf); }

        // Check 3c: ProcessDebugObjectHandle
        buf = Marshal.AllocHGlobal(IntPtr.Size);
        try
        {
            int status = NativeResolver.NtQueryInformationProcess(
                hProcess, ProcessDebugObjectHandle, buf, IntPtr.Size, out retLen);
            if (status == 0 && Marshal.ReadIntPtr(buf) != IntPtr.Zero)
                return true;
        }
        finally { Marshal.FreeHGlobal(buf); }

        return false;
    }

    private static bool CheckNtGlobalFlag()
    {
        try
        {
            int flags = NativeResolver.RtlGetNtGlobalFlags();
            return (flags & NtGlobalFlagDebugMask) != 0;
        }
        catch
        {
            return false;
        }
    }
}
