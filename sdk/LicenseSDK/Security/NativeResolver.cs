using System.Diagnostics;
using System.Runtime.InteropServices;

namespace LicenseSDK.Security;

/// <summary>
/// Resolves native Win32 API addresses at runtime by walking the PE export tables
/// of loaded system DLLs using FNV-1a hash comparison.
///
/// This eliminates all [DllImport] declarations from the SDK, so x64dbg's import
/// table view shows zero references to IsDebuggerPresent, NtQueryInformationProcess,
/// EnumWindows, etc.
///
/// Resolution is done once per function and cached in static delegates.
/// </summary>
internal static class NativeResolver
{
    // ── FNV-1a hash ──────────────────────────────────────────────
    private const uint FnvPrime = 16777619;
    private const uint FnvOffset = 2166136261;

    private static uint HashString(string s)
    {
        uint hash = FnvOffset;
        foreach (char c in s)
        {
            byte b = c >= 'A' && c <= 'Z' ? (byte)(c | 0x20) : (byte)c;
            hash = (hash ^ b) * FnvPrime;
        }
        return hash;
    }

    private static uint HashAnsi(IntPtr ptr)
    {
        uint hash = FnvOffset;
        int i = 0;
        while (true)
        {
            byte b = Marshal.ReadByte(ptr, i);
            if (b == 0) break;
            if (b >= 0x41 && b <= 0x5A) b |= 0x20; // lowercase
            hash = (hash ^ b) * FnvPrime;
            i++;
        }
        return hash;
    }

    // ── Pre-computed hashes ──────────────────────────────────────
    // Module names
    private static readonly uint H_KERNEL32 = HashString("kernel32.dll");
    private static readonly uint H_NTDLL    = HashString("ntdll.dll");
    private static readonly uint H_USER32   = HashString("user32.dll");

    // Function names
    private static readonly uint H_IsDebuggerPresent          = HashString("IsDebuggerPresent");
    private static readonly uint H_NtQueryInformationProcess  = HashString("NtQueryInformationProcess");
    private static readonly uint H_RtlGetNtGlobalFlags        = HashString("RtlGetNtGlobalFlags");
    private static readonly uint H_NtSetInformationProcess    = HashString("NtSetInformationProcess");
    private static readonly uint H_SetProcessMitigationPolicy = HashString("SetProcessMitigationPolicy");
    private static readonly uint H_EnumWindows                = HashString("EnumWindows");
    private static readonly uint H_GetClassNameW              = HashString("GetClassNameW");
    private static readonly uint H_IsWindowVisible            = HashString("IsWindowVisible");
    private static readonly uint H_GetWindowTextW             = HashString("GetWindowTextW");
    private static readonly uint H_MessageBoxW                = HashString("MessageBoxW");
    private static readonly uint H_GetVolumeInformationW      = HashString("GetVolumeInformationW");

    // ── Delegate type definitions ────────────────────────────────
    internal delegate bool IsDebuggerPresentDelegate();
    internal delegate int NtQueryInformationProcessDelegate(
        IntPtr ProcessHandle, int InfoClass, IntPtr Info, int Size, out int RetLen);
    internal delegate int RtlGetNtGlobalFlagsDelegate();
    internal delegate int NtSetInformationProcessDelegate(
        IntPtr ProcessHandle, int InfoClass, ref uint Info, int Size);
    internal delegate bool SetProcessMitigationPolicyDelegate(
        int Policy, IntPtr Buffer, int Size);
    internal delegate bool EnumWindowsDelegate(EnumWindowsCallback callback, IntPtr lParam);
    internal delegate int GetClassNameWDelegate(IntPtr hWnd, IntPtr lpClassName, int maxCount);
    internal delegate bool IsWindowVisibleDelegate(IntPtr hWnd);
    internal delegate int GetWindowTextWDelegate(IntPtr hWnd, IntPtr lpString, int maxCount);
    internal delegate int MessageBoxWDelegate(IntPtr hWnd, IntPtr lpText, IntPtr lpCaption, uint uType);
    internal delegate bool GetVolumeInformationWDelegate(
        string? root, IntPtr volBuf, int volSize, out uint serial,
        out int maxComp, out int flags, IntPtr fsBuf, int fsSize);

    internal delegate bool EnumWindowsCallback(IntPtr hWnd, IntPtr lParam);

    // ── Cached delegates ─────────────────────────────────────────
    private static IsDebuggerPresentDelegate? _isDebuggerPresent;
    private static NtQueryInformationProcessDelegate? _ntQueryInfo;
    private static RtlGetNtGlobalFlagsDelegate? _rtlGetNtGlobalFlags;
    private static NtSetInformationProcessDelegate? _ntSetInfo;
    private static SetProcessMitigationPolicyDelegate? _setProcMitigation;
    private static EnumWindowsDelegate? _enumWindows;
    private static GetClassNameWDelegate? _getClassNameW;
    private static IsWindowVisibleDelegate? _isWindowVisible;
    private static GetWindowTextWDelegate? _getWindowTextW;
    private static MessageBoxWDelegate? _messageBoxW;
    private static GetVolumeInformationWDelegate? _getVolumeInfoW;

    // ── Module base resolution ───────────────────────────────────
    private static IntPtr FindModule(string moduleName, uint nameHash)
    {
        try
        {
            using var process = Process.GetCurrentProcess();
            foreach (ProcessModule module in process.Modules)
            {
                try
                {
                    string? mn = module.ModuleName;
                    if (mn != null && HashString(mn) == nameHash)
                        return module.BaseAddress;
                }
                catch { continue; }
            }
        }
        catch { }
        return IntPtr.Zero;
    }

    // ── PE export resolution ─────────────────────────────────────
    private static IntPtr FindExport(IntPtr moduleBase, uint targetHash)
    {
        if (moduleBase == IntPtr.Zero) return IntPtr.Zero;

        try
        {
            // DOS header
            if (Marshal.ReadInt16(moduleBase) != 0x5A4D) return IntPtr.Zero; // "MZ"

            int e_lfanew = Marshal.ReadInt32(moduleBase, 0x3C);
            IntPtr ntHeaders = moduleBase + e_lfanew;

            // NT signature
            if (Marshal.ReadInt32(ntHeaders) != 0x00004550) return IntPtr.Zero; // "PE\0\0"

            // Determine PE32+ vs PE32
            ushort magic = (ushort)Marshal.ReadInt16(ntHeaders + 24);
            bool isPE32Plus = magic == 0x20B;

            // DataDirectory[0] (Export Directory) offset
            int dataDirOffset = isPE32Plus ? 112 : 96;
            IntPtr exportDataDir = ntHeaders + 24 + dataDirOffset;

            uint exportRva = (uint)Marshal.ReadInt32(exportDataDir);
            if (exportRva == 0) return IntPtr.Zero;

            IntPtr exportDir = moduleBase + (int)exportRva;

            uint numNames = (uint)Marshal.ReadInt32(exportDir + 24);

            uint nameRva   = (uint)Marshal.ReadInt32(exportDir + 32);
            uint funcRva   = (uint)Marshal.ReadInt32(exportDir + 28);
            uint ordRva    = (uint)Marshal.ReadInt32(exportDir + 36);

            IntPtr nameArray  = moduleBase + (int)nameRva;
            IntPtr funcArray  = moduleBase + (int)funcRva;
            IntPtr ordArray   = moduleBase + (int)ordRva;

            for (uint i = 0; i < numNames; i++)
            {
                uint namePtrRva = (uint)Marshal.ReadInt32(nameArray, (int)(i * 4));
                IntPtr funcName = moduleBase + (int)namePtrRva;

                if (HashAnsi(funcName) == targetHash)
                {
                    ushort ordinal = (ushort)Marshal.ReadInt16(ordArray, (int)(i * 2));
                    uint funcRvaValue = (uint)Marshal.ReadInt32(funcArray, ordinal * 4);
                    return moduleBase + (int)funcRvaValue;
                }
            }
        }
        catch { }

        return IntPtr.Zero;
    }

    private static T Resolve<T>(string moduleName, uint moduleHash, uint funcHash)
    {
        IntPtr baseAddr = FindModule(moduleName, moduleHash);
        IntPtr funcAddr = FindExport(baseAddr, funcHash);
        if (funcAddr == IntPtr.Zero)
            throw new InvalidOperationException(
                $"Failed to resolve {moduleName}!{funcHash:X8}");

        return Marshal.GetDelegateForFunctionPointer<T>(funcAddr);
    }

    // ── Public accessors (resolve once, cache forever) ───────────

    internal static IsDebuggerPresentDelegate IsDebuggerPresent =>
        _isDebuggerPresent ??= Resolve<IsDebuggerPresentDelegate>(
            "kernel32.dll", H_KERNEL32, H_IsDebuggerPresent);

    internal static NtQueryInformationProcessDelegate NtQueryInformationProcess =>
        _ntQueryInfo ??= Resolve<NtQueryInformationProcessDelegate>(
            "ntdll.dll", H_NTDLL, H_NtQueryInformationProcess);

    internal static RtlGetNtGlobalFlagsDelegate RtlGetNtGlobalFlags =>
        _rtlGetNtGlobalFlags ??= Resolve<RtlGetNtGlobalFlagsDelegate>(
            "ntdll.dll", H_NTDLL, H_RtlGetNtGlobalFlags);

    internal static NtSetInformationProcessDelegate NtSetInformationProcess =>
        _ntSetInfo ??= Resolve<NtSetInformationProcessDelegate>(
            "ntdll.dll", H_NTDLL, H_NtSetInformationProcess);

    internal static SetProcessMitigationPolicyDelegate SetProcessMitigationPolicy =>
        _setProcMitigation ??= Resolve<SetProcessMitigationPolicyDelegate>(
            "kernel32.dll", H_KERNEL32, H_SetProcessMitigationPolicy);

    internal static EnumWindowsDelegate EnumWindows =>
        _enumWindows ??= Resolve<EnumWindowsDelegate>(
            "user32.dll", H_USER32, H_EnumWindows);

    internal static GetClassNameWDelegate GetClassNameW =>
        _getClassNameW ??= Resolve<GetClassNameWDelegate>(
            "user32.dll", H_USER32, H_GetClassNameW);

    internal static IsWindowVisibleDelegate IsWindowVisible =>
        _isWindowVisible ??= Resolve<IsWindowVisibleDelegate>(
            "user32.dll", H_USER32, H_IsWindowVisible);

    internal static GetWindowTextWDelegate GetWindowTextW =>
        _getWindowTextW ??= Resolve<GetWindowTextWDelegate>(
            "user32.dll", H_USER32, H_GetWindowTextW);

    internal static MessageBoxWDelegate MessageBoxW =>
        _messageBoxW ??= Resolve<MessageBoxWDelegate>(
            "user32.dll", H_USER32, H_MessageBoxW);

    internal static GetVolumeInformationWDelegate GetVolumeInformationW =>
        _getVolumeInfoW ??= Resolve<GetVolumeInformationWDelegate>(
            "kernel32.dll", H_KERNEL32, H_GetVolumeInformationW);
}
