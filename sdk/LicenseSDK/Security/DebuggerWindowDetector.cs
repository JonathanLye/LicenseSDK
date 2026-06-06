using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace LicenseSDK.Security;

/// <summary>
/// Detects reverse-engineering tools by enumerating visible windows
/// and running processes. Uses NativeResolver for all Win32 calls —
/// no [DllImport] declarations.
/// </summary>
internal static class DebuggerWindowDetector
{
    private static readonly string[] DebuggerClassNames =
    [
        "x64dbg", "x32dbg",
        "dnSpy", "dnSpy-ILSpy", "HwndWrapper[dnSpy",
        "Cheat Engine", "TForm1", "TCEForm",
        "OllyDbg", "OLLYDBG", "TRegshot",
        "TIdaWindow", "TViewer",
        "ProcessHacker", "PROCEXP_MAINFRAME",
        "PROCMON_WINDOW_CLASS",
        "ImmunityDebugger",
        "WinDbgFrameClass", "WinDbgView",
        "Qt5QWindowIcon",
        "WindowsForms10.Window.8.app.0.",
    ];

    private static readonly string[] DebuggerProcessNames =
    [
        "x64dbg", "x32dbg", "x96dbg",
        "dnSpy", "dnSpy-x86", "dnSpy.Console",
        "cheatengine", "cheatengine-x86_64", "cheatengine-i386",
        "ollydbg", "OLLYDBG",
        "ida", "ida64", "idaw", "idaw64",
        "processhacker", "procexp", "procexp64",
        "procmon", "procmon64",
        "immunitydebugger",
        "windbg", "windbg.exe",
        "frida", "frida.exe",
        "scylla", "Scylla_x64", "Scylla_x86",
        "apimonitor", "apitool",
        "httppdb",
        "x64netdumper", "megadumper", "megadumper_x64",
    ];

    internal static bool IsDebuggerWindowPresent()
    {
        bool found = false;

        // NativeResolver.EnumWindows calls user32.EnumWindows via resolved function pointer
        NativeResolver.EnumWindows((hWnd, _) =>
        {
            if (!NativeResolver.IsWindowVisible(hWnd))
                return true;

            // Allocate buffer for class name
            IntPtr sb = Marshal.AllocHGlobal(512);
            try
            {
                int len = NativeResolver.GetClassNameW(hWnd, sb, 256);
                if (len <= 0) return true;

                string className = Marshal.PtrToStringUni(sb, len) ?? "";
                foreach (string name in DebuggerClassNames)
                {
                    if (className.Contains(name, StringComparison.OrdinalIgnoreCase))
                    {
                        // Double-check with window title for Qt apps
                        if (name == "Qt5QWindowIcon")
                        {
                            IntPtr titleBuf = Marshal.AllocHGlobal(512);
                            try
                            {
                                int titleLen = NativeResolver.GetWindowTextW(hWnd, titleBuf, 256);
                                string title = Marshal.PtrToStringUni(titleBuf, titleLen) ?? "";
                                if (!title.Contains("dbg", StringComparison.OrdinalIgnoreCase) &&
                                    !title.Contains("dump", StringComparison.OrdinalIgnoreCase))
                                    return true; // false positive, keep going
                            }
                            finally { Marshal.FreeHGlobal(titleBuf); }
                        }

                        found = true;
                        return false;
                    }
                }
            }
            finally { Marshal.FreeHGlobal(sb); }

            return true;
        }, IntPtr.Zero);

        return found;
    }

    internal static bool IsDebuggerProcessRunning()
    {
        try
        {
            var running = Process.GetProcesses()
                .Select(p =>
                {
                    try { return p.ProcessName.ToLowerInvariant(); }
                    catch { return ""; }
                })
                .ToHashSet();

            foreach (string name in DebuggerProcessNames)
            {
                if (running.Contains(name.ToLowerInvariant()))
                    return true;
            }

            if ((running.Contains("java") || running.Contains("javaw")) &&
                IsGhidraWindowPresent())
                return true;

            return false;
        }
        catch
        {
            return false;
        }
    }

    private static bool IsGhidraWindowPresent()
    {
        bool found = false;
        NativeResolver.EnumWindows((hWnd, _) =>
        {
            if (!NativeResolver.IsWindowVisible(hWnd))
                return true;

            IntPtr sb = Marshal.AllocHGlobal(512);
            try
            {
                int len = NativeResolver.GetWindowTextW(hWnd, sb, 256);
                string title = Marshal.PtrToStringUni(sb, len) ?? "";
                if (title.Contains("Ghidra", StringComparison.OrdinalIgnoreCase))
                {
                    found = true;
                    return false;
                }
            }
            finally { Marshal.FreeHGlobal(sb); }

            return true;
        }, IntPtr.Zero);

        return found;
    }
}
