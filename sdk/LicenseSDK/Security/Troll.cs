using System.Runtime.InteropServices;

namespace LicenseSDK.Security;

/// <summary>
/// When a reverse-engineering tool is detected, show a taunting message
/// before blocking execution. Uses NativeResolver for the MessageBoxW call —
/// no [DllImport] used.
/// </summary>
internal static class Troll
{
    private const uint MB_OK = 0x00000000;
    private const uint MB_ICONERROR = 0x00000010;
    private const uint MB_TOPMOST = 0x00040000;

    internal static void Show()
    {
#if !DEBUG
        // Allocate UTF-16 strings in unmanaged memory for the MessageBoxW call
        IntPtr text = Marshal.StringToHGlobalUni("你逆向你妈逼");
        IntPtr caption = Marshal.StringToHGlobalUni("LicenseSDK — 安全防护");

        try
        {
            NativeResolver.MessageBoxW(
                IntPtr.Zero, text, caption,
                MB_OK | MB_ICONERROR | MB_TOPMOST);
        }
        finally
        {
            Marshal.FreeHGlobal(text);
            Marshal.FreeHGlobal(caption);
        }
#endif
    }
}
