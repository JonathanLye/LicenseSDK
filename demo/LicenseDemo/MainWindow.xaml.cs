using System.IO;
using System.Windows;
using System.Windows.Media;
using LicenseSDK;
using LicenseSDK.Fingerprint;
using LicenseSDK.Security;

namespace LicenseDemo;

public partial class MainWindow : Window
{
    private LicenseManager? _license;
    private static readonly string _logPath = Path.Combine(
        AppDomain.CurrentDomain.BaseDirectory, "crash.log");

    public MainWindow()
    {
        try
        {
            InitializeComponent();
            Loaded += OnLoaded;
        }
        catch (Exception ex)
        {
            File.WriteAllText(_logPath, $"CTOR: {ex}");
            MessageBox.Show($"CTOR: {ex.GetType().Name}: {ex.Message}", "Crash");
        }
    }

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        try
        {
            File.AppendAllText(_logPath, $"{DateTime.UtcNow:HH:mm:ss.fff} OnLoaded\n");
            _license = BuildManager();

        // Display hardware fingerprint immediately — no network required
        var fp = _license.Fingerprint;
        FpMotherboard.Text       = fp.Motherboard      ?? "(unavailable)";
        FpDisk.Text              = fp.Disks is { Count: > 0 } ? string.Join(", ", fp.Disks) : "(unavailable)";
        FpBios.Text              = fp.Bios             ?? "(unavailable)";
        FpVolumeSerial.Text      = fp.VolumeSerial     ?? "(unavailable)";
        FpCpu.Text               = fp.Cpu              ?? "(unavailable)";
        FpMachineGuid.Text       = fp.MachineGuid      ?? "(unavailable)";
        FpWindowsProductId.Text  = fp.WindowsProductId ?? "(unavailable)";
        FpMac.Text               = fp.Macs is { Count: > 0 } ? string.Join(", ", fp.Macs) : "(unavailable)";
        FpHash.Text              = FingerprintHasher.ComputeHash(fp);

        // Auto-verify on startup
        await RunVerify();

        File.AppendAllText(_logPath, $"{DateTime.UtcNow:HH:mm:ss.fff} Done\n");
    }
    catch (Exception ex)
    {
        File.WriteAllText(_logPath, $"{DateTime.UtcNow:HH:mm:ss.fff} ERROR {ex.GetType().Name}: {ex.Message}\n{ex.StackTrace}");
        MessageBox.Show($"{ex.GetType().Name}: {ex.Message}", "Crash");
    }
}

    private async void Activate_Click(object sender, RoutedEventArgs e)
    {
        var key = LicenseKeyBox.Text.Trim();
        if (string.IsNullOrEmpty(key)) return;

        SetStatus("正在激活…", "#e0e060", "#2a2a1a", "#4a4a2a");
        _license ??= BuildManager();
        var result = await _license.ActivateAsync(key);

        if (result.Success)
            SetStatus($"✓ 激活成功  |  有效期至: {result.ExpiresAt ?? "永久"}", "#6fcf6f", "#1a2a1a", "#2a4a2a");
        else
            SetStatus($"✗ 激活失败: {result.Error}", "#cf6f6f", "#2a1a1a", "#4a2a2a");
    }

    private async void Verify_Click(object sender, RoutedEventArgs e) => await RunVerify();

    private async void Deactivate_Click(object sender, RoutedEventArgs e)
    {
        SetStatus("正在解绑…", "#e0e060", "#2a2a1a", "#4a4a2a");
        _license ??= BuildManager();
        var ok = await _license.DeactivateAsync();
        SetStatus(ok ? "✓ 已解绑，本设备激活名额已释放" : "✗ 解绑失败（此设备可能未激活）",
            ok ? "#6fcf6f" : "#cf6f6f",
            ok ? "#1a2a1a" : "#2a1a1a",
            ok ? "#2a4a2a" : "#4a2a2a");
    }

    private async Task RunVerify()
    {
        SetStatus("正在验证许可证…", "#e0e060", "#2a2a1a", "#4a4a2a");
        _license ??= BuildManager();
        var result = await _license.VerifyAsync();

        if (result.Valid)
        {
            var offline = result.IsOffline ? " [离线宽限期]" : "";
            SetStatus($"✓ 许可证有效{offline}  |  有效期至: {result.ExpiresAt ?? "永久"}", "#6fcf6f", "#1a2a1a", "#2a4a2a");
        }
        else
        {
            SetStatus($"✗ {result.Error ?? "许可证无效"}", "#cf6f6f", "#2a1a1a", "#4a2a2a");
        }
    }

    private void SetStatus(string text, string fg, string bg, string border)
    {
        StatusText.Text = text;
        StatusText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString(fg));
        StatusBorder.Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString(bg));
        StatusBorder.BorderBrush = new SolidColorBrush((Color)ColorConverter.ConvertFromString(border));
    }

    private static LicenseManager BuildManager() => new(new LicenseConfig
    {
        // Read from config/env in a real integration; hardcoded here for demo
        ServerUrl    = "http://localhost:3100",
        SharedSecret = KeyProtector.Reveal(),
        ProductId    = "11111111-1111-1111-1111-111111111111",
    });
}
