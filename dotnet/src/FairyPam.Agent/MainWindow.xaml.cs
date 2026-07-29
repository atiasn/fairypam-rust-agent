using System.ComponentModel;
using System.IO;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Windows;
using FairyPam.Agent.Core;

namespace FairyPam.Agent;

public partial class MainWindow : Window
{
    private readonly LocalRuntime runtime;
    private bool allowClose;

    internal MainWindow(LocalRuntime runtime)
    {
        this.runtime = runtime;
        InitializeComponent();
        ApplyStatus(runtime.Status);
        runtime.StatusChanged += RuntimeStatusChanged;
    }

    internal void ShowFromTray()
    {
        Show();
        WindowState = WindowState.Normal;
        Activate();
    }

    internal void AllowClose() => allowClose = true;

    protected override void OnClosing(CancelEventArgs error)
    {
        if (!allowClose)
        {
            error.Cancel = true;
            Hide();
        }
        else
        {
            runtime.StatusChanged -= RuntimeStatusChanged;
        }
        base.OnClosing(error);
    }

    private async void Register_Click(object sender, RoutedEventArgs eventArgs)
    {
        using SecureString secureCode = EnrollmentCodeBox.SecurePassword;
        EnrollmentCodeBox.Clear();
        char[] code = CopyCode(secureCode);
        try
        {
            RegisterButton.IsEnabled = false;
            await runtime.RegisterAsync(code, CancellationToken.None);
        }
        catch (Exception error) when (error is InvalidOperationException
            or HttpRequestException
            or CryptographicException
            or IOException
            or UnauthorizedAccessException
            or AgentContractException)
        {
            System.Windows.MessageBox.Show(
                "注册未完成。注册码可能无效或 Hub 暂时不可用。",
                "FairyPam Agent",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
        }
        finally
        {
            Array.Clear(code);
            RegisterButton.IsEnabled = true;
        }
    }

    private static char[] CopyCode(SecureString secureCode)
    {
        char[] code = new char[secureCode.Length];
        IntPtr plaintext = IntPtr.Zero;
        try
        {
            plaintext = Marshal.SecureStringToGlobalAllocUnicode(secureCode);
            for (int index = 0; index < code.Length; index++)
            {
                code[index] = (char)Marshal.ReadInt16(plaintext, index * sizeof(char));
            }
            return code;
        }
        catch
        {
            Array.Clear(code);
            throw;
        }
        finally
        {
            if (plaintext != IntPtr.Zero)
            {
                Marshal.ZeroFreeGlobalAllocUnicode(plaintext);
            }
        }
    }

    private async void Rescan_Click(object sender, RoutedEventArgs eventArgs)
    {
        RescanButton.IsEnabled = false;
        try
        {
            await runtime.RescanAsync(CancellationToken.None);
        }
        catch (InvalidOperationException)
        {
            System.Windows.MessageBox.Show(
                "请先完成设备注册，再重新扫描游戏。",
                "FairyPam Agent",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
        }
        finally
        {
            RescanButton.IsEnabled = true;
        }
    }

    private void RuntimeStatusChanged(LocalRuntimeStatus status) =>
        Dispatcher.Invoke(() => ApplyStatus(status));

    private void ApplyStatus(LocalRuntimeStatus status)
    {
        DeviceStatusText.Text = status.DeviceStatus;
        ControlStatusText.Text = status.ControlStatus;
        FrameStatusText.Text = status.FrameStatus;
        SafetyStatusText.Text = status.SafetyStatus;
        RegisterButton.IsEnabled = !status.RecoveryBlocked;
        RescanButton.IsEnabled = !status.RecoveryBlocked && status.DeviceStatus == "已注册";
    }
}
