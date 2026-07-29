using System.Drawing;
using System.Windows;
using Forms = System.Windows.Forms;

namespace FairyPam.Agent;

public partial class App : System.Windows.Application
{
    private SingleInstance? singleInstance;
    private Forms.NotifyIcon? trayIcon;
    private MainWindow? window;
    private LocalRuntime? runtime;
    private bool shuttingDown;

    protected override void OnStartup(StartupEventArgs eventArgs)
    {
        base.OnStartup(eventArgs);
        ShutdownMode = ShutdownMode.OnExplicitShutdown;
        if (!SingleInstance.TryAcquire(out singleInstance))
        {
            Shutdown();
            return;
        }

        runtime = LocalRuntime.Initialize();
        window = new(runtime);
        window.Show();
        CreateTrayIcon();
        _ = runtime.StartAsync();
    }

    protected override void OnExit(ExitEventArgs eventArgs)
    {
        trayIcon?.Dispose();
        singleInstance?.Dispose();
        base.OnExit(eventArgs);
    }

    private void CreateTrayIcon()
    {
        Forms.ContextMenuStrip menu = new();
        menu.Items.Add("打开", null, (_, _) => Dispatcher.Invoke(ShowWindow));
        menu.Items.Add("退出", null, async (_, _) => await RequestExitAsync());
        trayIcon = new()
        {
            ContextMenuStrip = menu,
            Icon = SystemIcons.Application,
            Text = "FairyPam Agent",
            Visible = true,
        };
        trayIcon.DoubleClick += (_, _) => Dispatcher.Invoke(ShowWindow);
    }

    private void ShowWindow() => window?.ShowFromTray();

    private async Task RequestExitAsync()
    {
        if (shuttingDown || runtime is null || window is null)
        {
            return;
        }
        shuttingDown = true;
        if (!await runtime.TryShutdownAsync())
        {
            shuttingDown = false;
            System.Windows.MessageBox.Show(
                "安全清理尚未完成。请先完成本机恢复后再退出。",
                "FairyPam Agent",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
            return;
        }

        trayIcon!.Visible = false;
        window.AllowClose();
        window.Close();
        Shutdown();
    }
}
