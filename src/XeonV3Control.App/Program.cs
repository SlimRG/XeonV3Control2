using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using Microsoft.Windows.AppLifecycle;
using XeonV3Control.Core;

namespace XeonV3Control.App;

internal static class Program
{
    private const int BootstrapFailureExitCode = 1;

    [STAThread]
    private static void Main()
    {
        try
        {
            // WinUI's UI thread must be a real STA. An async Main can move the STAThread attribute
            // away from the generated process entry point, which breaks Clipboard/text-selection COM activation.
            if (Thread.CurrentThread.GetApartmentState() != ApartmentState.STA)
            {
                throw new InvalidOperationException(OperationError.StaApartmentRequired);
            }

            WinRT.ComWrappersSupport.InitializeComWrappers();

            AppActivationArguments activation = AppInstance.GetCurrent().GetActivatedEventArgs();
            AppInstance instance = AppInstance.FindOrRegisterForKey(ApplicationIdentity.MainInstanceKey);
            if (!instance.IsCurrent)
            {
                ForegroundActivationInterop.AllowProcess(instance.ProcessId);
                instance.RedirectActivationToAsync(activation).GetAwaiter().GetResult();
                return;
            }

            using var registration = new PrimaryInstanceRegistration(instance);
            Application.Start(initializationCallbackParams =>
            {
                _ = initializationCallbackParams;
                if (Thread.CurrentThread.GetApartmentState() != ApartmentState.STA)
                {
                    throw new InvalidOperationException(OperationError.StaApartmentRequired);
                }

                DispatcherQueue dispatcher = DispatcherQueue.GetForCurrentThread()
                    ?? throw new InvalidOperationException(OperationError.UiDispatcherUnavailable);
                SynchronizationContext.SetSynchronizationContext(new DispatcherQueueSynchronizationContext(dispatcher));
                _ = new App(registration);
            });
        }
        catch (Exception error)
        {
            AppLog.ConfigureCrashFallback(SecureTransientStorage.TryGetCrashFallbackPath());
            AppLog.Crash(error, "Application bootstrap");
            Environment.ExitCode = BootstrapFailureExitCode;
        }
    }
}
