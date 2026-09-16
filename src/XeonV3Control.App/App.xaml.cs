using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;

namespace XeonV3Control.App;

public partial class App : Application
{
    private MainWindow? window;
    private readonly PrimaryInstanceRegistration appInstance;
    private SessionLifetime? session;
    private DispatcherQueue? uiDispatcher;
    private int redirectedActivationPending;
    private int released;

    internal App(PrimaryInstanceRegistration appInstance)
    {
        this.appInstance = appInstance ?? throw new ArgumentNullException(nameof(appInstance));
        InitializeComponent();
        UnhandledException += OnUiUnhandledException;
        AppDomain.CurrentDomain.UnhandledException += OnDomainUnhandledException;
        TaskScheduler.UnobservedTaskException += OnUnobservedTaskException;
        AppDomain.CurrentDomain.ProcessExit += (_, _) => ReleaseResources();
    }

    protected override void OnLaunched(LaunchActivatedEventArgs _)
    {
        try
        {
            session = new SessionLifetime();
            AppLog.Configure(session.LogPath, session.CrashFallbackPath);

            ApplicationLaunchRequest launch = ApplicationLaunchRequest.Parse(Environment.GetCommandLineArgs());
            if (launch.UiSmoke is UiSmokeRequest smoke)
            {
                window = new MainWindow(smoke.Culture, session, ReleaseResources, smoke.OutputDirectory, smoke.ImagePath);
            }
            else
            {
                window = new MainWindow(null, session, ReleaseResources, startupImage: launch.ImagePath);
            }

            window.Activate();
            uiDispatcher = window.DispatcherQueue;
            appInstance.Attach(OnRedirectedActivation);
        }
        catch (Exception error)
        {
            AppLog.Error(error);
            AppLog.Crash(error, "Application startup");
            ReleaseResources();
            throw;
        }
    }

    private void OnUiUnhandledException(object sender, Microsoft.UI.Xaml.UnhandledExceptionEventArgs e)
    {
        _ = sender;
        AppLog.Error(e.Exception);
        AppLog.Crash(e.Exception, "WinUI unhandled exception");
        ReleaseResources();
    }

    private static void OnUnobservedTaskException(object? sender, UnobservedTaskExceptionEventArgs e)
    {
        _ = sender;
        AppLog.Error(e.Exception);
    }

    private static void OnDomainUnhandledException(object? sender, System.UnhandledExceptionEventArgs e)
    {
        _ = sender;
        if (e.ExceptionObject is Exception error)
        {
            AppLog.Crash(error, "AppDomain unhandled exception");
        }
        else
        {
            AppLog.Crash(new InvalidOperationException("A non-Exception object reached the AppDomain unhandled-exception boundary."),
                "AppDomain unhandled exception");
        }
    }

    private void OnRedirectedActivation()
    {
        if (Volatile.Read(ref released) != 0)
        {
            return;
        }
        Interlocked.Exchange(ref redirectedActivationPending, 1);
        DispatcherQueue? dispatcher = Volatile.Read(ref uiDispatcher);
        if (dispatcher is null)
        {
            return;
        }

        _ = dispatcher.TryEnqueue(DispatcherQueuePriority.Normal, ProcessPendingRedirectedActivation);
    }

    private void ProcessPendingRedirectedActivation()
    {
        if (Interlocked.Exchange(ref redirectedActivationPending, 0) == 0 || window is null)
        {
            return;
        }
        _ = ShowAlreadyRunningAsync(window);
    }

    private static async Task ShowAlreadyRunningAsync(MainWindow currentWindow)
    {
        try
        {
            await currentWindow.NotifyAlreadyRunningAsync();
        }
        catch (Exception error)
        {
            AppLog.Error(error);
        }
    }

    private void ReleaseResources()
    {
        if (Interlocked.Exchange(ref released, 1) != 0)
        {
            return;
        }

        Volatile.Write(ref uiDispatcher, null);
        try
        {
            appInstance.Dispose();
        }
        catch (Exception error)
        {
            AppLog.Error(error);
        }

        SessionLifetime? currentSession = Interlocked.Exchange(ref session, null);
        if (currentSession is null)
        {
            return;
        }
        try
        {
            currentSession.Dispose();
        }
        catch (Exception error)
        {
            AppLog.Error(error);
        }
    }
}
