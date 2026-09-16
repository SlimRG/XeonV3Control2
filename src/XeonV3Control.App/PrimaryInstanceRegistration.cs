using Microsoft.Windows.AppLifecycle;

namespace XeonV3Control.App;

/// <summary>Holds the primary AppInstance registration and buffers redirected activations until the window is ready.</summary>
internal sealed class PrimaryInstanceRegistration : IDisposable
{
    private readonly AppInstance instance;
    private Action? activationHandler;
    private int pendingActivation;
    private int disposed;

    internal PrimaryInstanceRegistration(AppInstance instance)
    {
        this.instance = instance ?? throw new ArgumentNullException(nameof(instance));
        this.instance.Activated += OnActivated;
    }

    internal void Attach(Action handler)
    {
        ArgumentNullException.ThrowIfNull(handler);
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
        if (Interlocked.CompareExchange(ref activationHandler, handler, null) is not null)
        {
            throw new InvalidOperationException("The primary-instance activation handler is already attached.");
        }

        if (Interlocked.Exchange(ref pendingActivation, 0) != 0)
        {
            handler();
        }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0)
        {
            return;
        }
        instance.Activated -= OnActivated;
        Interlocked.Exchange(ref activationHandler, null);
        Interlocked.Exchange(ref pendingActivation, 0);
    }

    private void OnActivated(object? sender, AppActivationArguments activation)
    {
        _ = sender;
        _ = activation;
        if (Volatile.Read(ref disposed) != 0)
        {
            return;
        }

        Action? handler = Volatile.Read(ref activationHandler);
        if (handler is not null)
        {
            handler();
            return;
        }

        Interlocked.Exchange(ref pendingActivation, 1);
        handler = Volatile.Read(ref activationHandler);
        if (handler is not null && Interlocked.Exchange(ref pendingActivation, 0) != 0)
        {
            handler();
        }
    }
}
