using System.Runtime.InteropServices;

namespace XeonV3Control.App;

internal static class ForegroundActivationInterop
{
    private const int ShowWindowRestore = 9;

    internal static void AllowProcess(uint processId)
    {
        if (processId == 0)
        {
            return;
        }
        _ = Native.AllowSetForegroundWindow(processId);
    }

    internal static void RestoreAndRequestForeground(nint window)
    {
        if (window == 0)
        {
            return;
        }
        _ = Native.ShowWindow(window, ShowWindowRestore);
        _ = Native.SetForegroundWindow(window);
    }

    private static class Native
    {
        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool AllowSetForegroundWindow(uint processId);

        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool ShowWindow(nint window, int command);

        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool SetForegroundWindow(nint window);
    }
}
