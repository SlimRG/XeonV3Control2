using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

namespace XeonV3Control.App;

/// <summary>
/// Enables shell file drops from a lower-integrity Explorer into this elevated window.
/// Only the two messages required by the legacy shell-drop path are admitted through UIPI.
/// </summary>
internal sealed class ElevatedFileDropTarget : IDisposable
{
    private const uint WmDropFiles = 0x0233;
    private const uint WmCopyGlobalData = 0x0049;
    private const uint MsgfltAllow = 1;
    private const uint QueryFileCount = uint.MaxValue;
    private const nuint SubclassId = 0x58454F4E; // "XEON"

    private readonly nint hwnd;
    private readonly Func<int, int, bool> acceptsPoint;
    private readonly Action<IReadOnlyList<string>> onFilesDropped;
    private readonly Native.SubclassProc subclassProc;
    private bool installed;
    private bool acceptingFiles;

    public ElevatedFileDropTarget(
        nint hwnd,
        Func<int, int, bool> acceptsPoint,
        Action<IReadOnlyList<string>> onFilesDropped)
    {
        if (hwnd == 0)
        {
            throw new ArgumentException("A valid window handle is required.", nameof(hwnd));
        }
        this.hwnd = hwnd;
        this.acceptsPoint = acceptsPoint ?? throw new ArgumentNullException(nameof(acceptsPoint));
        this.onFilesDropped = onFilesDropped ?? throw new ArgumentNullException(nameof(onFilesDropped));
        subclassProc = WindowSubclassProc;

        AllowMessage(WmDropFiles);
        AllowMessage(WmCopyGlobalData);

        if (!Native.SetWindowSubclass(hwnd, subclassProc, SubclassId, 0))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to install the shell file-drop window subclass.");
        }

        installed = true;
        SetEnabled(false);
    }

    public void SetEnabled(bool enabled)
    {
        if (!installed || acceptingFiles == enabled)
        {
            return;
        }
        Native.DragAcceptFiles(hwnd, enabled);
        acceptingFiles = enabled;
    }

    public void Dispose()
    {
        if (!installed)
        {
            return;
        }

        if (acceptingFiles)
        {
            Native.DragAcceptFiles(hwnd, false);
            acceptingFiles = false;
        }
        if (!Native.RemoveWindowSubclass(hwnd, subclassProc, SubclassId))
        {
            int error = Marshal.GetLastWin32Error();
            if (error != 0)
            {
                AppLog.Error(new Win32Exception(error, "Unable to remove the shell file-drop window subclass."));
            }
        }

        installed = false;
    }

    private void AllowMessage(uint message)
    {
        if (!Native.ChangeWindowMessageFilterEx(hwnd, message, MsgfltAllow, 0))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), $"Unable to allow window message 0x{message:X4} for shell file drop.");
        }
    }

    private nint WindowSubclassProc(nint window, uint message, nuint wParam, nint lParam, nuint subclassId, nuint refData)
    {
        _ = subclassId;
        _ = refData;

        if (message == WmDropFiles)
        {
            nint dropHandle = (nint)wParam;
            if (acceptingFiles && IsAcceptedDropPoint(dropHandle))
            {
                HandleDrop(dropHandle);
            }
            else
            {
                Native.DragFinish(dropHandle);
            }
            return 0;
        }

        return Native.DefSubclassProc(window, message, wParam, lParam);
    }

    private bool IsAcceptedDropPoint(nint dropHandle)
    {
        try
        {
            if (!Native.DragQueryPoint(dropHandle, out Native.Point point))
            {
                return false;
            }

            return acceptsPoint(point.X, point.Y);
        }
        catch (Exception error)
        {
            AppLog.Error(error);
            return false;
        }
    }

    private void HandleDrop(nint dropHandle)
    {
        try
        {
            uint count = Native.DragQueryFile(dropHandle, QueryFileCount, null, 0);
            if (count != 1)
            {
                onFilesDropped([]);
                return;
            }

            uint length = Native.DragQueryFile(dropHandle, 0, null, 0);
            if (length == 0)
            {
                onFilesDropped([]);
                return;
            }

            var buffer = new StringBuilder(checked((int)length + 1));
            IReadOnlyList<string> paths = Native.DragQueryFile(dropHandle, 0, buffer, (uint)buffer.Capacity) > 0
                ? [buffer.ToString()]
                : [];
            onFilesDropped(paths);
        }
        catch (Exception error)
        {
            AppLog.Error(error);
        }
        finally
        {
            Native.DragFinish(dropHandle);
        }
    }

    private static class Native
    {
        [StructLayout(LayoutKind.Sequential)]
        internal struct Point
        {
            internal int X;
            internal int Y;
        }

        internal delegate nint SubclassProc(
            nint window,
            uint message,
            nuint wParam,
            nint lParam,
            nuint subclassId,
            nuint refData);

        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool ChangeWindowMessageFilterEx(nint window, uint message, uint action, nint changeFilterStruct);

        [DllImport("shell32.dll")]
        internal static extern void DragAcceptFiles(nint window, [MarshalAs(UnmanagedType.Bool)] bool accept);

        [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
        internal static extern uint DragQueryFile(nint dropHandle, uint fileIndex, StringBuilder? fileName, uint fileNameSize);

        [DllImport("shell32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool DragQueryPoint(nint dropHandle, out Point point);

        [DllImport("shell32.dll")]
        internal static extern void DragFinish(nint dropHandle);

        [DllImport("comctl32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool SetWindowSubclass(nint window, SubclassProc subclassProc, nuint subclassId, nuint refData);

        [DllImport("comctl32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool RemoveWindowSubclass(nint window, SubclassProc subclassProc, nuint subclassId);

        [DllImport("comctl32.dll")]
        internal static extern nint DefSubclassProc(nint window, uint message, nuint wParam, nint lParam);
    }
}
