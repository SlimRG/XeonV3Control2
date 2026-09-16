using System.Runtime.InteropServices;

namespace XeonV3Control.App;

/// <summary>
/// Thin managed COM projection over the Windows shell file-open dialog.
/// This is UI-only interop: firmware parsing and mutation remain fully managed and never cross this boundary.
/// </summary>
internal static class SystemFileOpenDialog
{
    private const int ErrorCancelledHResult = unchecked((int)0x800704C7);
    private static readonly Guid FileOpenDialogClsid = new("DC1C5A9C-E88A-4DDE-A5A1-60F82A20AEF7");

    internal readonly record struct Filter(string Name, IReadOnlyList<string> Extensions);

    internal static string? PickSingleFile(nint ownerWindow, IReadOnlyList<Filter> filters)
    {
        if (ownerWindow == 0)
        {
            throw new ArgumentException("A valid owner window handle is required.", nameof(ownerWindow));
        }
        ArgumentNullException.ThrowIfNull(filters);
        if (filters.Count == 0)
        {
            throw new ArgumentException("At least one file filter is required.", nameof(filters));
        }

        Type dialogType = Type.GetTypeFromCLSID(FileOpenDialogClsid, throwOnError: true)
            ?? throw new InvalidOperationException("Windows file-open dialog is unavailable.");
        object dialogObject = Activator.CreateInstance(dialogType)
            ?? throw new InvalidOperationException("Windows file-open dialog could not be created.");

        try
        {
            var dialog = (IFileDialog)dialogObject;
            FileTypeSpec[] specs = filters.Select(ToFileTypeSpec).ToArray();
            dialog.SetFileTypes(checked((uint)specs.Length), specs);
            dialog.SetFileTypeIndex(1);
            dialog.GetOptions(out FileOpenOptions currentOptions);
            dialog.SetOptions(
                currentOptions |
                FileOpenOptions.ForceFileSystem |
                FileOpenOptions.FileMustExist |
                FileOpenOptions.PathMustExist |
                FileOpenOptions.NoChangeDirectory);

            int showResult = dialog.Show(ownerWindow);
            if (showResult == ErrorCancelledHResult)
            {
                return null;
            }
            Marshal.ThrowExceptionForHR(showResult);

            dialog.GetResult(out IShellItem item);
            try
            {
                item.GetDisplayName(ShellItemDisplayName.FileSystemPath, out nint pathPointer);
                try
                {
                    return Marshal.PtrToStringUni(pathPointer)
                        ?? throw new InvalidDataException("The selected file does not have a filesystem path.");
                }
                finally
                {
                    Marshal.FreeCoTaskMem(pathPointer);
                }
            }
            finally
            {
                ReleaseComObject(item);
            }
        }
        finally
        {
            ReleaseComObject(dialogObject);
        }
    }

    private static FileTypeSpec ToFileTypeSpec(Filter filter)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filter.Name);
        ArgumentNullException.ThrowIfNull(filter.Extensions);
        if (filter.Extensions.Count == 0)
        {
            throw new ArgumentException("A file filter must contain at least one extension.", nameof(filter));
        }

        string[] patterns = new string[filter.Extensions.Count];
        for (int index = 0; index < filter.Extensions.Count; index++)
        {
            string extension = filter.Extensions[index];
            if (string.IsNullOrWhiteSpace(extension) ||
                extension[0] != '.' ||
                extension.IndexOfAny(['*', '?', ';', '\\', '/']) >= 0)
            {
                throw new ArgumentException($"Invalid file extension filter: '{extension}'.", nameof(filter));
            }
            patterns[index] = "*" + extension;
        }

        return new FileTypeSpec(filter.Name, string.Join(';', patterns));
    }

    private static void ReleaseComObject(object value)
    {
        if (Marshal.IsComObject(value))
        {
            _ = Marshal.FinalReleaseComObject(value);
        }
    }

    [Flags]
    private enum FileOpenOptions : uint
    {
        NoChangeDirectory = 0x00000008,
        ForceFileSystem = 0x00000040,
        FileMustExist = 0x00001000,
        PathMustExist = 0x00000800
    }

    private enum ShellItemDisplayName : uint
    {
        FileSystemPath = 0x80058000
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct FileTypeSpec
    {
        internal FileTypeSpec(string name, string pattern)
        {
            Name = name;
            Pattern = pattern;
        }

        [MarshalAs(UnmanagedType.LPWStr)]
        internal string Name;

        [MarshalAs(UnmanagedType.LPWStr)]
        internal string Pattern;
    }

    [ComImport]
    [Guid("42F85136-DB7E-439C-85F1-E4075D135FC8")]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IFileDialog
    {
        [PreserveSig]
        int Show(nint parent);

        void SetFileTypes(uint count, [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 0)] FileTypeSpec[] filters);
        void SetFileTypeIndex(uint index);
        void GetFileTypeIndex(out uint index);
        void Advise(nint events, out uint cookie);
        void Unadvise(uint cookie);
        void SetOptions(FileOpenOptions options);
        void GetOptions(out FileOpenOptions options);
        void SetDefaultFolder(nint shellItem);
        void SetFolder(nint shellItem);
        void GetFolder(out nint shellItem);
        void GetCurrentSelection(out nint shellItem);
        void SetFileName([MarshalAs(UnmanagedType.LPWStr)] string fileName);
        void GetFileName([MarshalAs(UnmanagedType.LPWStr)] out string fileName);
        void SetTitle([MarshalAs(UnmanagedType.LPWStr)] string title);
        void SetOkButtonLabel([MarshalAs(UnmanagedType.LPWStr)] string text);
        void SetFileNameLabel([MarshalAs(UnmanagedType.LPWStr)] string label);
        void GetResult(out IShellItem shellItem);
        void AddPlace(nint shellItem, uint placement);
        void SetDefaultExtension([MarshalAs(UnmanagedType.LPWStr)] string defaultExtension);
        void Close(int hresult);
        void SetClientGuid(in Guid guid);
        void ClearClientData();
        void SetFilter(nint filter);
    }

    [ComImport]
    [Guid("43826D1E-E718-42EE-BC55-A1E261C37BFE")]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IShellItem
    {
        void BindToHandler(nint bindContext, in Guid handlerId, in Guid interfaceId, out nint result);
        void GetParent(out IShellItem parent);
        void GetDisplayName(ShellItemDisplayName displayName, out nint name);
        void GetAttributes(uint requestedAttributes, out uint attributes);
        void Compare(IShellItem other, uint hint, out int order);
    }
}
