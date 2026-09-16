using System.Runtime.InteropServices;

namespace XeonV3Control.App;

internal static class SystemFileSaveDialog
{
    private const int ErrorCancelledHResult = unchecked((int)0x800704C7);
    private static readonly Guid FileSaveDialogClsid = new("C0B4E2F3-BA21-4773-8DBA-335EC946EB8B");

    internal static string? PickFile(nint ownerWindow, string suggestedName, string filterName, string extension)
    {
        if (ownerWindow == 0) throw new ArgumentException(nameof(ownerWindow));
        if (string.IsNullOrWhiteSpace(suggestedName)) throw new ArgumentException(nameof(suggestedName));
        if (string.IsNullOrWhiteSpace(extension) || extension[0] != '.') throw new ArgumentException(nameof(extension));

        Type type = Type.GetTypeFromCLSID(FileSaveDialogClsid, throwOnError: true)
            ?? throw new InvalidOperationException("Windows file-save dialog is unavailable.");
        object instance = Activator.CreateInstance(type)
            ?? throw new InvalidOperationException("Windows file-save dialog could not be created.");
        try
        {
            var dialog = (IFileDialog)instance;
            FileTypeSpec[] specs = [new(filterName, "*" + extension)];
            dialog.SetFileTypes(1, specs);
            dialog.SetFileTypeIndex(1);
            dialog.GetOptions(out FileDialogOptions options);
            dialog.SetOptions(options | FileDialogOptions.ForceFileSystem | FileDialogOptions.PathMustExist |
                FileDialogOptions.NoChangeDirectory | FileDialogOptions.OverwritePrompt);
            dialog.SetFileName(suggestedName);
            dialog.SetDefaultExtension(extension[1..]);
            int result = dialog.Show(ownerWindow);
            if (result == ErrorCancelledHResult) return null;
            Marshal.ThrowExceptionForHR(result);
            dialog.GetResult(out IShellItem item);
            try
            {
                item.GetDisplayName(ShellItemDisplayName.FileSystemPath, out nint pointer);
                try { return Marshal.PtrToStringUni(pointer); }
                finally { Marshal.FreeCoTaskMem(pointer); }
            }
            finally { Release(item); }
        }
        finally { Release(instance); }
    }

    private static void Release(object value)
    {
        if (Marshal.IsComObject(value)) _ = Marshal.FinalReleaseComObject(value);
    }

    [Flags]
    private enum FileDialogOptions : uint
    {
        NoChangeDirectory = 0x00000008,
        ForceFileSystem = 0x00000040,
        PathMustExist = 0x00000800,
        OverwritePrompt = 0x00000002
    }

    private enum ShellItemDisplayName : uint { FileSystemPath = 0x80058000 }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct FileTypeSpec
    {
        internal FileTypeSpec(string name, string pattern)
        {
            Name = name;
            Pattern = pattern;
        }

        [MarshalAs(UnmanagedType.LPWStr)] internal string Name;
        [MarshalAs(UnmanagedType.LPWStr)] internal string Pattern;
    }

    [ComImport, Guid("42F85136-DB7E-439C-85F1-E4075D135FC8"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IFileDialog
    {
        [PreserveSig] int Show(nint parent);
        void SetFileTypes(uint count, [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 0)] FileTypeSpec[] filters);
        void SetFileTypeIndex(uint index); void GetFileTypeIndex(out uint index); void Advise(nint events, out uint cookie);
        void Unadvise(uint cookie); void SetOptions(FileDialogOptions options); void GetOptions(out FileDialogOptions options);
        void SetDefaultFolder(nint shellItem); void SetFolder(nint shellItem); void GetFolder(out nint shellItem);
        void GetCurrentSelection(out nint shellItem); void SetFileName([MarshalAs(UnmanagedType.LPWStr)] string fileName);
        void GetFileName([MarshalAs(UnmanagedType.LPWStr)] out string fileName); void SetTitle([MarshalAs(UnmanagedType.LPWStr)] string title);
        void SetOkButtonLabel([MarshalAs(UnmanagedType.LPWStr)] string text); void SetFileNameLabel([MarshalAs(UnmanagedType.LPWStr)] string label);
        void GetResult(out IShellItem shellItem); void AddPlace(nint shellItem, uint placement);
        void SetDefaultExtension([MarshalAs(UnmanagedType.LPWStr)] string defaultExtension); void Close(int hresult);
        void SetClientGuid(in Guid guid); void ClearClientData(); void SetFilter(nint filter);
    }

    [ComImport, Guid("43826D1E-E718-42EE-BC55-A1E261C37BFE"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IShellItem
    {
        void BindToHandler(nint bindContext, in Guid handlerId, in Guid interfaceId, out nint result);
        void GetParent(out IShellItem parent); void GetDisplayName(ShellItemDisplayName displayName, out nint name);
        void GetAttributes(uint requestedAttributes, out uint attributes); void Compare(IShellItem other, uint hint, out int order);
    }
}
