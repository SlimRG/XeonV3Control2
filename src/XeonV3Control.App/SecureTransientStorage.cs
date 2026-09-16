using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;
using XeonV3Control.Core;

namespace XeonV3Control.App;

/// <summary>
/// Creates and pins the elevated application's transient storage below ProgramData.
/// Directories are created with a protected DACL atomically and are kept open without
/// FILE_SHARE_DELETE while in use so their path cannot be replaced by an unprivileged process.
/// </summary>
internal static class SecureTransientStorage
{
    private static readonly SecurityIdentifier AdministratorsSid =
        new(WellKnownSidType.BuiltinAdministratorsSid, domainSid: null);
    private static readonly SecurityIdentifier LocalSystemSid =
        new(WellKnownSidType.LocalSystemSid, domainSid: null);

    internal static SecureDirectoryLease AcquireRoot()
    {
        string commonData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        if (string.IsNullOrWhiteSpace(commonData))
        {
            throw new SecurityException(OperationError.TemporaryStorage);
        }

        string root = Path.Combine(commonData, ApplicationIdentity.TransientRootDirectoryName);
        return CreateOrOpenProtectedDirectory(root);
    }

    internal static SecureDirectoryLease CreateSessionDirectory(string rootPath, string directoryName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(rootPath);
        ArgumentException.ThrowIfNullOrWhiteSpace(directoryName);
        if (!string.Equals(directoryName, Path.GetFileName(directoryName), StringComparison.Ordinal) ||
            directoryName.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
        {
            throw new ArgumentException("Session directory name must be a single valid path component.", nameof(directoryName));
        }

        return CreateOrOpenProtectedDirectory(Path.Combine(rootPath, directoryName));
    }

    internal static string? TryGetCrashFallbackPath()
    {
        try
        {
            using SecureDirectoryLease root = AcquireRoot();
            return Path.Combine(root.Path, ApplicationIdentity.CrashReportFileName);
        }
        catch (Exception error) when (IsExpectedStorageFailure(error))
        {
            return null;
        }
    }

    internal static bool TryDeleteRootIfEmpty(string rootPath)
    {
        try
        {
            var info = new DirectoryInfo(rootPath);
            if (!info.Exists)
            {
                return true;
            }
            info.Refresh();
            if ((info.Attributes & FileAttributes.ReparsePoint) != 0 || info.EnumerateFileSystemInfos().Any())
            {
                return false;
            }
            info.Delete();
            return true;
        }
        catch (DirectoryNotFoundException)
        {
            return true;
        }
        catch (Exception error) when (IsExpectedStorageFailure(error))
        {
            return false;
        }
    }

    private static SecureDirectoryLease CreateOrOpenProtectedDirectory(string path)
    {
        try
        {
            DirectorySecurity expectedSecurity = CreateDirectorySecurity();
            _ = System.IO.FileSystemAclExtensions.CreateDirectory(expectedSecurity, path);

            SafeFileHandle handle = OpenDirectoryNoFollow(path);
            try
            {
                EnsureNotReparsePoint(handle);
                EnsureExpectedSecurity(path);
                return new SecureDirectoryLease(path, handle);
            }
            catch
            {
                handle.Dispose();
                throw;
            }
        }
        catch (Exception error) when (IsExpectedStorageFailure(error))
        {
            throw new SecurityException(OperationError.TemporaryStorage, error);
        }
    }

    private static DirectorySecurity CreateDirectorySecurity()
    {
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        const InheritanceFlags inheritance = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        security.AddAccessRule(new FileSystemAccessRule(
            AdministratorsSid,
            FileSystemRights.FullControl,
            inheritance,
            PropagationFlags.None,
            AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(
            LocalSystemSid,
            FileSystemRights.FullControl,
            inheritance,
            PropagationFlags.None,
            AccessControlType.Allow));
        return security;
    }

    private static void EnsureExpectedSecurity(string path)
    {
        var security = new DirectorySecurity(path, AccessControlSections.Access | AccessControlSections.Owner);
        if (!security.AreAccessRulesProtected)
        {
            throw new SecurityException(OperationError.TemporaryStorage);
        }

        SecurityIdentifier? owner = security.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
        SecurityIdentifier? currentUser = WindowsIdentity.GetCurrent().User;
        if (owner is null ||
            (!owner.Equals(AdministratorsSid) && !owner.Equals(LocalSystemSid) &&
             (currentUser is null || !owner.Equals(currentUser))))
        {
            throw new SecurityException(OperationError.TemporaryStorage);
        }

        var administrators = new AccessCoverage();
        var system = new AccessCoverage();
        foreach (FileSystemAccessRule rule in security.GetAccessRules(
                     includeExplicit: true,
                     includeInherited: false,
                     targetType: typeof(SecurityIdentifier)))
        {
            if (rule.IdentityReference is not SecurityIdentifier sid ||
                rule.AccessControlType != AccessControlType.Allow ||
                (rule.FileSystemRights & FileSystemRights.FullControl) != FileSystemRights.FullControl ||
                (rule.PropagationFlags & PropagationFlags.NoPropagateInherit) != 0)
            {
                throw new SecurityException(OperationError.TemporaryStorage);
            }

            AccessCoverage coverage;
            if (sid.Equals(AdministratorsSid))
            {
                coverage = administrators;
            }
            else if (sid.Equals(LocalSystemSid))
            {
                coverage = system;
            }
            else
            {
                throw new SecurityException(OperationError.TemporaryStorage);
            }
            coverage.Add(rule);
        }

        if (!administrators.IsComplete || !system.IsComplete)
        {
            throw new SecurityException(OperationError.TemporaryStorage);
        }
    }

    private sealed class AccessCoverage
    {
        private bool appliesToDirectory;
        private bool containerInheritance;
        private bool objectInheritance;

        internal bool IsComplete => appliesToDirectory && containerInheritance && objectInheritance;

        internal void Add(FileSystemAccessRule rule)
        {
            if ((rule.PropagationFlags & PropagationFlags.InheritOnly) == 0)
            {
                appliesToDirectory = true;
            }
            if ((rule.InheritanceFlags & InheritanceFlags.ContainerInherit) != 0)
            {
                containerInheritance = true;
            }
            if ((rule.InheritanceFlags & InheritanceFlags.ObjectInherit) != 0)
            {
                objectInheritance = true;
            }
        }
    }

    private static SafeFileHandle OpenDirectoryNoFollow(string path)
    {
        SafeFileHandle handle = Native.CreateFile(
            path,
            Native.FileReadAttributes,
            Native.FileShareRead | Native.FileShareWrite,
            0,
            Native.OpenExisting,
            Native.FileFlagBackupSemantics | Native.FileFlagOpenReparsePoint,
            0);
        if (handle.IsInvalid)
        {
            int error = Marshal.GetLastWin32Error();
            handle.Dispose();
            throw new Win32Exception(error);
        }
        return handle;
    }

    private static void EnsureNotReparsePoint(SafeFileHandle handle)
    {
        if (!Native.GetFileInformationByHandleEx(
                handle,
                Native.FileAttributeTagInfo,
                out Native.FileAttributeTagInformation information,
                (uint)Marshal.SizeOf<Native.FileAttributeTagInformation>()))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        if ((information.FileAttributes & (uint)FileAttributes.ReparsePoint) != 0)
        {
            throw new SecurityException(OperationError.TemporaryStorage);
        }
    }

    private static bool IsExpectedStorageFailure(Exception error) =>
        error is IOException or UnauthorizedAccessException or SecurityException or Win32Exception or
        ArgumentException or NotSupportedException;

    internal sealed class SecureDirectoryLease(string path, SafeFileHandle directoryHandle) : IDisposable
    {
        private SafeFileHandle? handle = directoryHandle;
        internal string Path { get; } = System.IO.Path.GetFullPath(path);

        public void Dispose() => Interlocked.Exchange(ref handle, null)?.Dispose();
    }

    private static class Native
    {
        internal const uint FileReadAttributes = 0x00000080;
        internal const uint FileShareRead = 0x00000001;
        internal const uint FileShareWrite = 0x00000002;
        internal const uint OpenExisting = 3;
        internal const uint FileFlagOpenReparsePoint = 0x00200000;
        internal const uint FileFlagBackupSemantics = 0x02000000;
        internal const int FileAttributeTagInfo = 9;

        [StructLayout(LayoutKind.Sequential)]
        internal struct FileAttributeTagInformation
        {
            internal uint FileAttributes;
            internal uint ReparseTag;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern SafeFileHandle CreateFile(
            string fileName,
            uint desiredAccess,
            uint shareMode,
            nint securityAttributes,
            uint creationDisposition,
            uint flagsAndAttributes,
            nint templateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool GetFileInformationByHandleEx(
            SafeFileHandle file,
            int informationClass,
            out FileAttributeTagInformation information,
            uint bufferSize);
    }
}
