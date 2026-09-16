using System.Security;
using XeonV3Control.Core;

namespace XeonV3Control.App;

internal enum TemporaryBiosArtifact
{
    SystemDump,
    SecureBootRepair,
    CpuPatchRemoval,
    ForeignUnlockRemoval,
    UefiDriverUpdate,
    PackageImport,
    LargeBootLogo,
    SmallAmiLogo,
    BeeperDisabled,
    BeeperEnabled,
    TpmDebugInstall,
    TpmDebugRemoval
}

public sealed class SessionLifetime : IDisposable
{
    private string directory = string.Empty;
    private SecureTransientStorage.SecureDirectoryLease? rootLease;
    private SecureTransientStorage.SecureDirectoryLease? sessionLease;
    private FileStream? lockFile;
    private int disposed;

    internal SessionLifetime()
    {
        try
        {
            rootLease = SecureTransientStorage.AcquireRoot();
            CleanupStaleSessions(rootLease.Path);

            string sessionName = ApplicationIdentity.TemporarySessionPrefix + Environment.ProcessId + "-" +
                Guid.NewGuid().ToString("N");
            sessionLease = SecureTransientStorage.CreateSessionDirectory(rootLease.Path, sessionName);
            directory = sessionLease.Path;

            string lockPath = Path.Combine(directory, ApplicationIdentity.TemporarySessionLockFileName);
            lockFile = new FileStream(lockPath, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None);
        }
        catch (Exception error) when (IsExpectedStorageFailure(error))
        {
            DisposeConstructionState();
            if (error is SecurityException { Message: OperationError.TemporaryStorage })
            {
                throw;
            }
            throw new SecurityException(OperationError.TemporaryStorage, error);
        }
    }

    internal string LogPath
    {
        get
        {
            ThrowIfDisposed();
            return Path.Combine(directory, ApplicationIdentity.TemporaryLogFileName);
        }
    }

    internal string WindowIconPath
    {
        get
        {
            ThrowIfDisposed();
            return Path.Combine(directory, ApplicationIdentity.TemporaryWindowIconFileName);
        }
    }

    internal string CrashFallbackPath
    {
        get
        {
            ThrowIfDisposed();
            SecureTransientStorage.SecureDirectoryLease? root = rootLease;
            if (root is null)
            {
                throw new ObjectDisposedException(nameof(SessionLifetime));
            }
            return Path.Combine(root.Path, ApplicationIdentity.CrashReportFileName);
        }
    }

    internal string NewBiosPath(TemporaryBiosArtifact artifact)
    {
        ThrowIfDisposed();
        string prefix = artifact switch
        {
            TemporaryBiosArtifact.SystemDump => ApplicationIdentity.SystemDumpArtifactPrefix,
            TemporaryBiosArtifact.SecureBootRepair => ApplicationIdentity.SecureBootRepairedArtifactPrefix,
            TemporaryBiosArtifact.CpuPatchRemoval => ApplicationIdentity.CpuPatchRemovedArtifactPrefix,
            TemporaryBiosArtifact.ForeignUnlockRemoval => ApplicationIdentity.ForeignUnlockRemovedArtifactPrefix,
            TemporaryBiosArtifact.UefiDriverUpdate => ApplicationIdentity.UefiDriverUpdatedArtifactPrefix,
            TemporaryBiosArtifact.PackageImport => ApplicationIdentity.PackageImportArtifactPrefix,
            TemporaryBiosArtifact.LargeBootLogo => ApplicationIdentity.LargeBootLogoArtifactPrefix,
            TemporaryBiosArtifact.SmallAmiLogo => ApplicationIdentity.SmallAmiLogoArtifactPrefix,
            TemporaryBiosArtifact.BeeperDisabled => ApplicationIdentity.BeeperDisabledArtifactPrefix,
            TemporaryBiosArtifact.BeeperEnabled => ApplicationIdentity.BeeperEnabledArtifactPrefix,
            TemporaryBiosArtifact.TpmDebugInstall => ApplicationIdentity.TpmDebugInstalledArtifactPrefix,
            TemporaryBiosArtifact.TpmDebugRemoval => ApplicationIdentity.TpmDebugRemovedArtifactPrefix,
            _ => throw new ArgumentOutOfRangeException(nameof(artifact))
        };
        return Path.Combine(directory,
            prefix + "-" + Guid.NewGuid().ToString("N") + ApplicationIdentity.TemporaryBiosExtension);
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0)
        {
            return;
        }

        DisposeLockFile();
        Interlocked.Exchange(ref sessionLease, null)?.Dispose();
        if (!string.IsNullOrEmpty(directory))
        {
            _ = TryDeleteSessionDirectory(directory);
        }

        SecureTransientStorage.SecureDirectoryLease? root = Interlocked.Exchange(ref rootLease, null);
        string? rootPath = root?.Path;
        root?.Dispose();
        if (rootPath is not null)
        {
            _ = SecureTransientStorage.TryDeleteRootIfEmpty(rootPath);
        }
    }

    private void DisposeConstructionState()
    {
        DisposeLockFile();
        sessionLease?.Dispose();
        sessionLease = null;
        if (!string.IsNullOrEmpty(directory))
        {
            _ = TryDeleteSessionDirectory(directory);
        }

        string? rootPath = rootLease?.Path;
        rootLease?.Dispose();
        rootLease = null;
        if (rootPath is not null)
        {
            _ = SecureTransientStorage.TryDeleteRootIfEmpty(rootPath);
        }
    }

    private void DisposeLockFile()
    {
        FileStream? currentLock = Interlocked.Exchange(ref lockFile, null);
        if (currentLock is null)
        {
            return;
        }
        try
        {
            currentLock.Dispose();
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            AppLog.Error(error);
        }
    }

    private static void CleanupStaleSessions(string root)
    {
        foreach (string stale in Directory.EnumerateDirectories(root, ApplicationIdentity.TemporarySessionPrefix + "*"))
        {
            if (!IsInactiveSession(stale))
            {
                continue;
            }
            _ = TryDeleteSessionDirectory(stale);
        }
    }

    private static bool IsInactiveSession(string path)
    {
        try
        {
            var info = new DirectoryInfo(path);
            info.Refresh();
            if (!info.Exists || (info.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                return false;
            }

            string lockPath = Path.Combine(path, ApplicationIdentity.TemporarySessionLockFileName);
            if (!File.Exists(lockPath))
            {
                return true;
            }
            if ((File.GetAttributes(lockPath) & FileAttributes.ReparsePoint) != 0)
            {
                return false;
            }

            using var probe = new FileStream(lockPath, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
            return true;
        }
        catch (DirectoryNotFoundException)
        {
            return false;
        }
        catch (FileNotFoundException)
        {
            return true;
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or SecurityException)
        {
            return false;
        }
    }

    private static bool TryDeleteSessionDirectory(string path)
    {
        try
        {
            var directoryInfo = new DirectoryInfo(path);
            if (!directoryInfo.Exists)
            {
                return true;
            }
            directoryInfo.Refresh();
            if ((directoryInfo.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                return false;
            }

            FileSystemInfo[] entries = directoryInfo.GetFileSystemInfos();
            if (entries.Any(entry => entry is DirectoryInfo ||
                                     (entry.Attributes & FileAttributes.ReparsePoint) != 0))
            {
                return false;
            }

            foreach (FileSystemInfo entry in entries)
            {
                File.Delete(entry.FullName);
            }
            directoryInfo.Delete();
            return true;
        }
        catch (DirectoryNotFoundException)
        {
            return true;
        }
        catch (FileNotFoundException)
        {
            return !Directory.Exists(path);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or SecurityException)
        {
            return false;
        }
    }

    private void ThrowIfDisposed() =>
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);

    private static bool IsExpectedStorageFailure(Exception error) =>
        error is IOException or UnauthorizedAccessException or SecurityException or ArgumentException or
        NotSupportedException or System.ComponentModel.Win32Exception;
}
