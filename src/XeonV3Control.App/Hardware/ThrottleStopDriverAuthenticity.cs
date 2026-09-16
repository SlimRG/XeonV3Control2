using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;
using XeonV3Control.Core;

namespace XeonV3Control.App.Hardware;

internal static class ThrottleStopDriverAuthenticity
{
    internal const string DriverResourceName = "ThrottleStop.driver";
    private const string IntegrityResourceName = "ThrottleStop.integrity.json";
    private static readonly Guid GenericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
    private static readonly Lazy<BinaryIntegrityManifest> ManifestValue = new(LoadManifest, LazyThreadSafetyMode.ExecutionAndPublication);

    internal static BinaryIntegrityManifest Manifest => ManifestValue.Value;

    internal static void VerifyBytes(ReadOnlySpan<byte> driver)
    {
        if (!CryptographicOperations.FixedTimeEquals(SHA256.HashData(driver), Manifest.GetSha256Bytes()))
        {
            throw new InvalidDataException(OperationError.DriverHash);
        }
    }

    internal static void VerifyLockedFile(FileStream driver, string path)
    {
        ArgumentNullException.ThrowIfNull(driver);
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        driver.Position = 0;
        byte[] onDiskHash = SHA256.HashData(driver);
        if (!CryptographicOperations.FixedTimeEquals(onDiskHash, Manifest.GetSha256Bytes()))
        {
            throw new InvalidDataException(OperationError.DriverHash);
        }

        driver.Position = 0;
        VerifyAuthenticode(driver.SafeFileHandle, Path.GetFullPath(path));
    }

    private static BinaryIntegrityManifest LoadManifest()
    {
        using Stream resource = typeof(ThrottleStopDriverAuthenticity).Assembly.GetManifestResourceStream(IntegrityResourceName)
            ?? throw new InvalidDataException(OperationError.IntegrityManifest);
        return BinaryIntegrityManifest.Load(resource);
    }

    private static void VerifyAuthenticode(SafeFileHandle fileHandle, string path)
    {
        ArgumentNullException.ThrowIfNull(fileHandle);
        if (fileHandle.IsInvalid || fileHandle.IsClosed)
        {
            throw new InvalidDataException(OperationError.DriverSignature);
        }

        nint pathPointer = Marshal.StringToCoTaskMemUni(path);
        nint fileInfoPointer = 0;
        bool handleReferenceAdded = false;
        try
        {
            fileHandle.DangerousAddRef(ref handleReferenceAdded);
            var fileInfo = new WinTrustFileInfo
            {
                Size = (uint)Marshal.SizeOf<WinTrustFileInfo>(),
                FilePath = pathPointer,
                FileHandle = fileHandle.DangerousGetHandle()
            };
            fileInfoPointer = Marshal.AllocCoTaskMem(Marshal.SizeOf<WinTrustFileInfo>());
            Marshal.StructureToPtr(fileInfo, fileInfoPointer, false);

            var data = new WinTrustData
            {
                Size = (uint)Marshal.SizeOf<WinTrustData>(),
                UiChoice = WinTrustDataUiChoice.None,
                RevocationChecks = WinTrustDataRevocationChecks.None,
                UnionChoice = WinTrustDataChoice.File,
                File = fileInfoPointer,
                StateAction = WinTrustDataStateAction.Ignore,
                ProviderFlags = WinTrustDataProviderFlags.CacheOnlyUrlRetrieval
            };

            Guid action = GenericVerifyV2;
            int result = Native.WinVerifyTrust(0, ref action, ref data);
            if (result != 0)
            {
                throw new InvalidDataException(OperationError.DriverSignature);
            }
        }
        finally
        {
            if (fileInfoPointer != 0)
            {
                Marshal.FreeCoTaskMem(fileInfoPointer);
            }
            if (handleReferenceAdded)
            {
                fileHandle.DangerousRelease();
            }
            Marshal.FreeCoTaskMem(pathPointer);
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WinTrustFileInfo
    {
        internal uint Size;
        internal nint FilePath;
        internal nint FileHandle;
        internal nint KnownSubject;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WinTrustData
    {
        internal uint Size;
        internal nint PolicyCallbackData;
        internal nint SipClientData;
        internal WinTrustDataUiChoice UiChoice;
        internal WinTrustDataRevocationChecks RevocationChecks;
        internal WinTrustDataChoice UnionChoice;
        internal nint File;
        internal WinTrustDataStateAction StateAction;
        internal nint StateData;
        internal nint UrlReference;
        internal WinTrustDataProviderFlags ProviderFlags;
        internal uint UiContext;
        internal nint SignatureSettings;
    }

    private enum WinTrustDataUiChoice : uint
    {
        None = 2
    }
    private enum WinTrustDataRevocationChecks : uint
    {
        None = 0
    }
    private enum WinTrustDataChoice : uint
    {
        File = 1
    }
    private enum WinTrustDataStateAction : uint
    {
        Ignore = 0
    }

    [Flags]
    private enum WinTrustDataProviderFlags : uint
    {
        CacheOnlyUrlRetrieval = 0x00001000
    }

    private static class Native
    {
        [DllImport("wintrust.dll", ExactSpelling = true, PreserveSig = true)]
        internal static extern int WinVerifyTrust(nint window, ref Guid actionId, ref WinTrustData trustData);
    }
}
