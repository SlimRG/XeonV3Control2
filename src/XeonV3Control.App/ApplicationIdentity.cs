namespace XeonV3Control.App;

internal static class ApplicationIdentity
{
    internal const string ProductId = "XeonV3Control2";
    internal const string DisplayName = "Xeon V3 Control 2";
    internal const string MainInstanceKey = ProductId + ".MainInstance";
    internal const string SettingsRegistryPath = @"Software\" + ProductId;
    internal const string CrashReportFileName = "error.txt";
    internal const string TransientRootDirectoryName = ProductId + ".Transient";
    internal const string TemporarySessionPrefix = "session-";
    internal const string TemporaryLogFileName = "log.txt";
    internal const string TemporaryWindowIconFileName = "window-icon.ico";
    internal const string TemporarySessionLockFileName = ".session.lock";
    internal const string TemporaryBiosExtension = ".bin";
    internal const string SystemDumpArtifactPrefix = "system-bios";
    internal const string SecureBootRepairedArtifactPrefix = "secureboot-repaired";
    internal const string CpuPatchRemovedArtifactPrefix = "cpu-patch-removed";
    internal const string ForeignUnlockRemovedArtifactPrefix = "foreign-unlock-removed";
    internal const string UefiDriverUpdatedArtifactPrefix = "uefi-driver-updated";
    internal const string PackageImportArtifactPrefix = "package-bios";
    internal const string LargeBootLogoArtifactPrefix = "boot-logo-large";
    internal const string SmallAmiLogoArtifactPrefix = "boot-logo-small";
    internal const string BeeperDisabledArtifactPrefix = "beeper-disabled";
    internal const string BeeperEnabledArtifactPrefix = "beeper-enabled";
    internal const string TpmDebugInstalledArtifactPrefix = "tpm-debug-installed";
    internal const string TpmDebugRemovedArtifactPrefix = "tpm-debug-removed";
    internal const string SpiReadSemaphoreName = @"Global\" + ProductId + ".SpiRead";
    internal const string DriverServicePrefix = "XeonV3Bios_";
}
