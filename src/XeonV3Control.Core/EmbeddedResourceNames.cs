namespace XeonV3Control.Core;

/// <summary>Builds manifest-resource names from the assembly namespace instead of duplicating it in each subsystem.</summary>
internal static class EmbeddedResourceNames
{
    internal const string LocalizationFolder = "Localization";
    internal const string CertificatesFolder = "Certificates";
    internal const string FirmwareFolder = "Firmware";

    private static readonly string RootNamespace = typeof(EmbeddedResourceNames).Namespace
        ?? throw new InvalidOperationException("Core namespace is unavailable.");

    internal static string FolderPrefix(string folder)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(folder);
        return RootNamespace + "." + folder + ".";
    }

    internal static string File(string folder, string file)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(file);
        return FolderPrefix(folder) + file;
    }
}
