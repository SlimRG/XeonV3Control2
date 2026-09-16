using System.Security;

namespace XeonV3Control.Core;

internal static class FileSystemCleanup
{
    internal const string FailureDataKey = "FileCleanupFailure";

    internal static bool TryDeleteFile(string path, out Exception? failure)
    {
        try
        {
            File.Delete(path);
            failure = null;
            return true;
        }
        catch (FileNotFoundException)
        {
            failure = null;
            return true;
        }
        catch (DirectoryNotFoundException)
        {
            failure = null;
            return true;
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or SecurityException)
        {
            failure = error;
            return false;
        }
    }

    internal static void AttachCleanupFailure(Exception operationError, Exception cleanupError)
    {
        ArgumentNullException.ThrowIfNull(operationError);
        ArgumentNullException.ThrowIfNull(cleanupError);
        operationError.Data[FailureDataKey] = cleanupError.ToString();
    }
}
