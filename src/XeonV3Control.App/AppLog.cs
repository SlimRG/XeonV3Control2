using System.Diagnostics;
using System.Globalization;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;

namespace XeonV3Control.App;

internal static class AppLog
{
    private static readonly object Sync = new();
    private static readonly UTF8Encoding Utf8WithoutBom = new(encoderShouldEmitUTF8Identifier: false);
    private static string? path;
    private static string? crashFallbackPath;
    private static int crashState;

    internal static void Configure(string logPath, string fallbackCrashPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(logPath);
        ArgumentException.ThrowIfNullOrWhiteSpace(fallbackCrashPath);
        lock (Sync)
        {
            path = Path.GetFullPath(logPath);
            crashFallbackPath = Path.GetFullPath(fallbackCrashPath);
        }
    }


    internal static void ConfigureCrashFallback(string? fallbackCrashPath)
    {
        lock (Sync)
            crashFallbackPath = string.IsNullOrWhiteSpace(fallbackCrashPath) ? null : Path.GetFullPath(fallbackCrashPath);
    }

    internal static void Error(Exception exception)
    {
        ArgumentNullException.ThrowIfNull(exception);
        try
        {
            lock (Sync)
            {
                if (path is null)
                {
                    return;
                }
                File.AppendAllText(
                    path,
                    DateTimeOffset.Now.ToString("O", CultureInfo.InvariantCulture) + " " + exception + Environment.NewLine,
                    Utf8WithoutBom);
            }
        }
        catch (Exception loggingError) when (IsExpectedLoggingFailure(loggingError))
        {
            Debug.WriteLine(loggingError);
        }
    }

    internal static void ReportError(Exception exception, string source)
    {
        ArgumentNullException.ThrowIfNull(exception);
        ArgumentException.ThrowIfNullOrWhiteSpace(source);
        Error(exception);

        try
        {
            byte[] report = Utf8WithoutBom.GetBytes(BuildReport(exception, source, "error report"));
            string primary = ResolvePrimaryCrashPath();
            if (TryWriteCrashReport(primary, report, requirePlainParent: false))
            {
                return;
            }

            string? fallback = ResolveFallbackCrashPath();
            if (fallback is not null &&
                !string.Equals(primary, fallback, StringComparison.OrdinalIgnoreCase))
            {
                _ = TryWriteCrashReport(fallback, report, requirePlainParent: true);
            }
        }
        catch (Exception loggingError) when (IsExpectedLoggingFailure(loggingError))
        {
            Debug.WriteLine(loggingError);
        }
    }

    internal static void Crash(Exception exception, string source)
    {
        ArgumentNullException.ThrowIfNull(exception);
        ArgumentException.ThrowIfNullOrWhiteSpace(source);
        if (Interlocked.CompareExchange(ref crashState, 1, 0) != 0)
        {
            return;
        }

        try
        {
            byte[] report = Utf8WithoutBom.GetBytes(BuildReport(exception, source, "crash report"));
            string primary = ResolvePrimaryCrashPath();
            if (TryWriteCrashReport(primary, report, requirePlainParent: false))
            {
                Volatile.Write(ref crashState, 2);
                return;
            }

            string? fallback = ResolveFallbackCrashPath();
            if (fallback is not null &&
                !string.Equals(primary, fallback, StringComparison.OrdinalIgnoreCase) &&
                TryWriteCrashReport(fallback, report, requirePlainParent: true))
            {
                Volatile.Write(ref crashState, 2);
                return;
            }

            Volatile.Write(ref crashState, 0);
        }
        catch (Exception loggingError) when (IsExpectedLoggingFailure(loggingError))
        {
            Debug.WriteLine(loggingError);
            Volatile.Write(ref crashState, 0);
        }
    }

    private static string BuildReport(Exception exception, string source, string reportKind)
    {
        Version? version = Assembly.GetExecutingAssembly().GetName().Version;
        var builder = new StringBuilder()
            .Append(ApplicationIdentity.DisplayName).Append(' ').AppendLine(reportKind)
            .Append("Time: ").AppendLine(DateTimeOffset.Now.ToString("O", CultureInfo.InvariantCulture))
            .Append("Source: ").AppendLine(source)
            .Append("Version: ").AppendLine(version?.ToString() ?? "unknown")
            .Append("Runtime: .NET ").AppendLine(Environment.Version.ToString())
            .Append("OS: ").AppendLine(RuntimeInformation.OSDescription)
            .Append("Architecture: ").AppendLine(RuntimeInformation.ProcessArchitecture.ToString())
            .Append("Process ID: ").AppendLine(Environment.ProcessId.ToString(CultureInfo.InvariantCulture))
            .AppendLine()
            .AppendLine(exception.ToString());

        AppendExceptionData(builder, exception);
        return builder.ToString();
    }

    private static void AppendExceptionData(StringBuilder builder, Exception exception)
    {
        int depth = 0;
        for (Exception? current = exception; current is not null; current = current.InnerException, depth++)
        {
            if (current.Data.Count == 0)
            {
                continue;
            }

            builder.AppendLine().Append("ExceptionData[").Append(depth).AppendLine("]:");
            foreach (System.Collections.DictionaryEntry entry in current.Data)
            {
                builder.Append("  ").Append(entry.Key).Append(" = ").AppendLine(entry.Value?.ToString() ?? "<null>");
            }
        }
    }

    private static bool TryWriteCrashReport(string target, byte[] report, bool requirePlainParent)
    {
        try
        {
            string? directory = Path.GetDirectoryName(target);
            if (string.IsNullOrWhiteSpace(directory))
            {
                return false;
            }

            DirectoryInfo directoryInfo;
            if (requirePlainParent)
            {
                directoryInfo = new DirectoryInfo(directory);
                directoryInfo.Refresh();
                if (!directoryInfo.Exists || (directoryInfo.Attributes & FileAttributes.ReparsePoint) != 0)
                {
                    return false;
                }
            }
            else
            {
                directoryInfo = Directory.CreateDirectory(directory);
            }

            if (File.Exists(target))
            {
                if ((File.GetAttributes(target) & FileAttributes.ReparsePoint) != 0)
                {
                    return false;
                }
                File.Delete(target);
            }

            // CreateNew ensures an attacker cannot replace the just-checked path with a reparse point
            // between cleanup and open: a raced-in entry makes the open fail instead of being followed.
            using var output = new FileStream(target, new FileStreamOptions
            {
                Mode = FileMode.CreateNew,
                Access = FileAccess.Write,
                Share = FileShare.Read,
                Options = FileOptions.WriteThrough
            });
            output.Write(report);
            output.Flush(flushToDisk: true);
            Debug.WriteLine("Crash report written to " + target);
            return true;
        }
        catch (Exception loggingError) when (IsExpectedLoggingFailure(loggingError))
        {
            Debug.WriteLine(loggingError);
            return false;
        }
    }

    private static string ResolvePrimaryCrashPath()
    {
        string? executable = Environment.ProcessPath;
        string directory = executable is null
            ? AppContext.BaseDirectory
            : Path.GetDirectoryName(executable) ?? AppContext.BaseDirectory;
        return Path.Combine(directory, ApplicationIdentity.CrashReportFileName);
    }

    private static string? ResolveFallbackCrashPath()
    {
        lock (Sync) return crashFallbackPath;
    }

    private static bool IsExpectedLoggingFailure(Exception error) =>
        error is IOException or UnauthorizedAccessException or SecurityException or
        ArgumentException or NotSupportedException;
}
