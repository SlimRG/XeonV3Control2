using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using XeonV3Control.App;
using XeonV3Control.App.Hardware;
using XeonV3Control.Core;

if (args.Length != ProbePolicy.RequiredArgumentCount)
{
    return ProbePolicy.InvalidArgumentsExitCode;
}

string output = Path.GetFullPath(args[0]);
Directory.CreateDirectory(output);
string logPath = Path.Combine(output, ProbeArtifacts.LogFileName);
void Log(string value) => File.AppendAllText(
    logPath,
    DateTimeOffset.Now.ToString("O", CultureInfo.InvariantCulture) + " " + value + Environment.NewLine);

int code = ProbePolicy.FailureExitCode;
try
{
    Log("START Read-only hardware validation; full-SPI-first, two independent reads.");
    using var timeout = new CancellationTokenSource(ProbePolicy.OperationTimeout);
    using var gate = new Semaphore(1, 1, ApplicationIdentity.SpiReadSemaphoreName);
    if (!gate.WaitOne(TimeSpan.Zero))
    {
        throw new IOException(OperationError.SpiBusy);
    }
    try
    {
        using (var driver = ThrottleStopDriver.Open(Log, timeout.Token))
        {
            Log($"HSFS=0x{driver.Read(X99Platform.Spi.HardwareStatusRegister, X99Platform.Spi.WordWidth):X4}; " +
                $"FRAP=0x{driver.Read(X99Platform.Spi.FlashRegionAccessPermissionsRegister, X99Platform.Spi.DwordWidth):X8}; " +
                $"FREG1=0x{driver.Read(X99Platform.Spi.BiosRegionRegister, X99Platform.Spi.DwordWidth):X8}");
            var reader = new ObservedReader(new X99SpiReader(driver), Log, output);
            VerifiedFirmwareDump result = await VerifiedDump.CreateAsync(
                reader,
                Path.Combine(output, ProbeArtifacts.VerifiedFirmwareFileName),
                cancellationToken: timeout.Token);
            File.WriteAllText(
                Path.Combine(output, ProbeArtifacts.ImageReportFileName),
                JsonSerializer.Serialize(result.Image, ProbePolicy.JsonOptions));
            Log(
                $"VERIFIED scope={result.Scope}; {result.Image.Size} bytes SHA256={result.Image.Sha256}; " +
                $"volumes={result.Image.Volumes.Count}; issues={result.Image.Issues.Count}; " +
                $"regions={ProbePolicy.FormatRegions(result.Regions)}");
        }

        Log("DRIVER_DISPOSED");
        code = ProbePolicy.SuccessExitCode;
    }
    finally
    {
        gate.Release();
    }
}
catch (Exception error)
{
    Log("FAIL " + error);
    File.WriteAllText(Path.Combine(output, ProbeArtifacts.ErrorFileName), error.ToString());
}
finally
{
    File.WriteAllText(
        Path.Combine(output, ProbeArtifacts.ExitCodeFileName),
        code.ToString(CultureInfo.InvariantCulture));
    Log("END exit=" + code.ToString(CultureInfo.InvariantCulture));
}

return code;

sealed class ObservedReader(IFirmwareReader inner, Action<string> log, string output) : IFirmwareReader
{
    private int _pass;

    public FirmwareCapabilities Capabilities => inner.Capabilities;

    public FirmwareReadSnapshot ReadFirmware(
        IProgress<double>? progress,
        CancellationToken cancellationToken)
    {
        int current = ++_pass;
        int lastProgressBucket = -1;
        log("READ_START " + current.ToString(CultureInfo.InvariantCulture));
        FirmwareReadSnapshot snapshot = inner.ReadFirmware(new Callback(value =>
        {
            progress?.Report(value);
            int percent = (int)(value * ProbePolicy.PercentScale);
            int bucket = percent / ProbePolicy.ProgressLogStepPercent;
            if (bucket == lastProgressBucket)
            {
                return;
            }

            lastProgressBucket = bucket;
            log($"READ_PROGRESS {current} {percent}%");
        }), cancellationToken);
        byte[] data = snapshot.Data;
        log(
            $"READ_COMPLETE {current} scope={snapshot.Scope} bytes={data.Length} " +
            $"SHA256={Convert.ToHexString(SHA256.HashData(data))}; regions={ProbePolicy.FormatRegions(snapshot.Regions)}");
        BiosImage report = BiosImageLoader.Analyze(data, cancellationToken: cancellationToken);
        log("STRUCTURE " + JsonSerializer.Serialize(report));

        string rawReadName = string.Format(
            CultureInfo.InvariantCulture,
            ProbeArtifacts.UnverifiedReadFileNameFormat,
            current);
        using var stream = new FileStream(
            Path.Combine(output, rawReadName),
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.None);
        stream.Write(data);
        stream.Flush(true);
        return snapshot;
    }

    private sealed class Callback(Action<double> action) : IProgress<double>
    {
        public void Report(double value) => action(value);
    }
}

static class ProbePolicy
{
    internal const int RequiredArgumentCount = 1;
    internal const int SuccessExitCode = 0;
    internal const int FailureExitCode = 1;
    internal const int InvalidArgumentsExitCode = 2;
    internal const int PercentScale = 100;
    internal const int ProgressLogStepPercent = 10;
    internal static readonly TimeSpan OperationTimeout = TimeSpan.FromMinutes(15);
    internal static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    internal static string FormatRegions(IReadOnlyList<FirmwareRegionReadStatus> regions) =>
        string.Join(
            ",",
            regions.Select(region => string.Create(
                CultureInfo.InvariantCulture,
                $"{region.Kind}@0x{region.Start:X}:{region.Length}:{(region.Readable ? "read" : "blocked")}")));
}

static class ProbeArtifacts
{
    internal const string LogFileName = "probe.log";
    internal const string VerifiedFirmwareFileName = "X99-SPI-verified.bin";
    internal const string ImageReportFileName = "image.json";
    internal const string ErrorFileName = "error.txt";
    internal const string ExitCodeFileName = "exit-code.txt";
    internal const string UnverifiedReadFileNameFormat = "read-{0}.unverified.bin";
}
