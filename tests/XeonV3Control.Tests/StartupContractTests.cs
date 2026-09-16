namespace XeonV3Control.Tests;

[TestClass]
public sealed class StartupContractTests
{
    [TestMethod]
    public void WinUiEntryPointIsSynchronousSta()
    {
        string path = RepositoryTestFiles.Find("src", "XeonV3Control.App", "Program.cs");
        string source = File.ReadAllText(path);

        StringAssert.Contains(source, "[STAThread]");
        StringAssert.Contains(source, "private static void Main()");
        Assert.AreEqual(2,
            CountOccurrences(source, "Thread.CurrentThread.GetApartmentState() != ApartmentState.STA"),
            "STA must be verified both at the process entry point and inside the WinUI initialization callback.");
        StringAssert.Contains(source, "SynchronizationContext.SetSynchronizationContext(new DispatcherQueueSynchronizationContext(dispatcher))");
        Assert.IsFalse(source.Contains("async Task Main", StringComparison.Ordinal),
            "WinUI entry point must not be async because Clipboard/Drag&Drop require a real STA process entry thread.");
    }

    [TestMethod]
    public void UiSmokeExercisesStaDataTransferActivation()
    {
        string path = RepositoryTestFiles.Find("src", "XeonV3Control.App", "UiSmoke.cs");
        string source = File.ReadAllText(path);

        StringAssert.Contains(source, "new DataPackage()");
        StringAssert.Contains(source, "package.GetView()");
        StringAssert.Contains(source, "ApartmentState.STA");
    }

    private static int CountOccurrences(string source, string value)
    {
        int count = 0;
        int offset = 0;
        while ((offset = source.IndexOf(value, offset, StringComparison.Ordinal)) >= 0)
        {
            count++;
            offset += value.Length;
        }
        return count;
    }
}
