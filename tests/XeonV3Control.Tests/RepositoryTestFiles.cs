namespace XeonV3Control.Tests;

internal static class RepositoryTestFiles
{
    internal static string Find(params string[] relativePath)
    {
        for (DirectoryInfo? directory = new(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
        {
            string candidate = Path.Combine(directory.FullName, Path.Combine(relativePath));
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }

        throw new FileNotFoundException(string.Join(Path.DirectorySeparatorChar, relativePath));
    }
}
