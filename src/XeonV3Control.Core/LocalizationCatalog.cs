using System.Globalization;
using System.Text.Json;

namespace XeonV3Control.Core;

public sealed class LocalizationCatalog
{
    public const string DefaultCulture = "en-US";
    private static readonly string ResourcePrefix = EmbeddedResourceNames.FolderPrefix(
        EmbeddedResourceNames.LocalizationFolder);
    private const string ResourceSuffix = ".json";
    private static readonly IReadOnlyList<string> Cultures = DiscoverCultures();

    public static IReadOnlyList<string> SupportedCultures => Cultures;
    public string Language { get; }
    public CultureInfo Culture { get; }
    private readonly Dictionary<string, string> strings;

    public LocalizationCatalog(string? culture = null)
    {
        Language = ResolveLanguage(culture ?? CultureInfo.CurrentUICulture.Name);
        Culture = CultureInfo.GetCultureInfo(Language);
        using Stream resource = typeof(LocalizationCatalog).Assembly.GetManifestResourceStream(
                ResourcePrefix + Language + ResourceSuffix)
            ?? throw new InvalidDataException(OperationError.LocalizationResource);
        strings = JsonSerializer.Deserialize<Dictionary<string, string>>(resource)
            ?? throw new InvalidDataException(OperationError.LocalizationResource);
    }

    public string this[string key] => strings.TryGetValue(key, out string? value) ? value : key;
    public IReadOnlyCollection<string> Keys => strings.Keys;

    public static bool IsSupportedCulture(string culture) =>
        Cultures.Contains(culture, StringComparer.OrdinalIgnoreCase);

    private static IReadOnlyList<string> DiscoverCultures()
    {
        string[] cultures = typeof(LocalizationCatalog).Assembly.GetManifestResourceNames()
            .Where(name => name.StartsWith(ResourcePrefix, StringComparison.Ordinal) &&
                           name.EndsWith(ResourceSuffix, StringComparison.Ordinal))
            .Select(name => name[ResourcePrefix.Length..^ResourceSuffix.Length])
            .Where(IsValidCultureName)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(name => string.Equals(name, DefaultCulture, StringComparison.OrdinalIgnoreCase) ? 0 : 1)
            .ThenBy(name => name, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        if (!cultures.Contains(DefaultCulture, StringComparer.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(OperationError.LocalizationResource);
        }
        return cultures;
    }

    private static string ResolveLanguage(string culture)
    {
        string? exact = Cultures.FirstOrDefault(candidate =>
            string.Equals(candidate, culture, StringComparison.OrdinalIgnoreCase));
        if (exact is not null)
        {
            return exact;
        }

        try
        {
            string language = CultureInfo.GetCultureInfo(culture).TwoLetterISOLanguageName;
            string? compatible = Cultures.FirstOrDefault(candidate =>
                string.Equals(CultureInfo.GetCultureInfo(candidate).TwoLetterISOLanguageName,
                    language, StringComparison.OrdinalIgnoreCase));
            if (compatible is not null)
            {
                return compatible;
            }
        }
        catch (CultureNotFoundException)
        {
            // Invalid external culture values fall back to the product default.
        }

        return DefaultCulture;
    }

    private static bool IsValidCultureName(string name)
    {
        try
        {
            _ = CultureInfo.GetCultureInfo(name);
            return true;
        }
        catch (CultureNotFoundException)
        {
            return false;
        }
    }
}
