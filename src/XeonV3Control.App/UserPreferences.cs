using System.Security;
using System.Text.Json;
using Microsoft.Win32;
using XeonV3Control.Core;

namespace XeonV3Control.App;

internal enum ThemePreference
{
    System,
    Light,
    Dark
}

internal sealed class UserPreferences
{
    private const string PreferencesValueName = "Preferences";
    private const string LegacyLanguageValueName = "Language";
    private const string LegacyThemeValueName = "Theme";
    private const int CurrentSchemaVersion = 1;
    internal const string SystemCultureTag = "system";

    public string? Culture { get; private set; }
    public ThemePreference Theme { get; private set; } = ThemePreference.System;

    public static UserPreferences Load()
    {
        var preferences = new UserPreferences();
        try
        {
            using RegistryKey? key = Registry.CurrentUser.OpenSubKey(ApplicationIdentity.SettingsRegistryPath, writable: false);
            if (key is null)
            {
                return preferences;
            }

            if (key.GetValue(PreferencesValueName) is string serialized && !string.IsNullOrWhiteSpace(serialized))
            {
                StoredPreferences stored = JsonSerializer.Deserialize<StoredPreferences>(serialized)
                    ?? throw new InvalidDataException(OperationError.SettingsStorage);
                if (stored.SchemaVersion != CurrentSchemaVersion)
                {
                    throw new InvalidDataException(OperationError.SettingsStorage);
                }

                preferences.Culture = ParseStoredCulture(stored.Culture);
                preferences.Theme = ParseStoredTheme(stored.Theme);
                return preferences;
            }

            // One-time compatibility with releases that stored two independent registry values.
            string? legacyCulture = key.GetValue(LegacyLanguageValueName) as string;
            preferences.Culture = ParseStoredCulture(legacyCulture);
            string? legacyTheme = key.GetValue(LegacyThemeValueName) as string;
            if (Enum.TryParse(legacyTheme, ignoreCase: true, out ThemePreference parsedTheme) && Enum.IsDefined(parsedTheme))
            {
                preferences.Theme = parsedTheme;
            }

            if (legacyCulture is not null || legacyTheme is not null)
            {
                _ = TryPersist(preferences.Culture, preferences.Theme, out _);
            }
        }
        catch (Exception error) when (IsSettingsLoadFailure(error))
        {
            AppLog.Error(error);
        }

        return preferences;
    }

    public bool TrySetCulture(string? culture, out Exception? error)
    {
        string? normalized = ValidateCulture(culture);
        if (!TryPersist(normalized, Theme, out error))
        {
            return false;
        }
        Culture = normalized;
        return true;
    }

    internal void SetCulture(string? culture) => Culture = ValidateCulture(culture);

    public bool TrySetTheme(ThemePreference theme, out Exception? error)
    {
        ValidateTheme(theme);
        if (!TryPersist(Culture, theme, out error))
        {
            return false;
        }
        Theme = theme;
        return true;
    }

    internal void SetTheme(ThemePreference theme)
    {
        ValidateTheme(theme);
        Theme = theme;
    }

    private static bool TryPersist(string? culture, ThemePreference theme, out Exception? error)
    {
        try
        {
            using RegistryKey key = Registry.CurrentUser.CreateSubKey(ApplicationIdentity.SettingsRegistryPath, writable: true)
                ?? throw new IOException(OperationError.SettingsStorage);
            var stored = new StoredPreferences(
                CurrentSchemaVersion,
                culture ?? SystemCultureTag,
                theme.ToString());
            key.SetValue(PreferencesValueName, JsonSerializer.Serialize(stored), RegistryValueKind.String);

            // Cleanup is best-effort after the atomic combined value has been committed.
            TryDeleteLegacyValue(key, LegacyLanguageValueName);
            TryDeleteLegacyValue(key, LegacyThemeValueName);
            error = null;
            return true;
        }
        catch (Exception caught) when (IsSettingsStorageFailure(caught))
        {
            AppLog.Error(caught);
            error = caught;
            return false;
        }
    }

    private static string? ParseStoredCulture(string? culture)
    {
        if (string.IsNullOrWhiteSpace(culture) ||
            string.Equals(culture, SystemCultureTag, StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        return LocalizationCatalog.IsSupportedCulture(culture)
            ? culture
            : throw new InvalidDataException(OperationError.SettingsStorage);
    }

    private static ThemePreference ParseStoredTheme(string? theme) =>
        Enum.TryParse(theme, ignoreCase: true, out ThemePreference parsed) && Enum.IsDefined(parsed)
            ? parsed
            : throw new InvalidDataException(OperationError.SettingsStorage);

    private static string? ValidateCulture(string? culture)
    {
        if (culture is null)
        {
            return null;
        }
        if (LocalizationCatalog.IsSupportedCulture(culture))
        {
            return culture;
        }
        throw new ArgumentOutOfRangeException(nameof(culture), culture, OperationError.SettingsStorage);
    }

    private static void ValidateTheme(ThemePreference theme)
    {
        if (!Enum.IsDefined(theme))
        {
            throw new ArgumentOutOfRangeException(nameof(theme));
        }
    }

    private static void TryDeleteLegacyValue(RegistryKey key, string valueName)
    {
        try
        {
            key.DeleteValue(valueName, throwOnMissingValue: false);
        }
        catch (Exception error) when (IsSettingsStorageFailure(error))
        {
            AppLog.Error(error);
        }
    }

    private static bool IsSettingsLoadFailure(Exception error) =>
        IsSettingsStorageFailure(error) || error is JsonException or InvalidDataException;

    private static bool IsSettingsStorageFailure(Exception error) =>
        error is IOException or UnauthorizedAccessException or SecurityException;

    private sealed record StoredPreferences(int SchemaVersion, string Culture, string Theme);
}
