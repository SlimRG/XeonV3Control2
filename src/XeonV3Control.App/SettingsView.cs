using System.Globalization;
using System.Reflection;
using System.Runtime.InteropServices;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using XeonV3Control.Core;
using XeonV3Control.App.Hardware;

namespace XeonV3Control.App;

public sealed partial class MainWindow
{
    private bool settingsUiUpdate;
    private bool languageApplyQueued;
    private string pendingLanguageTag = UserPreferences.SystemCultureTag;
    private string? languageBeforePending;

    private void ApplySettingsLocalization()
    {
        settingsUiUpdate = true;
        try
        {
            SettingsHeading.Text = text["SettingsTitle"];
            SettingsSubtitle.Text = text["SettingsSubtitle"];
            AppearanceTitle.Text = text["Appearance"];
            LanguageSettingLabel.Text = text["LanguageSetting"];
            ThemeSettingLabel.Text = text["ThemeSetting"];
            Microsoft.UI.Xaml.Automation.AutomationProperties.SetName(LanguageComboBox, text["LanguageSetting"]);
            Microsoft.UI.Xaml.Automation.AutomationProperties.SetName(ThemeComboBox, text["ThemeSetting"]);
            AboutTitle.Text = text["About"];

            EnsureSettingsOptions();
            SetOptionContent(LanguageComboBox, UserPreferences.SystemCultureTag, text["SystemDefault"]);
            foreach (string culture in LocalizationCatalog.SupportedCultures)
            {
                SetOptionContent(LanguageComboBox, culture, CultureInfo.GetCultureInfo(culture).NativeName);
            }
            SelectTaggedItem(LanguageComboBox, preferences.Culture ?? UserPreferences.SystemCultureTag);

            SetOptionContent(ThemeComboBox, ThemePreference.System.ToString(), text["ThemeSystem"]);
            SetOptionContent(ThemeComboBox, ThemePreference.Light.ToString(), text["ThemeLight"]);
            SetOptionContent(ThemeComboBox, ThemePreference.Dark.ToString(), text["ThemeDark"]);
            SelectTaggedItem(ThemeComboBox, preferences.Theme.ToString());

            PopulateAboutDetails();
        }
        finally
        {
            settingsUiUpdate = false;
        }
    }

    private void EnsureSettingsOptions()
    {
        if (LanguageComboBox.Items.Count == 0)
        {
            LanguageComboBox.Items.Add(Option(string.Empty, UserPreferences.SystemCultureTag));
            foreach (string culture in LocalizationCatalog.SupportedCultures)
            {
                LanguageComboBox.Items.Add(Option(string.Empty, culture));
            }
        }

        if (ThemeComboBox.Items.Count == 0)
        {
            ThemeComboBox.Items.Add(Option(string.Empty, ThemePreference.System.ToString()));
            ThemeComboBox.Items.Add(Option(string.Empty, ThemePreference.Light.ToString()));
            ThemeComboBox.Items.Add(Option(string.Empty, ThemePreference.Dark.ToString()));
        }
    }

    private static ComboBoxItem Option(string content, string tag) => new()
    {
        Content = content,
        Tag = tag
    };

    private static void SetOptionContent(ComboBox comboBox, string tag, string content)
    {
        foreach (object item in comboBox.Items)
        {
            if (item is ComboBoxItem option && string.Equals(option.Tag as string, tag, StringComparison.OrdinalIgnoreCase))
            {
                option.Content = content;
                return;
            }
        }
    }

    private static void SelectTaggedItem(ComboBox comboBox, string tag)
    {
        foreach (object item in comboBox.Items)
        {
            if (item is ComboBoxItem option && string.Equals(option.Tag as string, tag, StringComparison.OrdinalIgnoreCase))
            {
                if (!ReferenceEquals(comboBox.SelectedItem, option))
                {
                    comboBox.SelectedItem = option;
                }
                return;
            }
        }

        if (comboBox.SelectedIndex != 0)
        {
            comboBox.SelectedIndex = 0;
        }
    }

    private void LanguageSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (settingsUiUpdate || LanguageComboBox.SelectedItem is not ComboBoxItem option || option.Tag is not string tag)
        {
            return;
        }

        string? culture = string.Equals(tag, UserPreferences.SystemCultureTag, StringComparison.OrdinalIgnoreCase) ? null : tag;
        if (!languageApplyQueued)
        {
            languageBeforePending = preferences.Culture;
        }

        if (settingsPersistenceEnabled)
        {
            if (!preferences.TrySetCulture(culture, out _))
            {
                ShowSettingsStorageError();
                settingsUiUpdate = true;
                try
                {
                    SelectTaggedItem(LanguageComboBox, preferences.Culture ?? UserPreferences.SystemCultureTag);
                }
                finally
                {
                    settingsUiUpdate = false;
                }
                return;
            }

            SettingsNotice.IsOpen = false;
        }
        else
        {
            preferences.SetCulture(culture);
        }

        // Rebuilding localized WinUI content from inside ComboBox.SelectionChanged can re-enter
        // the open popup. Defer the visual-tree update until the selection transaction is complete.
        pendingLanguageTag = tag;
        LanguageComboBox.IsDropDownOpen = false;
        if (languageApplyQueued)
        {
            return;
        }

        languageApplyQueued = true;
        if (!DispatcherQueue.TryEnqueue(DispatcherQueuePriority.Normal, ApplyPendingLanguageChange))
        {
            languageApplyQueued = false;
            string? previousCulture = languageBeforePending;
            languageBeforePending = null;
            RestoreCulturePreference(previousCulture);
            settingsUiUpdate = true;
            try
            {
                SelectTaggedItem(LanguageComboBox, previousCulture ?? UserPreferences.SystemCultureTag);
            }
            finally
            {
                settingsUiUpdate = false;
            }
            SetNotice(SettingsNotice, text["Error"], text["LanguageApplyFailed"], InfoBarSeverity.Warning);
        }
    }

    private void ApplyPendingLanguageChange()
    {
        languageApplyQueued = false;
        string tag = pendingLanguageTag;
        string? culture = string.Equals(tag, UserPreferences.SystemCultureTag, StringComparison.OrdinalIgnoreCase) ? null : tag;
        LocalizationCatalog previous = text;
        string? previousCulture = languageBeforePending;
        languageBeforePending = null;

        try
        {
            text = new LocalizationCatalog(culture);
            ApplyLocalization();
        }
        catch (Exception error)
        {
            // Runtime language replacement is a UI boundary: keep a failed visual-tree refresh from terminating the process.
            AppLog.Error(error);
            RestoreCulturePreference(previousCulture);

            text = previous;
            try
            {
                ApplyLocalization();
            }
            catch (Exception restoreError)
            {
                AppLog.Error(restoreError);
            }

            SetNotice(SettingsNotice, text["Error"], text["LanguageApplyFailed"], InfoBarSeverity.Warning);
        }
    }

    private void RestoreCulturePreference(string? culture)
    {
        if (!settingsPersistenceEnabled)
        {
            preferences.SetCulture(culture);
            return;
        }

        if (!preferences.TrySetCulture(culture, out Exception? rollbackError))
        {
            preferences.SetCulture(culture);
            if (rollbackError is not null)
            {
                AppLog.Error(rollbackError);
            }
        }
    }

    private void ThemeSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (settingsUiUpdate || ThemeComboBox.SelectedItem is not ComboBoxItem option || option.Tag is not string tag ||
            !Enum.TryParse(tag, ignoreCase: true, out ThemePreference theme) || !Enum.IsDefined(theme))
        {
            return;
        }

        ThemePreference previousTheme = preferences.Theme;
        if (settingsPersistenceEnabled)
        {
            if (!preferences.TrySetTheme(theme, out _))
            {
                ShowSettingsStorageError();
                RestoreThemeSelection(previousTheme);
                return;
            }

            SettingsNotice.IsOpen = false;
        }
        else
        {
            preferences.SetTheme(theme);
        }

        try
        {
            ApplyThemePreference(theme);
        }
        catch (Exception error)
        {
            AppLog.Error(error);
            RestoreThemePreference(previousTheme);
            try
            {
                ApplyThemePreference(previousTheme);
            }
            catch (Exception restoreError)
            {
                AppLog.Error(restoreError);
            }

            RestoreThemeSelection(previousTheme);
            SetNotice(SettingsNotice, text["Error"], text["ThemeApplyFailed"], InfoBarSeverity.Warning);
        }
    }

    private void RestoreThemePreference(ThemePreference theme)
    {
        if (!settingsPersistenceEnabled)
        {
            preferences.SetTheme(theme);
            return;
        }

        if (!preferences.TrySetTheme(theme, out Exception? rollbackError))
        {
            preferences.SetTheme(theme);
            if (rollbackError is not null)
            {
                AppLog.Error(rollbackError);
            }
        }
    }

    private void RestoreThemeSelection(ThemePreference theme)
    {
        settingsUiUpdate = true;
        try
        {
            SelectTaggedItem(ThemeComboBox, theme.ToString());
        }
        finally
        {
            settingsUiUpdate = false;
        }
    }

    private void ApplyThemePreference(ThemePreference theme)
    {
        Root.RequestedTheme = ElementThemeFor(theme);
        ApplyWindowIcon();
    }

    private static ElementTheme ElementThemeFor(ThemePreference theme) => theme switch
    {
        ThemePreference.Light => ElementTheme.Light,
        ThemePreference.Dark => ElementTheme.Dark,
        ThemePreference.System => ElementTheme.Default,
        _ => throw new ArgumentOutOfRangeException(nameof(theme), theme, null)
    };

    private void ShowSettingsStorageError() =>
        SetNotice(SettingsNotice, text["Error"], text["SettingsSaveFailed"], InfoBarSeverity.Warning);

    private void PopulateAboutDetails()
    {
        AboutDetails.Children.Clear();
        Version? version = Assembly.GetExecutingAssembly().GetName().Version;
        string versionText = version is null ? text["Unknown"] : version.ToString(3);

        AddRow(AboutDetails, text["Version"], versionText);
        AddRow(AboutDetails, text["Runtime"], string.Format(text.Culture, text["RuntimeVersionFormat"], Environment.Version));
        AddRow(AboutDetails, text["OperatingSystem"], RuntimeInformation.OSDescription);
        AddRow(AboutDetails, text["Architecture"], RuntimeInformation.ProcessArchitecture.ToString());
        AddRow(AboutDetails, text["Driver"], string.Format(
            text.Culture,
            text["InlinePairFormat"],
            ThrottleStopDriverAuthenticity.Manifest.FileName,
            text["DriverProtection"]));
    }
}
