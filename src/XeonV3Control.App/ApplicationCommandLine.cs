namespace XeonV3Control.App;

internal sealed record UiSmokeRequest(string OutputDirectory, string Culture, string ImagePath);

internal sealed record ApplicationLaunchRequest(string? ImagePath, UiSmokeRequest? UiSmoke)
{
    internal const string UiSmokeSwitch = "--ui-smoke";

    internal static ApplicationLaunchRequest Parse(string[] arguments)
    {
        ArgumentNullException.ThrowIfNull(arguments);
        if (arguments.Length > 1 && string.Equals(arguments[1], UiSmokeSwitch, StringComparison.Ordinal))
        {
            if (arguments.Length != 5)
            {
                throw new ArgumentException("The UI smoke command requires output directory, culture and image path.", nameof(arguments));
            }

            return new(null, new UiSmokeRequest(arguments[2], arguments[3], arguments[4]));
        }

        return arguments.Length switch
        {
            0 or 1 => new(null, null),
            2 => new(arguments[1], null),
            _ => throw new ArgumentException("Unexpected application command-line arguments.", nameof(arguments))
        };
    }
}
