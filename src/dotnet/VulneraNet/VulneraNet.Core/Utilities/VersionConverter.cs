using System.Text.RegularExpressions;

namespace VulneraNet.Core.Utilities;

public static partial class VersionConverter
{
    [GeneratedRegex(@"(\d+\.\d+\.?\d*)", RegexOptions.Compiled)]
    private static partial Regex VersionRegex();

    public static Version? Convert(string versionString)
    {
        var match = VersionRegex().Match(versionString);
        return match.Success ? Version.Parse(match.Value) : default;
    }
}