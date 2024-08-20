using System.Text.RegularExpressions;
using VulneraNet.Core.Utilities;

namespace VulneraNet.Core.Domain;

public partial class VersionRange
{
    public Version Min { get; set; } = DefaultMin;
    public Version Max { get; set; } = DefaultMax;
    public bool IsMinInclusive { get; set; }
    public bool IsMaxInclusive { get; set; }

    private static readonly Version DefaultMin = Version.Parse("0.0.0");
    private static readonly Version DefaultMax = Version.Parse("9999.9999.9999");

    [GeneratedRegex(@"\(|\)|\[|\]", RegexOptions.Compiled)]
    private static partial Regex BracketRegex();

    public bool CheckInRange(Version version)
    {
        if (version > Min && version < Max)
        {
            return true;
        }

        if (Min.Equals(version))
        {
            return IsMinInclusive;
        }

        return Max.Equals(version) && IsMaxInclusive;
    }

    public static VersionRange Parse(string rangeString)
    {
        rangeString = rangeString.Trim();
        var vrange = new VersionRange
        {
            IsMinInclusive = rangeString.StartsWith('['),
            IsMaxInclusive = rangeString.EndsWith(']')
        };
        var versionStrings = BracketRegex().Replace(rangeString, string.Empty).Split(',');
        var minString = versionStrings[0];
        var maxString = versionStrings[1];
        
        // set Min version
        var minVersion = VersionConverter.Convert(minString);
        if (minVersion is not null)
        {
            vrange.Min = minVersion;
        }
        
        // set Max version
        var maxVersion = VersionConverter.Convert(maxString);
        if (maxVersion is not null)
        {
            vrange.Max = maxVersion;
        }

        return vrange;
    }

    public override string ToString()
    {
        var prefix = IsMinInclusive ? '[' : '(';
        var suffix = IsMaxInclusive ? ']' : ')';
        var minString = Min.Equals(DefaultMin) ? string.Empty : Min.ToString();
        var maxString = Max.Equals(DefaultMax) ? string.Empty : Max.ToString();
        return $"{prefix}{minString}, {maxString}{suffix}";
    }
}