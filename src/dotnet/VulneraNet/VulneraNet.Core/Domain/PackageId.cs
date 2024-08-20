using VulneraNet.Core.Utilities;

namespace VulneraNet.Core.Domain;

public record PackageId
{
    public string Name { get; }
    public Version Version { get; }
    public override string ToString() => $"{Name}/{Version}";

    public PackageId(string name, Version version)
    {
        Name = name.Trim().ToLower();
        Version = version;
    }
    
    public static PackageId Parse(string packageIdString)
    {
        var split = packageIdString.Split('/');
        var name = split[0];
        var version = VersionConverter.Convert(split[1])!;
        return new PackageId(name, version);
    }
}