namespace VulneraNet.Core.Domain;

public class Package(PackageId packageId) : IEquatable<Package>
{
    public PackageId Id { get; } = packageId;
    public List<Vulnerability> Vulnerabilities { get; } = [];
    public List<Package> Dependencies { get; } = [];
    public List<Package> Dependants { get; } = [];
    public List<PackageId> MinimalDependencies { get; } = [];

    public bool HasVulnerableDependencies { get; internal set; }
    public bool IsPackageReference { get; internal set; }
    public bool IsTransitive => Dependants.Count > 0;
    public bool IsDirect => !IsTransitive;
    public bool IsVulnerable => Vulnerabilities.Count > 0;

    public override string ToString() => Id.ToString();

    public IEnumerable<Package> GetAllTransitives()
    {
        var transitives = new HashSet<Package>();
        var stack = new Stack<Package>();
        stack.Push(this);

        while (stack.Count > 0)
        {
            var package = stack.Pop();
            foreach (var dependency in package.Dependencies.Where(dep => transitives.Add(dep)))
            {
                stack.Push(dependency);
            }
        }

        return transitives;
    }

    public bool Equals(Package? other)
    {
        if (ReferenceEquals(null, other)) return false;
        return ReferenceEquals(this, other) || Id.Equals(other.Id);
    }

    public override bool Equals(object? obj)
    {
        if (ReferenceEquals(null, obj)) return false;
        if (ReferenceEquals(this, obj)) return true;
        return obj.GetType() == GetType() && Equals((Package)obj);
    }

    public override int GetHashCode()
    {
        return Id.GetHashCode();
    }
}