using VulneraNet.Core.Domain;
using VulneraNet.Core.Services.Interfaces;

namespace VulneraNet.Core.DataStructures;

public class PackageStore
{
    private readonly Dictionary<string, Package> _store = new();
    private readonly Dictionary<string, PackageId[]> _dependencyMapping = new();

    public void Add(PackageId packageId)
    {
        var package = new Package(packageId);
        _store[packageId.Name] = package;
    }

    public void SetDependencies(PackageId packageId, IEnumerable<PackageId> dependencyIds)
    {
        var dependencies = dependencyIds as PackageId[] ?? dependencyIds.ToArray();
        _dependencyMapping[packageId.Name] = dependencies;
        var package = _store[packageId.Name];
        package.MinimalDependencies.AddRange(dependencies);
    }

    public async Task<IEnumerable<Package>> GetAllAsync(INugetService nugetService)
    {
        var packages = _store.Values.ToArray();
        var vulnerabilitiesTasks = new List<Task>();

        foreach (var package in packages)
        {
            vulnerabilitiesTasks.Add(FindVulnerabilitiesAsync(package, nugetService));
            SetupDependencies(package);
        }

        await Task.WhenAll(vulnerabilitiesTasks);

        PropagateVulnerableDependenciesFlag();

        return packages;


        static async Task FindVulnerabilitiesAsync(Package package, INugetService nugetService)
        {
            var vulnerabilities = await nugetService.FindVulnerabilitiesAsync(package.Id);
            package.Vulnerabilities.AddRange(vulnerabilities);
        }

        void SetupDependencies(Package package)
        {
            var dependencyIds = _dependencyMapping[package.Id.Name];
            foreach (var dependencyId in dependencyIds)
            {
                if (_store.TryGetValue(dependencyId.Name, out var dependency))
                {
                    package.Dependencies.Add(dependency);
                    dependency.Dependants.Add(package);
                }
                else
                {
                    Console.Error.WriteLine($"{dependency} dependency not found in the Package Store");
                }
            }
        }

        void PropagateVulnerableDependenciesFlag()
        {
            var packagesWithVulnerableDeps = new Stack<Package>();
            foreach (var package in _store.Values.Where(p => p.IsVulnerable))
            {
                packagesWithVulnerableDeps.Push(package);
            }

            while (packagesWithVulnerableDeps.Count > 0)
            {
                var package = packagesWithVulnerableDeps.Pop();
                foreach (var dependant in package.Dependants.Where(d => !d.HasVulnerableDependencies))
                {
                    dependant.HasVulnerableDependencies = true;
                    packagesWithVulnerableDeps.Push(dependant);
                }
            }
        }
    }
}