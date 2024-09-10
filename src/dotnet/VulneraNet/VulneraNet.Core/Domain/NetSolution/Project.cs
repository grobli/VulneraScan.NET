using System.Collections.Frozen;
using System.IO.Abstractions;
using System.Text.Json;
using System.Xml;
using VulneraNet.Core.DataStructures;
using VulneraNet.Core.Domain.NetSolution.ProjectAssetsJson;
using VulneraNet.Core.Exceptions;
using VulneraNet.Core.Json;
using VulneraNet.Core.Services.Interfaces;
using VulneraNet.Core.Utilities;

namespace VulneraNet.Core.Domain.NetSolution;

public class Project
{
    public IFileInfo File { get; }
    public Solution Solution { get; init; }
    public bool IsModern { get; private set; }
    public bool IsLegacy => !IsModern;

    private readonly IFileSystem _fileSystem;

    private XmlDocument _xmlContent = null!;
    private FrozenSet<string> _packageReferences = null!;

    private Project(string projectPath, Solution solution, IFileSystem fileSystem)
    {
        _fileSystem = fileSystem;
        Solution = solution;
        File = _fileSystem.FileInfo.New(projectPath);
    }

    public static async Task<Project> LoadAsync(string projectPath, Solution solution, IFileSystem fileSystem,
        CancellationToken cancellationToken = default)
    {
        var project = new Project(projectPath, solution, fileSystem);
        await project.SetupPropertiesAsync(cancellationToken);
        return project;
    }

    public static async Task<Project> LoadAsync(string projectPath, Solution solution,
        CancellationToken cancellationToken = default) =>
        await LoadAsync(projectPath, solution, new FileSystem(), cancellationToken);

    public async Task<IEnumerable<Package>> GetPackagesAsync(INugetService nugetService,
        CancellationToken cancellationToken = default)
    {
        var packages = await ReadProjectAssetsAsync(nugetService, cancellationToken);
        return FilterOutNotRelatedPackagesAsync(packages);

        IEnumerable<Package> FilterOutNotRelatedPackagesAsync(IEnumerable<Package> packagesToFilter)
        {
            if (IsLegacy)
            {
                return packagesToFilter;
            }

            var projectRelatedPackages = new HashSet<Package>();
            foreach (var package in packagesToFilter)
            {
                package.IsPackageReference = _packageReferences.Contains(package.Id.Name);

                if (!package.IsPackageReference) continue;

                projectRelatedPackages.Add(package);
                projectRelatedPackages.UnionWith(package.GetAllTransitives());
            }

            return projectRelatedPackages;
        }
    }

    public override string ToString() => File.FullName;

    private bool IsSdkStyle()
    {
        var projectNode = _xmlContent.SelectSingleNode("./Project");
        return projectNode?.Attributes?["Sdk"] is not null;
    }

    private async Task SetupPropertiesAsync(CancellationToken cancellationToken)
    {
        _xmlContent = await LoadXmlAsync(cancellationToken);

        IsModern = IsSdkStyle();
        _packageReferences = ReadPackageReferences();
    }

    private FrozenSet<string> ReadPackageReferences()
    {
        var packageReferences = _xmlContent.SelectNodes(".//PackageReference");
        if (packageReferences is null)
        {
            return FrozenSet<string>.Empty;
        }

        var prefSet = new HashSet<string>();
        foreach (XmlNode pref in packageReferences)
        {
            prefSet.Add(pref.Attributes!["Include"]!.Value.Trim().ToLower());
        }

        return prefSet.ToFrozenSet();
    }

    private async Task<XmlDocument> LoadXmlAsync(CancellationToken token)
    {
        var csprojXml = new XmlDocument();
        var content = await _fileSystem.File.ReadAllTextAsync(File.FullName, token);
        csprojXml.LoadXml(content);
        return csprojXml;
    }

    private async Task<IEnumerable<Package>> ReadProjectAssetsAsync(INugetService nugetService,
        CancellationToken cancellationToken)
    {
        var projectAssets = await ParseProjectAssetsAsync();
        var packageStore = new PackageStore();
        foreach (var (name, entry) in projectAssets)
        {
            var packageId = PackageId.Parse(name);
            packageStore.Add(packageId);
            var dependencies = entry.Dependencies?
                .Select(pair => new PackageId(pair.Key, VersionConverter.Convert(pair.Value)!)) ?? [];
            packageStore.SetDependencies(packageId, dependencies);
        }

        return await packageStore.GetAllAsync(nugetService, cancellationToken);
    }

    private async Task<Dictionary<string, TargetsEntry>> ParseProjectAssetsAsync()
    {
        var file = FindProjectAssetsFile();
        var stream = _fileSystem.File.OpenRead(file.FullName);
        var projectAssets =
            await JsonSerializer.DeserializeAsync(stream, SourceGenerationContext.Default.ProjectAssets);
        if (projectAssets is not null)
        {
            return projectAssets.Targets.First().Value;
        }

        throw new ProjectAssetsFileParsingException();
    }

    private IFileInfo FindProjectAssetsFile()
    {
        var path = _fileSystem.Path.Join(File.Directory?.FullName, "obj/project.assets.json");
        var file = _fileSystem.FileInfo.New(path);
        if (!file.Exists)
        {
            throw new ProjectNotRestoredException(ToString());
        }

        return file;
    }
}