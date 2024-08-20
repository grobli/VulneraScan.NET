using System.Collections.Frozen;
using VulneraNet.Core.Domain;
using VulneraNet.Core.Domain.NuGet.Vulnerabilities;
using VulneraNet.Core.Json;
using VulneraNet.Core.Mappers;
using VulneraNet.Core.Services.Interfaces;
using VulneraNet.Core.Utilities.Interfaces;

namespace VulneraNet.Core.Services;

public class NugetService : INugetService
{
    private readonly Uri _nugetVulnerabilityIndexUrl;
    private readonly Uri _nugetIndexUrl;

    private readonly IResilientHttpClient _httpClient;

    private readonly Task<FrozenDictionary<string, Vulnerability[]>> _vulnerabilityDataTask;

    public NugetService(IResilientHttpClient httpClient)
    {
        _httpClient = httpClient;
        _nugetVulnerabilityIndexUrl = new Uri("https://api.nuget.org/v3/vulnerabilities/index.json");
        _nugetIndexUrl = new Uri("https://api.nuget.org/v3/index.json");

        _vulnerabilityDataTask = FetchVulnerabilitiesDataAsync();
    }

    public async Task<IEnumerable<Vulnerability>> FindVulnerabilitiesAsync(PackageId packageId)
    {
        var data = await _vulnerabilityDataTask;
        return data.TryGetValue(packageId.Name, out var vulnerabilities)
            ? vulnerabilities.Where(v => v.VersionRange.CheckInRange(packageId.Version))
            : [];
    }

    public Task<Version?> FindFirstPatchedVersionAsync(PackageId packageId)
    {
        throw new NotImplementedException();
    }

    private async Task<VulnerabilitiesIndex> FetchVulnerabilitiesIndexAsync()
    {
        var entries = await _httpClient.GetAsync(_nugetVulnerabilityIndexUrl,
            SourceGenerationContext.Default.VulnerabilitiesIndexEntryArray);
        VulnerabilitiesIndexEntry? baseEntry = default;
        VulnerabilitiesIndexEntry? updateEntry = default;
        foreach (var entry in entries)
        {
            if (entry.Name.Equals("base", StringComparison.InvariantCultureIgnoreCase))
            {
                baseEntry = entry;
            }
            else
            {
                updateEntry = entry;
            }
        }

        return new VulnerabilitiesIndex { Base = baseEntry!, Update = updateEntry! };
    }

    private async Task<FrozenDictionary<string, Vulnerability[]>> FetchVulnerabilitiesDataAsync()
    {
        var index = await FetchVulnerabilitiesIndexAsync();

        var baseDataTask = _httpClient.GetAsync(index.Base.Id,
            SourceGenerationContext.Default.DictionaryStringListVulnerabilityEntry);
        var updateDataTask = _httpClient.GetAsync(index.Update.Id,
            SourceGenerationContext.Default.DictionaryStringListVulnerabilityEntry);
        await Task.WhenAll(baseDataTask, updateDataTask);

        var baseData = await baseDataTask;
        var updateData = await updateDataTask;

        // merge update into base
        foreach (var (key, updateEntries) in updateData)
        {
            if (baseData.TryGetValue(key, out var baseEntries))
            {
                baseEntries.AddRange(updateEntries);
            }
            else
            {
                baseData[key] = updateEntries;
            }
        }

        return baseData
            .ToDictionary(
                pair => pair.Key,
                pair => pair.Value.Select(v => v.ToVulnerability()).ToArray())
            .ToFrozenDictionary();
    }
}