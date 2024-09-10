using System.Collections.Frozen;
using VulneraNet.Core.Domain;
using VulneraNet.Core.Domain.NuGet.Vulnerabilities;
using VulneraNet.Core.Json;
using VulneraNet.Core.Mappers;
using VulneraNet.Core.Services.Interfaces;
using VulneraNet.Core.Utilities.Http;
using VulneraNet.Core.Utilities.Logging;

namespace VulneraNet.Core.Services;

public class NugetService(IResilientHttpClient httpClient, ILogger logger) : INugetService
{
    private readonly Uri _nugetVulnerabilityIndexUrl = new("https://api.nuget.org/v3/vulnerabilities/index.json");
    private readonly Uri _nugetIndexUrl = new("https://api.nuget.org/v3/index.json");

    private readonly SemaphoreSlim _semaphore = new(1, 1);

    private FrozenDictionary<string, Vulnerability[]>? _vulnerabilityData;

    public async Task<IEnumerable<Vulnerability>> FindVulnerabilitiesAsync(PackageId packageId,
        CancellationToken cancellationToken = default)
    {
        var data = await GetVulnerabilityDataAsync(cancellationToken);
        return data.TryGetValue(packageId.Name, out var vulnerabilities)
            ? vulnerabilities.Where(v => v.VersionRange.CheckInRange(packageId.Version))
            : [];
    }

    public Task<Version?> FindFirstPatchedVersionAsync(PackageId packageId,
        CancellationToken cancellationToken = default)
    {
        throw new NotImplementedException();
    }

    private async ValueTask<FrozenDictionary<string, Vulnerability[]>> GetVulnerabilityDataAsync(
        CancellationToken cancellationToken)
    {
        if (_vulnerabilityData is not null) return _vulnerabilityData;

        await _semaphore.WaitAsync(cancellationToken);
        try
        {
            _vulnerabilityData ??= await FetchVulnerabilitiesDataAsync(cancellationToken);
        }
        finally
        {
            _semaphore.Release();
        }

        return _vulnerabilityData;
    }

    private async Task<VulnerabilitiesIndex> FetchVulnerabilitiesIndexAsync(CancellationToken cancellationToken)
    {
        var entries = await httpClient.GetAsync(_nugetVulnerabilityIndexUrl,
            SourceGenerationContext.Default.VulnerabilitiesIndexEntryArray, cancellationToken);
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

    private async Task<FrozenDictionary<string, Vulnerability[]>> FetchVulnerabilitiesDataAsync(
        CancellationToken cancellationToken)
    {
        logger.LogInformation<NugetService>($"Fetching vulnerabilities data from {_nugetIndexUrl}.");

        var index = await FetchVulnerabilitiesIndexAsync(cancellationToken);

        var baseDataTask = httpClient.GetAsync(index.Base.Id,
            SourceGenerationContext.Default.DictionaryStringListVulnerabilityEntry, cancellationToken);
        var updateDataTask = httpClient.GetAsync(index.Update.Id,
            SourceGenerationContext.Default.DictionaryStringListVulnerabilityEntry, cancellationToken);
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