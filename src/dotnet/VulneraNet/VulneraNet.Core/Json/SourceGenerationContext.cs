using System.Text.Json.Serialization;
using VulneraNet.Core.Domain.NetSolution.ProjectAssetsJson;
using VulneraNet.Core.Domain.NuGet.Vulnerabilities;

namespace VulneraNet.Core.Json;

[JsonSourceGenerationOptions(WriteIndented = true, GenerationMode = JsonSourceGenerationMode.Metadata)]
[JsonSerializable(typeof(VulnerabilitiesIndex))]
[JsonSerializable(typeof(VulnerabilitiesIndexEntry[]))]
[JsonSerializable(typeof(ProjectAssets))]
[JsonSerializable(typeof(Dictionary<string, List<VulnerabilityEntry>>))]
internal partial class SourceGenerationContext : JsonSerializerContext;
