using System.Text.Json.Serialization;

namespace VulneraNet.Core.Domain.NetSolution.ProjectAssetsJson;

public class ProjectAssets
{
    [JsonPropertyName("targets")]
    public required Dictionary<string, Dictionary<string, TargetsEntry>> Targets { get; set; }
}