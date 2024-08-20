using System.Text.Json.Serialization;

namespace VulneraNet.Core.Domain.NetSolution.ProjectAssetsJson;

public class TargetsEntry
{
    [JsonPropertyName("type")] public required string Type { get; set; }
    [JsonPropertyName("dependencies")] public Dictionary<string, string>? Dependencies { get; set; }
}