using System.Text.Json.Serialization;

namespace VulneraNet.Core.Domain.NuGet.Vulnerabilities;

public class VulnerabilitiesIndex
{
    public required VulnerabilitiesIndexEntry Base { get; set; }
    public required VulnerabilitiesIndexEntry Update { get; set; }
}

public class VulnerabilitiesIndexEntry
{
    [JsonPropertyName("@name")] public required string Name { get; set; }
    [JsonPropertyName("@id")] public required Uri Id { get; set; }
    [JsonPropertyName("@updated")] public required DateTime Updated { get; set; }
}