using System.Text.Json.Serialization.Metadata;

namespace VulneraNet.Core.Utilities.Interfaces;

public interface IResilientHttpClient
{
    Task<HttpResponseMessage> GetAsync(Uri uri, CancellationToken cancellationToken = default);
    Task<T> GetAsync<T>(Uri uri, JsonTypeInfo<T> jsonTypeInfo, CancellationToken cancellationToken = default);
}