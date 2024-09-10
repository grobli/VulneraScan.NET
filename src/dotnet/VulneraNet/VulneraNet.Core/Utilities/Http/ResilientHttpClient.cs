using System.Net;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;
using VulneraNet.Core.Exceptions;
using VulneraNet.Core.Utilities.Logging;

namespace VulneraNet.Core.Utilities.Http;

public class ResilientHttpClient(ILogger logger) : IResilientHttpClient
{
    public TimeSpan FirstRetryDelay { get; set; } = TimeSpan.FromSeconds(1);
    public int MaxRetries { get; set; } = 5;

    private readonly HttpClient _httpClient = CreateHttpClient();

    public async Task<HttpResponseMessage> GetAsync(Uri uri, CancellationToken cancellationToken = default)
    {
        var retry = 0;
        while (retry < MaxRetries)
        {
            try
            {
                logger.LogDebug<ResilientHttpClient>($"GET {uri}");
                return await MakeGetRequestAsync(uri, cancellationToken);
            }
            catch (HttpRequestException e)
            {
                var delay = GetDelay(retry++);
                logger.LogError<ResilientHttpClient>($"GET {uri} failed. Retrying in {delay} ms.", e);
                await Task.Delay(delay, cancellationToken);
            }
        }

        throw new ResilientHttpClientException($"HTTP GET: {uri} - Failed after {MaxRetries} retries");
    }

    public async Task<T> GetAsync<T>(Uri uri, JsonTypeInfo<T> jsonTypeInfo,
        CancellationToken cancellationToken = default)
    {
        var response = await GetAsync(uri, cancellationToken);
        var content = await response.Content.ReadAsStreamAsync(cancellationToken);
        var deserialized = await JsonSerializer.DeserializeAsync(content, jsonTypeInfo, cancellationToken);
        return deserialized!;
    }

    private async Task<HttpResponseMessage> MakeGetRequestAsync(Uri uri, CancellationToken cancellationToken) =>
        await _httpClient.GetAsync(uri, cancellationToken);

    private TimeSpan GetDelay(int retry) => FirstRetryDelay * Math.Pow(2, retry);

    private static HttpClient CreateHttpClient()
    {
        var handler = new HttpClientHandler
        {
            AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate,
        };
        var httpClient = new HttpClient(handler);
        httpClient.DefaultRequestHeaders.Add("Accept", "application/json");
        httpClient.DefaultRequestHeaders.Add("Accept-Encoding", "gzip, deflate");
        return httpClient;
    }
}