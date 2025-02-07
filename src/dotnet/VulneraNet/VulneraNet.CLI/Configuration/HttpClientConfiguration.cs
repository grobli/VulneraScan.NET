using System.Net;
using Cocona;
using Cocona.Lite;
using VulneraNet.Core.Utilities.Http;
using VulneraNet.Core.Utilities.Logging;

namespace VulneraNet.CLI.Configuration;

public static class HttpClientConfiguration
{
    public static ICoconaLiteServiceCollection AddHttpClient(this ICoconaLiteServiceCollection services)
    {
        services.TryAddSingleton<HttpClient>(provider =>
        {
            var loggerFactory = provider.GetRequiredService<ILoggerFactory>();

            var handler = new ResilientHttpClientHandler(loggerFactory)
            {
                AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate,
            };
            var httpClient = new HttpClient(handler);
            httpClient.DefaultRequestHeaders.Add("Accept", "application/json");
            httpClient.DefaultRequestHeaders.Add("Accept-Encoding", "gzip, deflate");

            return httpClient;
        });
        
        return services;
    }
}