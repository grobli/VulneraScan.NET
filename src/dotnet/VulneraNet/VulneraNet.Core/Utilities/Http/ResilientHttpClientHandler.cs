using VulneraNet.Core.Utilities.Logging;

namespace VulneraNet.Core.Utilities.Http;

public class ResilientHttpClientHandler(ILoggerFactory loggerFactory) : HttpClientHandler
{
    public TimeSpan FirstRetryDelay { get; set; } = TimeSpan.FromSeconds(1);
    public int MaxRetries { get; set; } = 4;
    
    private readonly ILogger _logger = loggerFactory.GetLogger<ResilientHttpClientHandler>();
    
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        var retry = 0;
        HttpRequestException? lastException = null;
        while (retry < MaxRetries)
        {
            try
            {
                _logger.LogDebug($"{request.Method} {request.RequestUri}");
                var response = await base.SendAsync(request, cancellationToken);
                response.EnsureSuccessStatusCode();
                return response;
            }
            catch (HttpRequestException e)
            {
                lastException = e;
                var delay = GetDelay(retry++);
                _logger.LogError($"{request.Method} {request.RequestUri} failed. Retrying in {delay.Seconds} seconds...", e);
                await Task.Delay(delay, cancellationToken);
            }
        }
        
        throw new HttpRequestException($"{request.Method} {request.RequestUri} failed.", lastException);
    }
    
    private TimeSpan GetDelay(int retry) => FirstRetryDelay * Math.Pow(2, retry);
}