namespace VulneraNet.Core.Utilities.Logging;

public interface ILogger
{
    public Verbosity Verbosity { get; set; }

    public void LogInformation(string message);
    public void LogInformation<T>(string message) where T : class;
    public void LogDebug(string message);
    public void LogDebug<T>(string message) where T : class;
    public void LogError(string message, Exception? exception = null);
    public void LogError<T>(string message, Exception? exception = null) where T : class;
    public void LogWarning(string message);
    public void LogWarning<T>(string message) where T : class;
}