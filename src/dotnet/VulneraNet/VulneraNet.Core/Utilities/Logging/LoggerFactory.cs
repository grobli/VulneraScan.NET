using System.Collections.Concurrent;

namespace VulneraNet.Core.Utilities.Logging;

public interface ILoggerFactory
{
    public ILogger GetLogger<T>() where T : class;
}

public class LoggerFactory : ILoggerFactory
{
    private readonly ConcurrentDictionary<string, ILogger> _loggerPool = new();

    public ILogger GetLogger<T>() where T : class 
    {
        var typeName = typeof(T).Name;
        if (_loggerPool.TryGetValue(typeName, out var logger)) 
        {
            return logger;
        }
        logger = new Logger<T>();
        _loggerPool[typeName] = logger;
        return logger;
    }
}