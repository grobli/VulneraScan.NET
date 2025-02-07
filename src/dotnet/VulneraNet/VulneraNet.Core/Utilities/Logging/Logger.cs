namespace VulneraNet.Core.Utilities.Logging;

public interface ILogger
{
    void LogInformation(string message);
    void LogDebug(string message);    
    void LogError(string message, Exception? exception = null);
    void LogWarning(string message);
}

public static class LoggerGlobalSettings
{
    public static Verbosity Verbosity { get; set; } = Verbosity.Info;
}

public class Logger<T> : ILogger
{
    public Verbosity Verbosity { get; set; } = LoggerGlobalSettings.Verbosity;

    internal Logger()
    {
    }

    public void LogInformation(string message)
    {
        Log(message, Verbosity.Info, typeof(T).Name, ConsoleColor.Blue);
    }

    public void LogDebug(string message)
    {
        Log(message, Verbosity.Debug, typeof(T).Name, ConsoleColor.DarkGray);
    }

    public void LogError(string message, Exception? exception = null)
    {
        Log(message, Verbosity.Error, typeof(T).Name, ConsoleColor.Red);
        if (exception != null) Log(exception.Message, Verbosity.Error, typeof(T).Name, ConsoleColor.Red);
    }

    public void LogWarning(string message)
    {
        Log(message, Verbosity.Warning, typeof(T).Name, ConsoleColor.Yellow);
    }

    private void Log(string message, Verbosity logLevel, string context, ConsoleColor logLevelColor)
    {
        if (Verbosity > logLevel) return;

        Write(logLevel.ToString(), logLevelColor);
        if (!string.IsNullOrWhiteSpace(context))
        {
            Write(" [", ConsoleColor.White);
            Write(context);
            Write("]", ConsoleColor.White);
        }

        if (logLevel == Verbosity.Error) WriteLine($" : {message}", ConsoleColor.Red);
        else WriteLine($" : {message}");
    }

    private static void Write(string text, ConsoleColor color)
    {
        Console.ForegroundColor = color;
        Console.Error.Write(text);
        Console.ResetColor();
    }

    private static void Write(string text)
    {
        Console.Error.Write(text);
    }

    private static void WriteLine(string text, ConsoleColor color)
    {
        Console.ForegroundColor = color;
        Console.Error.WriteLine(text);
        Console.ResetColor();
    }

    private static void WriteLine(string text)
    {
        Console.Error.WriteLine(text);
    }
}