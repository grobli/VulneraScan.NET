namespace VulneraNet.Core.Utilities.Logging;

public class Logger : ILogger
{
    private readonly object _lock = new();

    public Verbosity Verbosity { get; set; } = Verbosity.Info;

    public void LogInformation(string message)
    {
        Log(message, Verbosity.Info, string.Empty, ConsoleColor.Blue);
    }

    public void LogInformation<T>(string message) where T : class
    {
        Log(message, Verbosity.Info, typeof(T).Name, ConsoleColor.Blue);
    }

    public void LogDebug(string message)
    {
        Log(message, Verbosity.Debug, string.Empty, ConsoleColor.DarkGray);
    }

    public void LogDebug<T>(string message) where T : class
    {
        Log(message, Verbosity.Debug, typeof(T).Name, ConsoleColor.DarkGray);
    }

    public void LogError(string message, Exception? exception = null)
    {
        Log(message, Verbosity.Error, string.Empty, ConsoleColor.Red);
        if (exception != null) Log(exception.Message, Verbosity.Error, string.Empty, ConsoleColor.Red);
    }

    public void LogError<T>(string message, Exception? exception = null) where T : class
    {
        Log(message, Verbosity.Error, typeof(T).Name, ConsoleColor.Red);
        if (exception != null) Log(exception.Message, Verbosity.Error, typeof(T).Name, ConsoleColor.Red);
    }

    public void LogWarning(string message)
    {
        Log(message, Verbosity.Warning, string.Empty, ConsoleColor.Yellow);
    }

    public void LogWarning<T>(string message) where T : class
    {
        Log(message, Verbosity.Warning, typeof(T).Name, ConsoleColor.Yellow);
    }

    private void Log(string message, Verbosity logLevel, string context, ConsoleColor logLevelColor)
    {
        if (Verbosity > logLevel) return;

        lock (_lock)
        {
            Write(logLevel.ToString(), logLevelColor);
            if (!string.IsNullOrWhiteSpace(context))
            {
                Write(" [", ConsoleColor.White);
                Write(context);
                Write("]", ConsoleColor.White);
            }

            WriteLine($" : {message}");
        }
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