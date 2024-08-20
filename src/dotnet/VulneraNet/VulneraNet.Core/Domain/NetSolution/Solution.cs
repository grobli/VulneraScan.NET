using System.IO.Abstractions;

namespace VulneraNet.Core.Domain.NetSolution;

public class Solution
{
    public IFileInfo File { get; }
    public IAsyncEnumerable<Project> Projects { get; }

    private readonly IFileSystem _fileSystem;

    public Solution(string solutionPath, IFileSystem fileSystem)
    {
        _fileSystem = fileSystem;
        File = _fileSystem.FileInfo.New(solutionPath);
        Projects = ParseSolutionFileAsync();
    }

    public Solution(string solutionPath) : this(solutionPath, new FileSystem())
    {
    }

    private async IAsyncEnumerable<Project> ParseSolutionFileAsync()
    {
        const string projectLineBegin = @"project(""";
        const string csprojExtension = ".csproj";

        var content = await _fileSystem.File.ReadAllLinesAsync(File.FullName);
        var projectLines = content
            .Where(IsProjectLine)
            .Where(HasCsprojPath);

        foreach (var projectLine in projectLines)
        {
            var projectPath = ParseProjectLine(projectLine);
            var fullPath = _fileSystem.Path.Join(File.Directory?.FullName, projectPath);
            yield return await Project.LoadAsync(fullPath, this, _fileSystem);
        }

        yield break;

        static bool IsProjectLine(string line) =>
            line.StartsWith(projectLineBegin, StringComparison.InvariantCultureIgnoreCase);

        static bool HasCsprojPath(string line) =>
            line.Contains(csprojExtension, StringComparison.InvariantCultureIgnoreCase);

        static string ParseProjectLine(string line) => line
            .Split(',').Skip(1).First()
            .Split('{').First()
            .Replace("\"", "")
            .Trim();
    }
}