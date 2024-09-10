using System.IO.Abstractions;

namespace VulneraNet.Core.Domain.NetSolution;

public class Solution
{
    public IFileInfo File { get; }
    public IEnumerable<Project> Projects { get; private set; } = null!;

    private readonly IFileSystem _fileSystem;

    private Solution(string solutionPath, IFileSystem fileSystem)
    {
        _fileSystem = fileSystem;
        File = _fileSystem.FileInfo.New(solutionPath);
    }

    public static async Task<Solution> LoadAsync(string solutionPath, CancellationToken cancellationToken = default) =>
        await LoadAsync(solutionPath, new FileSystem(), cancellationToken);

    public static async Task<Solution> LoadAsync(string solutionPath, IFileSystem fileSystem,
        CancellationToken cancellationToken = default)
    {
        var solution = new Solution(solutionPath, fileSystem);
        solution.Projects = await solution.ParseSolutionFileAsync(cancellationToken);
        return solution;
    }

    private async Task<IEnumerable<Project>> ParseSolutionFileAsync(CancellationToken cancellationToken)
    {
        const string projectLineBegin = @"project(""";
        const string csprojExtension = ".csproj";

        var content = await _fileSystem.File.ReadAllLinesAsync(File.FullName, cancellationToken);
        var projectTasks = content
            .Where(IsProjectLine)
            .Where(HasCsprojPath)
            .Select(ParseProjectLine)
            .Select(projectPath =>
            {
                var fullPath = _fileSystem.Path.Join(File.Directory?.FullName, projectPath);
                return Project.LoadAsync(fullPath, this, _fileSystem, cancellationToken);
            });

        return await Task.WhenAll(projectTasks);

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