namespace VulneraNet.Core.Exceptions;

public class ProjectNotRestoredException(string projectName) : Exception(
    $"""
     'project.assets.json' file for project: '{projectName}' not found!
     Use '--restore' switch to automatically restore project or run 
     'nuget restore' or 'dotnet restore' manually on the project's solution before running this script.
     """);

public class ProjectAssetsFileParsingException() : Exception;