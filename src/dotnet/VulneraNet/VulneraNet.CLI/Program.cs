using Cocona;
using Cocona.Lite;
using VulneraNet.Core.Domain;
using VulneraNet.Core.Domain.NetSolution;
using VulneraNet.Core.Services;
using VulneraNet.Core.Services.Interfaces;
using VulneraNet.Core.Utilities;
using VulneraNet.Core.Utilities.Interfaces;


var builder = CoconaLiteApp.CreateBuilder();
builder.Services.AddSingleton<IResilientHttpClient, ResilientHttpClient>();
builder.Services.AddSingleton<INugetService, NugetService>();

var app = builder.Build();

app.AddCommand("scan", async ([Argument] string package, INugetService nugetService) =>
{
    var packageId = PackageId.Parse(package);
    var vulnerabilities = await nugetService.FindVulnerabilitiesAsync(packageId);
    foreach (var vulnerability in vulnerabilities)
    {
        Console.WriteLine(vulnerability);
    }

    return Task.CompletedTask;
});

app.AddCommand("solution",
    async ([Argument] string solutionPath, [Option("recurse", ['r'])] bool isRecursive, INugetService nugetService) =>
    {
        if (isRecursive)
        {
            var solutions = Directory.EnumerateFiles(solutionPath, "*.sln", SearchOption.AllDirectories)
                .Select(s => new Solution(s));
            var jobs = solutions.Select(Job).ToArray();
            await Task.WhenAll(jobs);
            return;
        }

        await Job(new Solution(solutionPath));
        return;

        async Task Job(Solution solution)
        {
            var tasks = new List<Task>();

            await foreach (var project in solution.Projects)
            {
                tasks.Add(PrintPackages(project));
            }

            await Task.WhenAll(tasks);
        }

        async Task PrintPackages(Project project)
        {
            Console.WriteLine(project);
            var packages = await project.GetPackagesAsync(nugetService);
            foreach (var package in packages)
            {
                Console.WriteLine($"{package} - is vulnerable: {package.IsVulnerable}");
            }

            Console.WriteLine();
        }
    });

app.AddCommand("breaker", () => { });

app.Run();