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
builder.Services.AddSingleton<INugetService>(provider =>
{
    var httpClient = provider.GetRequiredService<IResilientHttpClient>();
    var context = provider.GetRequiredService<CoconaAppContext>();
    return NugetService.Create(httpClient, context.CancellationToken);
});

var app = builder.Build();

app.AddCommand("scan", async (CoconaAppContext context, [Argument] string package, INugetService nugetService) =>
{
    var packageId = PackageId.Parse(package);
    var vulnerabilities = await nugetService.FindVulnerabilitiesAsync(packageId, context.CancellationToken);
    foreach (var vulnerability in vulnerabilities)
    {
        Console.WriteLine(vulnerability);
    }

    return Task.CompletedTask;
});

app.AddCommand("solution",
        async (CoconaAppContext context,
            [Argument] string solutionPath, [Option("recurse", ['r'])] bool isRecursive,
            INugetService nugetService) =>
        {
            if (isRecursive)
            {
                var solutions = Directory.EnumerateFiles(solutionPath, "*.sln", SearchOption.AllDirectories)
                    .Select(s => new Solution(s));
                var jobs = solutions.Select(s => Job(s, context.CancellationToken)).ToArray();
                await Task.WhenAll(jobs);
                return;
            }

            await Job(new Solution(solutionPath), context.CancellationToken);
            return;

            async Task Job(Solution solution, CancellationToken cancellationToken)
            {
                var tasks = new List<Task>();

                await foreach (var project in solution.Projects)
                {
                    tasks.Add(PrintPackages(project, cancellationToken));
                }

                await Task.WhenAll(tasks);
            }

            async Task PrintPackages(Project project, CancellationToken cancellationToken)
            {
                Console.WriteLine(project);
                var packages = await project.GetPackagesAsync(nugetService, cancellationToken);
                foreach (var package in packages)
                {
                    Console.WriteLine($"{package} - is vulnerable: {package.IsVulnerable}");
                }

                Console.WriteLine();
            }
        })
    .WithFilter(async (context, @delegate) =>
    {
        try
        {
            return await @delegate(context);
        }
        catch (TaskCanceledException _)
        {
            Console.WriteLine("Operation cancelled");
            return 1;
        }
    });

app.AddCommand("breaker", () => { });

app.Run();