using System.Diagnostics;
using Cocona;
using Cocona.Lite;
using VulneraNet.Core.Domain;
using VulneraNet.Core.Domain.NetSolution;
using VulneraNet.Core.Services;
using VulneraNet.Core.Services.Interfaces;
using VulneraNet.Core.Utilities.Http;
using VulneraNet.Core.Utilities.Logging;

var builder = CoconaLiteApp.CreateBuilder(args, options => options.EnableShellCompletionSupport = true);
builder.Services.AddSingleton<IResilientHttpClient, ResilientHttpClient>();
builder.Services.AddSingleton<INugetService, NugetService>();
builder.Services.AddSingleton<ILogger, Logger>();

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
            INugetService nugetService, ILogger logger) =>
        {
            var watch = new Stopwatch();
            watch.Start();
            
            if (isRecursive)
            {
                var solutionTasks = Directory.EnumerateFiles(solutionPath, "*.sln", SearchOption.AllDirectories)
                    .Select(s => Solution.LoadAsync(s, context.CancellationToken));
                var solutions = await Task.WhenAll(solutionTasks);
                var jobs = solutions.Select(s => Job(s, context.CancellationToken)).ToArray();
                await Task.WhenAll(jobs);
                watch.Stop();
                logger.LogInformation($"Execution time was: {watch.Elapsed.TotalSeconds:F} seconds.");
                return;
            }

            var solution = await Solution.LoadAsync(solutionPath, context.CancellationToken);
            await Job(solution, context.CancellationToken);
            watch.Stop();
            logger.LogInformation($"Execution time was: {watch.Elapsed.TotalSeconds:F} seconds.");
            return;

            async Task Job(Solution sln, CancellationToken cancellationToken)
            {
                var tasks = sln.Projects.Select(project => PrintPackages(project, cancellationToken));
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
    .WithFilter(async (context, next) =>
    {
        try
        {
            return await next(context);
        }
        catch (TaskCanceledException)
        {
            Console.WriteLine("Operation cancelled");
            return 1;
        }
    });

app.AddCommand("breaker", () => { });

app.Run();