using VulneraNet.Core.Domain;

namespace VulneraNet.Core.Services.Interfaces;

public interface INugetService
{
    Task<IEnumerable<Vulnerability>> FindVulnerabilitiesAsync(PackageId packageId, CancellationToken cancellationToken = default);
    Task<Version?> FindFirstPatchedVersionAsync(PackageId packageId, CancellationToken cancellationToken = default);
}