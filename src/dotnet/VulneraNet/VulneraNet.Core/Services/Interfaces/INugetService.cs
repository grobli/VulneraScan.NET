using VulneraNet.Core.Domain;

namespace VulneraNet.Core.Services.Interfaces;

public interface INugetService
{
    Task<IEnumerable<Vulnerability>> FindVulnerabilitiesAsync(PackageId packageId);
    Task<Version?> FindFirstPatchedVersionAsync(PackageId packageId);
}