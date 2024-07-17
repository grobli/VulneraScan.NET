<# 
.SYNOPSIS
    Performs vulnerability scan of NuGet packages in .NET solutions.
#>

#Requires -Version 5.1

#region Parameters
[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)][string]$SolutionPath,
    [Parameter()][ValidateSet('Json', 'Text')]$Format,
    [Parameter()][switch]$Recurse,
    [Parameter()][switch]$BuildBreaker,
    [Parameter()][ValidateSet('Low', 'Moderate', 'High', 'Critical')]$MinimumBreakLevel = 'Low',
    [Parameter()][ValidateSet('All', 'Legacy', 'Modern')]$BreakOnProjectType = 'All',
    [Parameter()][switch]$FindPatchedOnline,
    [Parameter()][ValidateSet('All', 'Legacy', 'Modern')]$ProjectsToScan = 'All',
    [Parameter()][switch]$Restore,
    [Parameter()][ValidateSet('OnDemand', 'Always', 'Force')]$RestoreActionPreference = 'OnDemand',
    [Parameter()][ValidateSet('Dotnet', 'Nuget')]$RestoreToolPreference = 'Dotnet',
    [Parameter()][int]$RestoreMaxParallelism = 0,
    [Parameter()][switch]$OnlyProjectsWithVulnerabilities,
    [Parameter()][switch]$Minimal
)
#endregion

#region GlobalVariables
[bool]$IsNugetExeAvailable = $false
[bool]$IsDotnetExeAvailable = $false 

if ($Restore) {
    try {
        nuget.exe help | Out-Null
        $IsNugetExeAvailable = $LASTEXITCODE -eq 0 
    }
    catch {
        Write-Warning -Message "nuget.exe not found in system PATH"
    }
    
    try {
        dotnet.exe --info | Out-Null
        $IsDotnetExeAvailable = $LASTEXITCODE -eq 0
    }
    catch {
        Write-Warning -Message "dotnet.exe not found in system PATH"
    }
}
#endregion
    
#region DataClasses
enum Severity {
    Low = 0
    Moderate = 1
    High = 2
    Critical = 3
    None = 4
}

#region Vulnerability
class Vulnerability {
    [string]$AdvisoryUrl
    [Severity]$Severity
    [VersionRange]$VersionRange
    [string]$GhsaId
    
    Vulnerability([int]$severity, [string]$url, [VersionRange]$vrange) {
        $this.Severity = $severity
        $this.AdvisoryUrl = $url
        $lastIndexOfUriSeparator = $this.AdvisoryUrl.LastIndexOf('/') + 1
        $this.GhsaId = $this.AdvisoryUrl.Substring($lastIndexOfUriSeparator)
        $this.VersionRange = $vrange
    }

    [string]ToString() {
        return $this.GhsaId
    }
}
#endregion

#region SolutionAuditPlural
class SolutionAuditPlural {
    [SolutionAudit[]]$Solutions
    [SolutionAuditVulnerabilityCount]$VulnerabilityCount
    [PackageAudit[]]$VulnerablePackages

    SolutionAuditPlural([SolutionAudit[]]$solutions) {
        $counts = $solutions | Select-Object -ExpandProperty VulnerabilityCount
        $this.Solutions = $solutions | Sort-Object -Property SolutionName
        $this.VulnerabilityCount = [SolutionAuditVulnerabilityCount]::SumCounts($counts)
        $this.VulnerablePackages = $this.FindUniqueVulnerablePackages()
    }

    hidden [PackageAudit[]]FindUniqueVulnerablePackages() {
        $packages = @($this.Solutions.VulnerablePackages | Where-Object { $_ })
        if ($packages.Count -eq 0) {
            return @()
        }
        $distinctPackages = [System.Collections.Generic.SortedDictionary[string, PackageAudit]]::new()
        foreach ($package in $packages) {
            if (!$distinctPackages.ContainsKey($package.PackageId)) {
                $distinctPackages[$package.PackageId] = $package
            }
        }
        return $distinctPackages.Values
    }
}
#endregion
    
#region SolutionAudit
class SolutionAudit {
    [string]$SolutionName
    [SolutionAuditVulnerabilityCount]$VulnerabilityCount
    [ProjectAudit[]]$Projects
    [string]$SolutionPath
    [PackageAudit[]]$VulnerablePackages
    
    SolutionAudit([System.IO.FileInfo]$solutionFile, [ProjectAudit[]]$legacyAudits, [ProjectAudit[]]$audits) {
        $this.SolutionPath = $solutionFile.FullName
        $this.SolutionName = $solutionFile.BaseName
        $this.Projects = ($audits + $legacyAudits) | Sort-Object -Property ProjectName
        $this.VulnerabilityCount = [SolutionAuditVulnerabilityCount]::new($legacyAudits, $audits)
        $this.VulnerablePackages = $this.FindUniqueVulnerablePackages()
    }

    hidden [PackageAudit[]]FindUniqueVulnerablePackages() {
        $packages = @($this.Projects.VulnerablePackages | Where-Object { $_ })
        if ($packages.Count -eq 0) {
            return @()
        }
        $distinctPackages = [System.Collections.Generic.SortedDictionary[string, PackageAudit]]::new()
        foreach ($package in $packages) {
            if (!$distinctPackages.ContainsKey($package.PackageId)) {
                $distinctPackages[$package.PackageId] = $package
            }
        }
        return $distinctPackages.Values
    }
}
#endregion
    
#region ProjectAudit
class ProjectAudit {
    [string]$ProjectName
    [VulnerabilityCount]$VulnerabilityCount
    [PackageAudit[]]$VulnerablePackages
    [PackageAudit[]]$PackagesWithVulnerableDependencies
    [PackageAudit[]]$VulnerableDirectPackages
    [string]$ProjectPath
    [string]$ProjectType
    
    ProjectAudit([Project]$project, [PackageAudit[]]$audits) {
        $this.ProjectName = $project.File.BaseName
        $this.ProjectPath = $project.File.FullName
        $this.ProjectType = if ($project.IsLegacy) { 'Legacy' } else { 'Modern' }
        $this.VulnerablePackages = $audits `
        | Where-Object { $_.VulnerabilityCount.Total -gt 0 } `
        | Sort-Object -Property PackageName
        $this.PackagesWithVulnerableDependencies = $audits `
        | Where-Object { $_.VulnerableDependencies.Count -gt 0 } `
        | Sort-Object -Property PackageName 
        $this.VulnerableDirectPackages = $audits `
        | Where-Object { !$_.IsTransitive } `
        | Sort-Object -Property PackageName
        $counts = $audits | Select-Object -ExpandProperty VulnerabilityCount
        $this.VulnerabilityCount = [VulnerabilityCount]::SumCounts($counts)
    }
}
#endregion

#region PackageAudit
class PackageAudit {
    [string]$PackageId
    [string]$PackageName
    [string]$PackageVersion
    [string]$FirstPatchedVersion
    [Severity]$HighestSeverity
    [VulnerabilityCount]$VulnerabilityCount
    [Vulnerability[]]$Vulnerabilities
    [string[]]$DependentPackages
    [string[]]$VulnerableDependencies
    [bool]$IsTransitive

    PackageAudit([Package]$package) {
        $this.PackageId = $package.Id.ToString()
        $this.PackageName = $package.Id.Name
        $this.PackageVersion = $package.Id.Version
        $this.Vulnerabilities = $package.Vulnerabilities | Sort-Object -Property Severity -Descending
        $this.FirstPatchedVersion = $this.GetPatchedVersion()
        $this.VulnerabilityCount = [VulnerabilityCount]::Create($this.Vulnerabilities)
        $this.HighestSeverity = $this.VulnerabilityCount.GetHighestSeverity()
        $this.DependentPackages = $package.Dependants | ForEach-Object { $_.Id.ToString() }
        $this.VulnerableDependencies = $package.Dependencies | Where-Object { $_.IsVulnerable() -or $_.HasVulnerableDependencies }
        $this.IsTransitive = $package.IsTransitive()
    }

    hidden [string]GetPatchedVersion() {
        $versions = $this.Vulnerabilities `
        | Where-Object { !$_.VersionRange.IsMaxInclusive } `
        | ForEach-Object {
            $_.VersionRange.Max
        }
        if (!$versions) {
            return $null
        }
        $maxPatchedVersion = ($versions | Sort-Object -Descending)[0]
        # check if there is any uncertain version that is higher than inferred max patched version from Version Ranges
        foreach ($vln in  @($this.Vulnerabilities | Where-Object { $_.VersionRange.IsMaxInclusive })) {
            if ($vln.VersionRange.Max -gt $maxPatchedVersion) {
                return $null
            }
        }
        return $maxPatchedVersion
    }

    [string]ToString() {
        return $this.PackageId
    }
}
#endregion
    
#region VulnerabilityCount
class VulnerabilityCount {
    [int]$Total
    [int]$Low
    [int]$Moderate
    [int]$High
    [int]$Critical

    hidden VulnerabilityCount() {}
    
    static [VulnerabilityCount]Create([Vulnerability[]]$vulnerabilities) {
        $count = [VulnerabilityCount]::new()
        $count.Total = $vulnerabilities.Count
        $count.Low = ($vulnerabilities | Where-Object { $_.Severity -eq [Severity]::Low }).Count
        $count.Moderate = ($vulnerabilities | Where-Object { $_.Severity -eq [Severity]::Moderate }).Count
        $count.High = ($vulnerabilities | Where-Object { $_.Severity -eq [Severity]::High }).Count
        $count.Critical = ($vulnerabilities | Where-Object { $_.Severity -eq [Severity]::Critical }).Count
        return $count
    }
    
    static[VulnerabilityCount]SumCounts([VulnerabilityCount[]]$counts) {
        $count = [VulnerabilityCount]::new()
        $counts | ForEach-Object {
            $count.Total += $_.Total
            $count.Low += $_.Low
            $count.Moderate += $_.Moderate
            $count.High += $_.High
            $count.Critical += $_.Critical
        }
        return $count
    }

    [int]GetTotalFromLevel([Severity]$severityLevel) {
        if ($severityLevel -eq [Severity]::Low) { return $this.Total }
        if ($severityLevel -eq [Severity]::Moderate) { return $this.Moderate + $this.High + $this.Critical }
        if ($severityLevel -eq [Severity]::High) { return $this.High + $this.Critical }
        return $this.Critical
    }

    [Severity]GetHighestSeverity() {
        if ($this.Total -eq 0 ) {
            return [Severity]::None
        }
        if ( $this.Critical -gt 0 ) {
            return [Severity]::Critical
        }
        if ($this.High -gt 0) {
            return [Severity]::High
        }
        if ($this.Moderate -gt 0) {
            return [Severity]::Moderate 
        }
        return [Severity]::Low
    }
    
    [string]ToString() {
        $totalVal = $this.Total
        $lowVal = $this.Low
        $moderateVal = $this.Moderate
        $highVal = $this.High
        $criticalVal = $this.Critical
        return "$totalVal (L:$lowVal M:$moderateVal H:$highVal C:$criticalVal)"
    }
}
#endregion

#region SolutionAuditVulnerabilityCount
class SolutionAuditVulnerabilityCount {
    [VulnerabilityCount]$All
    [VulnerabilityCount]$Modern
    [VulnerabilityCount]$Legacy

    hidden SolutionAuditVulnerabilityCount() {}

    SolutionAuditVulnerabilityCount([ProjectAudit[]]$legacyProjectAudits, [ProjectAudit[]]$modernProjectAudits) {
        $modernCounts = $modernProjectAudits | Select-Object -ExpandProperty VulnerabilityCount
        $legacyCounts = $legacyProjectAudits | Select-Object -ExpandProperty VulnerabilityCount
        $this.Modern = [VulnerabilityCount]::SumCounts($modernCounts)
        $this.Legacy = [VulnerabilityCount]::SumCounts($legacyCounts)
        $allCounts = $($this.Modern; $this.Legacy)
        $this.All = [VulnerabilityCount]::SumCounts($allCounts)
    }

    static[SolutionAuditVulnerabilityCount]SumCounts([SolutionAuditVulnerabilityCount[]]$counts) {
        $count = [SolutionAuditVulnerabilityCount]::new()
        $allCounts = $counts | Select-Object -ExpandProperty All
        $legacyCounts = $counts | Select-Object -ExpandProperty Legacy
        $modernCounts = $counts | Select-Object -ExpandProperty Modern

        $count.All = [VulnerabilityCount]::SumCounts($allCounts)
        $count.Legacy = [VulnerabilityCount]::SumCounts($legacyCounts)
        $count.Modern = [VulnerabilityCount]::SumCounts($modernCounts)
        return $count
    }

    [string]ToString() {
        $allVal = $this.All
        $legacyVal = $this.Legacy
        $modernVal = $this.Modern
        return "$allVal (Legacy: $legacyVal | Modern: $modernVal)"
    }
}
#endregion
#endregion

#region Solution
class Solution {
    [System.IO.FileInfo]$File
    [Project[]]$LegacyProjects
    [Project[]]$ModernProjects

    hidden static $ProjectLineBegin = 'project("'
    hidden static $CsprojExtension = '.csproj'

    Solution() {}

    static [Solution]Parse([System.IO.FileInfo]$solutionFile) {
        $solution = [Solution]::new()
        $solution.File = $solutionFile
        $content = [System.IO.File]::ReadAllLines($solutionFile.FullName)
        $solutionDir = $solutionFile.Directory.FullName
        $projs = $content `
        | Where-Object { [Solution]::IsProjectLine($_) -and [Solution]::HasCsprojPath($_) } `
        | ForEach-Object { 
            ($name, $path) = $_.Split(',')
            ($path, $guid) = $path.Split('{')
            $path = $path.Replace('"', '').Trim()
            $path = Join-Path -Path $solutionDir -ChildPath $path
            [Project]::new($path, $solutionFile.FullName)
        }
        if (!$projs) { $projs = @() }
        $solution.ModernProjects = @($projs | Where-Object { -not $_.IsLegacy })
        $solution.LegacyProjects = @($projs | Where-Object { $_.IsLegacy })
        return $solution
    }

    hidden static [bool]IsProjectLine([string]$line) {
        return $line.StartsWith([Solution]::ProjectLineBegin, [System.StringComparison]::InvariantCultureIgnoreCase)
    }

    hidden static [bool]HasCsprojPath([string]$line) {
        $line = $line.ToLowerInvariant()
        return $line.Contains([Solution]::CsprojExtension)
    }
}
#endregion

#region Project
class Project {
    [System.IO.FileInfo]$File
    [System.IO.FileInfo]$Solution
    [bool]$IsLegacy
    hidden [System.IO.FileInfo]$PackagesConfigFile

    Project([string]$projectPath, [string]$solutionPath) {
        $this.File = $projectPath
        $this.Solution = $solutionPath
        $this.PackagesConfigFile = $this.GetPackagesConfig()
        $this.IsLegacy = !$this.IsSdkStyle()
    }

    [Package[]]GetPackages() {
        [Package[]]$packages = if ($this.IsLegacy) { $this.ReadPackagesConfig() } 
        else { $this.ReadProjectAssetsJson() }
        return $packages
    }

    [Package[]]GetPackages([NugetService]$nugetService) {
        $packageStore = [PackageStore]::new($nugetService)
        [Package[]]$packages = if ($this.IsLegacy) { $this.ReadPackagesConfig($packageStore) } 
        else { $this.ReadProjectAssetsJson($packageStore) }
        return $packages
    }

    [System.IO.FileInfo]GetProjectAssetsJsonFile([bool]$failOnNotFound) {
        $path = Join-Path -Path $this.File.Directory.FullName -ChildPath 'obj\project.assets.json'
        try {
            return Get-Item -Path $path -ErrorAction Stop -Force
        }
        catch {
            if ($failOnNotFound) {
                throw "project.assets.json for project: '$this' not found! Use '-Restore' switch to automatically restore project or run manually 'nuget restore' or 'dotnet restore' on the project's solution before running this script."
            }
            return $null
        }
    }

    [string]ToString() {
        return $this.File.FullName
    }

    hidden [bool]IsSdkStyle() {
        $projectNode = [xml]([System.IO.File]::ReadAllText($this.File.FullName)) `
        | Select-Xml -XPath './Project' -ErrorAction SilentlyContinue `
        | Select-Object -ExpandProperty Node
        $sdkAttribute = $projectNode.Attributes | Where-Object { $_.Name -eq 'Sdk' }
        return $null -ne $sdkAttribute
    }

    hidden [Package[]]ReadPackagesConfig() {
        [Package[]]$packages = @()
        if (!$this.PackagesConfigFile) {
            return $packages
        }
        $ids = $this.ParsePackagesConfig()
        foreach ($id in $ids) {
            $packages += [Package]::new($id)
        }
        return $packages
    }
  
    hidden [Package[]]ReadPackagesConfig([PackageStore]$packageStore) {
        if (!$this.PackagesConfigFile) {
            return @()
        }
        foreach ($id in $this.ParsePackagesConfig()) {
            $packageStore.Add($id)
        }
        return $packageStore.GetAll()
    }

    hidden [PackageId[]]ParsePackagesConfig() {
        $ids = [xml]([System.IO.File]::ReadAllText($this.PackagesConfigFile.FullName)) `
        | Select-Xml -XPath './/package' `
        | Select-Object -ExpandProperty Node `
        | ForEach-Object { [PackageId]::Create($_.id, $_.version) }
        return $ids
    }

    hidden [Package[]]ReadProjectAssetsJson() {
        $entries = $this.ParseProjectAssetsJson()
        [Package[]]$packages = @()
        foreach ($entry in $entries) {
            $id = [PackageId]::Create($entry.Name)
            $packages += [Package]::new($id)
        }
        return $packages
    }

    hidden [Package[]]ReadProjectAssetsJson([PackageStore]$packageStore) {
        $entries = $this.ParseProjectAssetsJson()
        foreach ($entry in $entries) {
            $packageId = [PackageId]::Create($entry.Name)
            $packageStore.Add($packageId)
            if ($entry.Value.dependencies) {
                $dependencies = $entry.Value.dependencies.PSObject.Properties `
                | Select-Object -Property Name, Value `
                | ForEach-Object { [PackageId]::Create($_.Name, $_.Value) }
                $packageStore.SetDependencies($packageId, $dependencies)
            }
        }
        return $packageStore.GetAll()
    }

    hidden [PSCustomObject[]]ParseProjectAssetsJson() {
        $projectAssetsJsonFile = $this.GetProjectAssetsJsonFile($true)
        $projectAssetsText = [System.IO.File]::ReadAllText($projectAssetsJsonFile.FullName) 
        $projectAssetsParsed = $projectAssetsText | ConvertFrom-Json
        $targets = @($projectAssetsParsed.targets.PSObject.Properties)[0].Value.PSObject.Properties
        $entries = $targets `
        | Select-Object -Property Name, Value `
        | Where-Object { $_.Value.type -eq 'package' }
        return $entries
    }

    hidden [System.IO.FileInfo]GetPackagesConfig() {
        return Get-ChildItem -Path $this.File.Directory.FullName -Filter 'packages.config' -ErrorAction SilentlyContinue -Force
    }
}
#endregion

#region PackageId
class PackageId {
    [string]$Name
    [version]$Version
    hidden [string]$Value

    hidden static [System.Collections.Generic.Dictionary[string, PackageId]]$Cache = `
        [System.Collections.Generic.Dictionary[string, PackageId]]::new()

    static [PackageId]Create([string]$packageIdString) {
        $packageIdString = $packageIdString.Trim().ToLower()
        if ([PackageId]::Cache.ContainsKey($packageIdString)) {
            return [PackageId]::Cache[$packageIdString]
        }

        $packageId = [PackageId]::new($packageIdString)
        [PackageId]::Cache[$packageIdString] = $packageId
        return $packageId
    }

    static [PackageId]Create([string]$name, [string]$version) {
        $packageIdString = $name + '/' + $version
        return [PackageId]::Create($packageIdString)
    }

    hidden PackageId([string]$packageIdString) {
        ($n, $v) = $packageIdString.Split('/')
        $this.Name = $n
        $this.Version = [VersionConverter]::Convert($v)
        $this.Value = $this.Name + '/' + $this.Version.ToString()
    }

    [int]GetHashCode() {
        return $this.Value.GetHashCode()
    }

    [bool]Equals($obj) {
        if ($obj -is [PackageId]) {
            return $this.Value -eq ([PackageId]$obj).Value
        }
        return $false
    }

    [string]ToString() {
        return $this.Value
    }
}
#endregion

#region Package
class Package {
    [PackageId]$Id
    [Vulnerability[]]$Vulnerabilities = @()
    [Package[]]$Dependencies = @()
    [Package[]]$Dependants = @()
    [bool]$HasVulnerableDependencies

    Package([PackageId]$packageId) {
        $this.Id = $packageId
    }

    [bool]IsTransitive() {
        return $this.Dependants.Count -gt 0
    }

    [bool]IsVulnerable() {
        return $this.Vulnerabilities.Count -gt 0
    }

    [int]GetHashCode() {
        return $this.Id.GetHashCode()
    }

    [bool]Equals($obj) {
        if ($obj -is [Package]) {
            return $this.Id -eq ([Package]$obj).Id
        }
        return $false
    }

    [string]ToString() {
        return $this.Id
    }
}
#endregion

#region PackageStore
class PackageStore {
    hidden [System.Collections.Generic.Dictionary[string, Package]]$Store
    hidden [System.Collections.Generic.Dictionary[PackageId, PackageId[]]]$DependencyMapping

    hidden [NugetService]$NugetService
        
    PackageStore([NugetService]$nugetService) {
        $this.Store = [System.Collections.Generic.Dictionary[string, Package]]::new()
        $this.DependencyMapping = [System.Collections.Generic.Dictionary[PackageId, PackageId[]]]::new()
        $this.NugetService = $nugetService
    }

    [void]Add([PackageId]$packageId) {
        $package = [Package]::new($packageId)
        $this.Store[$packageId.Name] = $package
    }

    [void]SetDependencies([PackageId]$packageId, [PackageId[]]$dependencyIds) {
        $this.DependencyMapping[$packageId] = $dependencyIds
    }

    [Package[]]GetAll() {
        $packages = $this.Store.Values
        foreach ($package in $packages) {
            $this.SetupDependencies($package)
        }
        foreach ($package in $packages) {
            $this.FindVulnerabilities($package)
        }
        $this.PropagateVulnerableDependenciesFlag()
        return $packages
    }

    hidden [void]SetupDependencies([Package]$package) {
        $dependencyIds = $this.DependencyMapping[$package.Id]
        foreach ($depId in $dependencyIds) {
            $dep = $this.Store[$depId.Name]
            $package.Dependencies += $dep
            $dep.Dependants += $package
        }
    }

    hidden [void]PropagateVulnerableDependenciesFlag() {
        [System.Collections.Generic.Stack[Package]]$packagesWithVulnerableDeps = `
            [System.Collections.Generic.Stack[Package]]::new()
        foreach ($package in $this.Store.Values) {
            if ($package.HasVulnerableDependencies) {
                $packagesWithVulnerableDeps.Push($package)
            }
        }
        while ($packagesWithVulnerableDeps.Count -gt 0) {
            [Package]$package = $packagesWithVulnerableDeps.Pop()
            foreach ($dependant in $package.Dependants) {
                if (!$dependant.HasVulnerableDependencies) {
                    $dependant.HasVulnerableDependencies = $true
                    $packagesWithVulnerableDeps.Push($dependant)
                }
            }
        }
    }

    hidden [void]FindVulnerabilities([Package]$package) {
        $package.Vulnerabilities = $this.NugetService.FindVulnerabilities($package.Id)
        if ($package.IsVulnerable() -or $package.HasVulnerableDependencies) {
            foreach ($dependant in $package.Dependants) {
                $dependant.HasVulnerableDependencies = $true
            }
        }
    }
}
#endregion

#region ResilientHttpClient
class ResilientHttpClient {
    static [int]$FirstRetryDelayMillis = 500
    static [int]$MaxRetries = 5

    static [PSCustomObject]Get([uri]$url) {
        $retry = 0
        $maxRetryCount = [ResilientHttpClient]::MaxRetries
        while ($retry -lt $maxRetryCount) {
            try {
                return [ResilientHttpClient]::MakeGetRequest($url)
            }
            catch {
                $delay = [ResilientHttpClient]::GetDelay($retry++)
                Write-Warning -Message "HTTP GET: $url - Error - Retry in $delay ms. Retry $retry out of $maxRetryCount"
                Start-Sleep -Milliseconds $delay
            }
        }
        throw "HTTP GET: $url - Failed after $maxRetryCount retries"
    }

    hidden static [PSCustomObject]MakeGetRequest([uri]$url) {
        return Invoke-RestMethod -Method Get -Uri $url -UseBasicParsing -ErrorAction Stop
    }

    hidden static [int]GetDelay([int]$retry) {
        return [ResilientHttpClient]::FirstRetryDelayMillis * [math]::Pow(2, $retry)
    }
}
#endregion

#region AdvisoryService
class AdvisoryService {
    hidden [uri]$AuditoryUrl
    hidden [System.Collections.Generic.Dictionary[string, PSCustomObject]]$AdvisoriesCache

    AdvisoryService() {
        $this.AuditoryUrl = 'https://api.github.com/advisories/'
        $this.AdvisoriesCache = [System.Collections.Generic.Dictionary[string, PSCustomObject]]::new()
    }

    [version]FindPatchedVersion([Package]$package) {
        if (!$package.Vulnerabilities) { return $null }

        $patchedVersions = $package.Vulnerabilities | ForEach-Object {
            if ($this.AdvisoriesCache.ContainsKey($_.GhsaId)) {
                $advisoryData = $this.AdvisoriesCache[$_.GhsaId]
            }
            else {
                $url = [uri]::new($this.AuditoryUrl, $_.GhsaId)
                $advisoryData = [ResilientHttpClient]::Get($url)
                $this.AdvisoriesCache[$_.GhsaId] = $advisoryData
            }
            $advisoryData `
            | Select-Object -ExpandProperty vulnerabilities `
            | Where-Object { $_.package.ecosystem -eq 'nuget' } `
            | Select-Object -ExpandProperty first_patched_version `
            | ForEach-Object { [VersionConverter]::Convert($_) } `
        }
        $patchedVersions = @($patchedVersions | Where-Object { $_ -ge $package.Version } | Sort-Object)
        if ($patchedVersions) { return $patchedVersions[0] } # return lowest possible patched version
        return $null
    }
}
#endregion

#region NugetService
class NugetService {
    hidden [uri]$NugetVulnerabilityIndexUrl
    hidden [uri]$NugetIndexUrl
    hidden [System.Collections.Generic.Dictionary[string, Vulnerability[]]]$Base
    hidden [System.Collections.Generic.Dictionary[string, Vulnerability[]]]$Update
    hidden [System.Collections.Generic.Dictionary[string, PSCustomObject]]$MetadataCache

    NugetService() {
        $this.NugetVulnerabilityIndexUrl = 'https://api.nuget.org/v3/vulnerabilities/index.json'
        $this.NugetIndexUrl = 'https://api.nuget.org/v3/index.json'
        $this.MetadataCache = [System.Collections.Generic.Dictionary[string, PSCustomObject]]::new()

        $index = $this.FetchNugetIndex()
        $this.Base = $this.FetchVulnerabilityData($index.Base)
        $this.Update = $this.FetchVulnerabilityData($index.Update)
    }

    [Vulnerability[]]FindVulnerabilities([PackageId]$package) {
        $vBase = [NugetService]::SearchInVulnerabilityData($this.Base, $package)
        $vUpdate = [NugetService]::SearchInVulnerabilityData($this.Update, $package)
        [Vulnerability[]]$allVulnerabilities = $vBase + $vUpdate
        return $allVulnerabilities
    }
    
    hidden [PSCustomObject]FetchNugetIndex() {
        $index = [PSCustomObject]@{
            Base   = $null
            Update = $null
        }
        $response = [ResilientHttpClient]::Get($this.NugetVulnerabilityIndexUrl)
        $response | ForEach-Object {
            if ($_.'@name' -eq 'base') {
                $index.Base = $_.'@id'
                return
            }
            $index.Update = $_.'@id'
        }
        return $index
    }

    hidden [System.Collections.Generic.Dictionary[string, Vulnerability[]]]FetchVulnerabilityData([string]$indexEntry) {   
        $entriesDict = [System.Collections.Generic.Dictionary[string, Vulnerability[]]]::new()
        $response = [ResilientHttpClient]::Get($indexEntry)
        $response.PSObject.Properties `
        | Select-Object -Property Name, Value `
        | ForEach-Object {
            $entries = $_.Value | ForEach-Object {
                $vrange = [VersionRange]::Parse($_.versions)
                [Vulnerability]::new($_.severity, $_.url, $vrange)
            }
            $entriesDict[$_.Name] = $entries
        }
        return $entriesDict
    }

    hidden static [Vulnerability[]]SearchInVulnerabilityData([System.Collections.Generic.Dictionary[string, Vulnerability[]]]$data, [PackageId]$package) {
        if (!$data.ContainsKey($package.Name)) {
            return @()
        }
        $vulnerabilities = $data[$package.Name] `
        | Where-Object { $_.VersionRange.CheckInRange($package.Version) }
        return $vulnerabilities
    }
}
#endregion

#region VulnerabilityAuditorSettings
enum ProjectScanMode {
    All
    Modern
    Legacy
}

class VulnerabilityAuditorSettings {
    [bool]$FindPatchedOnline = $false
    [bool]$IncludeDependencies = $true
    [ProjectScanMode]$ScanMode = [ProjectScanMode]::All

    VulnerabilityAuditorSettings() {}
}
#endregion
    
#region VulnerabilityAuditor
class VulnerabilityAuditor {
    hidden [NugetService]$NugetService
    hidden [AdvisoryService]$AdvisoryService
    hidden [System.Collections.Generic.Dictionary[PackageId, PackageAudit]]$AuditWithVulnerabilitiesCache
    hidden [System.Collections.Generic.HashSet[PackageId]]$AuditNoVulnerableSet

    [VulnerabilityAuditorSettings]$Settings

    VulnerabilityAuditor([NugetService]$nugetService, [AdvisoryService]$advisoryService) {
        $this.NugetService = $nugetService
        $this.AdvisoryService = $advisoryService
        $this.AuditWithVulnerabilitiesCache = [System.Collections.Generic.Dictionary[PackageId, PackageAudit]]::new()
        $this.AuditNoVulnerableSet = [System.Collections.Generic.HashSet[PackageId]]::new()
        $this.Settings = [VulnerabilityAuditorSettings]::new()
    }

    [SolutionAudit]RunSolutionAudit([Solution]$solution) {
        $scanMode = $this.Settings.ScanMode
        if ($scanMode -eq [ProjectScanMode]::All) {
            return $this.RunAllSolutionAudit($solution)
        }
        if ($scanMode -eq [ProjectScanMode]::Modern) {
            return $this.RunModernSolutionAudit($solution)
        }
        return $this.RunLegacySolutionAudit($solution)
    }

    hidden [SolutionAudit]RunAllSolutionAudit([Solution]$solution) {
        [ProjectAudit[]]$legacyAudits = @()
        foreach ($project in $solution.LegacyProjects) {
            $legacyAudits += $this.RunProjectAudit($project) 
        }
        [ProjectAudit[]]$modernAudits = @()
        foreach ($project in $solution.ModernProjects) {
            $modernAudits += $this.RunProjectAudit($project)
        }
        return [SolutionAudit]::new($solution.File, $legacyAudits, $modernAudits)
    }

    hidden [SolutionAudit]RunModernSolutionAudit([Solution]$solution) {
        [ProjectAudit[]]$modernAudits = @()
        foreach ($project in $solution.ModernProjects) {
            $modernAudits += $this.RunProjectAudit($project)
        }
        $solution.LegacyProjects | ForEach-Object {
            Write-Warning -Message "ProjectsToScan='Modern' - Ignoring legacy project: $_"
        }
        return [SolutionAudit]::new($solution.File, @(), $modernAudits)
    }

    hidden [SolutionAudit]RunLegacySolutionAudit([Solution]$solution) {
        [ProjectAudit[]]$legacyAudits = @()
        foreach ($project in $solution.LegacyProjects) {
            $legacyAudits += $this.RunProjectAudit($project) 
        }
        $solution.ModernProjects | ForEach-Object {
            Write-Warning -Message "ProjectsToScan='Legacy' - Ignoring modern project: $_"
        }
        return [SolutionAudit]::new($solution.File, $legacyAudits, @())
    }

    hidden [ProjectAudit]RunProjectAudit([Project]$project) {
        if ($this.Settings.IncludeDependencies) {
            [Package[]]$packages = $project.GetPackages($this.NugetService)
            [PackageAudit[]]$audits = @()
            foreach ($package in $packages) {
                if ($package.IsVulnerable() -or $package.HasVulnerableDependencies) {
                    $audit = $this.CreatePackageAudit($package)
                    $audits += $audit
                }
            }
            return [ProjectAudit]::new($project, $audits)
        }
        return $this.RunProjectAuditNoDeps($project)
    }

    hidden [ProjectAudit]RunProjectAuditNoDeps([Project]$project) {
        [Package[]]$packages = $project.GetPackages()
        [PackageAudit[]]$audits = @()
        foreach ($package in $packages) {
            if ($this.AuditNoVulnerableSet.Contains($package.Id)) {
                continue
            }
            if ($this.AuditWithVulnerabilitiesCache.ContainsKey($package.Id)) {
                $audits += $this.AuditWithVulnerabilitiesCache[$package.Id]
                continue
            }
            $package.Vulnerabilities = $this.NugetService.FindVulnerabilities($package.Id)
            if ($package.IsVulnerable()) {
                $audit = $this.CreatePackageAudit($package)
                $this.AuditWithVulnerabilitiesCache[$package.Id] = $audit
                $audits += $audit
            }
            else {
                $this.AuditNoVulnerableSet.Add($package.Id) 
            }
        }
        return [ProjectAudit]::new($project, $audits)

    }

    [PackageAudit]CreatePackageAudit([Package]$package) {
        $audit = [PackageAudit]::new($package)
        if ($this.Settings.FindPatchedOnline -and $package.IsVulnerable() -and -not $audit.FirstPatchedVersion) {
            $patchedVersion = $this.AdvisoryService.FindPatchedVersion($package)
            $audit.FirstPatchedVersion = $patchedVersion
        }
        return $audit
    }
}
#endregion
    
#region VersionRange
class VersionRange {
    [version]$Min
    [version]$Max
    [bool]$IsMinInclusive
    [bool]$IsMaxInclusive
    
    hidden static [version]$DefaultMin = [version]'0.0.0'
    hidden static [version]$DefaultMax = [version]'9999.9999.9999'
    hidden static [regex]$BracketRegex = [regex]::new("\(|\)|\[|\]", [System.Text.RegularExpressions.RegexOptions]::Compiled)
    hidden static $Cache = [System.Collections.Generic.Dictionary[string, VersionRange]]::new()

    VersionRange() {
        $this.Min = [VersionRange]::DefaultMin
        $this.Max = [VersionRange]::DefaultMax
        $this.IsMinInclusive = $false
        $this.IsMaxInclusive = $false
    }
    
    static [VersionRange]Parse([string]$rangeString) {
        $rangeString = $rangeString.Trim()
        if ([VersionRange]::Cache.ContainsKey($rangeString)) {
            return [VersionRange]::Cache[$rangeString]
        }
        $vrange = [VersionRange]::new()
        $vrange.IsMinInclusive = $rangeString.StartsWith('[')
        $vrange.IsMaxInclusive = $rangeString.EndsWith(']')
        ($minString, $maxString) = [VersionRange]::BracketRegex.Replace($rangeString, '').Split(',')
            
        # set Min version
        $minVersion = [VersionConverter]::Convert($minString)
        if ($minVersion) {
            $vrange.Min = $minVersion
        }
        # set Max version
        $maxVersion = [VersionConverter]::Convert($maxString)
        if ($maxVersion) {
            $vrange.Max = $maxVersion
        }

        [VersionRange]::Cache[$rangeString] = $vrange
        return $vrange     
    }
    
    [bool]CheckInRange([version]$version) {
        if ($version -gt $this.Min -and $version -lt $this.Max) {
            return $true
        }
        if ($this.Min.Equals($version)) {
            return $this.IsMinInclusive
        }
        if ($this.Max.Equals($version)) {
            return $this.IsMaxInclusive
        }
        return $false
    }
    
    [string]ToString() {
        $prefix = if ($this.IsMinInclusive) { '[' } else { '(' }
        $suffix = if ($this.IsMaxInclusive) { ']' } else { ')' }
        $minString = if ($this.Min.Equals([VersionRange]::DefaultMin)) { '' } else { $this.Min.ToString() }
        $maxString = if ($this.Max.Equals([VersionRange]::DefaultMax)) { '' } else { $this.Max.ToString() }
        return "$prefix$minString, $maxString$suffix"
    }
}
#endregion

#region VersionConverter
class VersionConverter {
    hidden static $Cache = [System.Collections.Generic.Dictionary[string, version]]::new()
    hidden static [regex]$Regex = [regex]::new("(\d+\.\d+\.\d+)", [System.Text.RegularExpressions.RegexOptions]::Compiled) 

    static [version]Convert([string]$versionString) {
        if ([VersionConverter]::Cache.ContainsKey($versionString)) {
            return [VersionConverter]::Cache[$versionString]
        }
        $match = [VersionConverter]::Regex.Match($versionString)
        [version]$version = $null
        if ($match.Success) {
            [version]$version = $match.Value
        }
        [VersionConverter]::Cache[$versionString] = $version
        return $version
    }
}
#endregion

#region JsonConverter
class JsonConverter {
    static [string]Convert([SolutionAudit]$solutionAudit) {
        return [JsonConverter]::Convert($solutionAudit, 3, $false)
    }

    static [string]Convert([SolutionAudit]$solutionAudit, [int]$vulnerablePackagesDepth, [bool]$vulnerablePackagesAsArray) {
        $nameJson = $solutionAudit.SolutionName | ConvertTo-Json
        if ($solutionAudit.Projects.Count -eq 1) {
            $projectAuditsJson = @($solutionAudit.Projects) | ConvertTo-Json -Depth 1 -WarningAction SilentlyContinue -Compress
            $projectAuditsJson = '[' + $projectAuditsJson + ']'
        }
        else {
            $projectAuditsJson = @($solutionAudit.Projects) | ConvertTo-Json -Depth 2 -WarningAction SilentlyContinue -Compress
            if (!$projectAuditsJson) { $projectAuditsJson = '[]' }
        }
        if ($vulnerablePackagesAsArray) {
            $vulnerablePackagesJson = @($solutionAudit.VulnerablePackages.Values) | ConvertTo-Json -Depth $vulnerablePackagesDepth `
                -WarningAction SilentlyContinue -Compress 
            if (!$vulnerablePackagesJson) {
                $vulnerablePackagesJson = '[]'
            }
        }
        else {
            $vulnerablePackagesJson = @($solutionAudit.VulnerablePackages) | ConvertTo-Json -Depth $vulnerablePackagesDepth `
                -WarningAction SilentlyContinue -Compress
        }
        $vulnerabilityCountJson = $solutionAudit.VulnerabilityCount | ConvertTo-Json -Compress
        $pathJson = $solutionAudit.SolutionPath | ConvertTo-Json
        $json = '{' + '"SolutionName":' + $nameJson + ',"VulnerabilityCount":' + $vulnerabilityCountJson + `
            ',"Projects":' + $projectAuditsJson + ',"SolutionPath":' + $pathJson + ',"VulnerablePackages":' + `
            $vulnerablePackagesJson + '}'
        return $json
    }

    static [string]Convert([SolutionAuditPlural]$solutionAuditPlural) {
        $solutionAuditJsons = $solutionAuditPlural.Solutions | ForEach-Object { 
            [JsonConverter]::Convert($_, 1, $true)
        }
        $solutionAuditJsons = '[' + [string]::Join(',', $solutionAuditJsons) + ']'
        $vulnerablePackagesJson = $solutionAuditPlural.VulnerablePackages | ConvertTo-Json -Depth 3 -WarningAction SilentlyContinue `
            -Compress
        $vulnerabilityCountJson = $solutionAuditPlural.VulnerabilityCount | ConvertTo-Json -Compress
        $json = '{' + '"Solutions":' + $solutionAuditJsons + ',"VulnerabilityCount":' + $vulnerabilityCountJson + `
            ',"VulnerablePackages":' + $vulnerablePackagesJson + '}'
        return $json
    }
}
#endregion

#region MainBlockFunctions
#region Format-AuditResult
function Format-AuditResult($AuditResult) { 
    if ($AuditResult -is [System.Collections.ICollection]) {
        $AuditResult = [SolutionAuditPlural]::new($AuditResult)
    }

    if ($Format -eq 'Json') {
        [JsonConverter]::Convert($AuditResult)
        return
    }

    if ($Format -eq 'Text') {
        if ($AuditResult -is [SolutionAuditPlural]) {
            $AuditResult | Select-Object -ExpandProperty Solutions | ForEach-Object {
                if (!$_.Projects) { return }
                Format-SolutionAuditAsText -SolutionAudit $_
                Write-Output "`n".PadRight(106, '#')
            }
            return
        }
        else {
            if (!$AuditResult.Projects) { return }
            Format-SolutionAuditAsText -SolutionAudit $AuditResult
            return
        }
    }
    
    $AuditResult
}
#endregion

#region Format-SolutionAuditAsText
function Format-SolutionAuditAsText([SolutionAudit]$SolutionAudit) {
    $SolutionAudit | Select-Object -Property SolutionName, SolutionPath | Format-Table
    Write-Output 'Vulnerability Count:'
    $SolutionAudit.VulnerabilityCount | Format-List
    $SolutionAudit.Projects | Where-Object { $_ } | ForEach-Object { Format-ProjectAuditAsText $_ }
    Write-Output "======= All Vulnerabilities Details ".PadRight(105, '=')
    Write-Output ''
    $SolutionAudit.VulnerablePackages | ForEach-Object {
        Format-PackageAuditAsText $_
    }
}
#endregion

#region Format-ProjectAuditAsText
function Format-ProjectAuditAsText([ProjectAudit]$ProjectAudit) {
    $name = $ProjectAudit.ProjectName
    Write-Output "======= $name ".PadRight(105, '=')
    ($ProjectAudit | Select-Object -Property VulnerabilityCount, ProjectType, ProjectPath | Format-List | Out-String).Trim()
    if ($ProjectAudit.VulnerablePackages) {
        $ProjectAudit.VulnerablePackages | Select-Object @{Name = 'Vulnerable Packages'; Expression = 'PackageId' } | Format-Table
    }
}
#endregion

#region Format-PackageAuditAsText
function Format-PackageAuditAsText([PackageAudit]$PackageAudit) {
    $id = $PackageAudit.PackageId
    Write-Output "_______ $id ".PadRight(105, '_')
    ($PackageAudit | Select-Object -Property PackageVersion, FirstPatchedVersion, VulnerabilityCount | Format-List | Out-String).Trim()
    $PackageAudit.Vulnerabilities | Select-Object -Property AdvisoryUrl, Severity | Format-List
}
#endregion

#region Invoke-ParallelRestore
function Invoke-ParallelRestore([Solution[]]$Solutions) {
    $cpuCount = (Get-CimInstance Win32_ComputerSystem).NumberOfLogicalProcessors
    $jobCount = if ($RestoreMaxParallelism -le 0) { $cpuCount } else { [math]::Min($cpuCount, $RestoreMaxParallelism) }
    $i = 0
    $batches = $Solutions `
    | ForEach-Object {
        [PSCustomObject]@{
            Solution = $_.File.FullName
            BatchId  = $i++ % $jobCount
        } `
    } `
    | Group-Object -Property BatchId

    $scriptBlock = {
        $ErrorActionPreference = $using:ErrorActionPreference
        $WarningPreference = $using:WarningPreference   
        $DebugPreference = $using:DebugPreference
        $VerbosePreference = $using:VerbosePreference
        $IsNugetExeAvailable = $using:IsNugetExeAvailable
        $IsDotnetExeAvailable = $using:IsDotnetExeAvailable
        $RestoreActionPreference = $using:RestoreActionPreference
        $RestoreToolPreference = $using:RestoreToolPreference

        #region Invoke-SolutionRestore
        function Invoke-SolutionRestore([System.IO.FileInfo]$TargetSolution) {
            $path = $TargetSolution.FullName
            if ($RestoreToolPreference -eq 'Nuget' -or -not $IsDotnetExeAvailable) {
                if ($IsNugetExeAvailable) {
                    $command = 'nuget.exe'
                    $params = 'restore', "$path", '-NonInteractive', '-Verbosity', 'quiet', $forceParam
                    if ($RestoreActionPreference -eq 'Force') { $params += '-Force' } 
                    Write-Verbose -Message "Executing command: $command $params"
                    & $command $params | Write-Verbose
                    if ($LASTEXITCODE -ne 0) {
                        Write-Error "$command $params - operation failed - process finished with exit code: $LASTEXITCODE"
                    }
                    return
                }
            }
            if ($IsDotnetExeAvailable) {
                $command = 'dotnet.exe'
                $params = 'restore', "$path", '--verbosity', 'quiet', $forceParam
                if ($RestoreActionPreference -eq 'Force') { $params += '--force' }
                Write-Verbose -Message "Executing command: $command $params"
                & $command $params | Write-Verbose
                if ($LASTEXITCODE -ne 0) {
                    Write-Error "$command $params - operation failed - process finished with exit code: $LASTEXITCODE"
                }
                return
            }
            throw "No tool for performing the NuGet restore is available on the machine. Install dotnet.exe or nuget.exe."
        }
        #endregion

        $input.Group `
        | Select-Object -ExpandProperty Solution `
        | ForEach-Object { Invoke-SolutionRestore $_ }
    }

    try {    
        $batches `
        | ForEach-Object { $_ | Start-ThreadJob -ScriptBlock $scriptBlock } `
        | Receive-Job -Wait -AutoRemoveJob
    }
    catch {
        $batches `
        | ForEach-Object { $_ | Start-Job -ScriptBlock $scriptBlock } `
        | Receive-Job -Wait -AutoRemoveJob
    }
}
#endregion

#region Invoke-SolutionVulnerabilityScan
function Invoke-SolutionVulnerabilityScan([Solution[]]$Solution) {
    if ($Restore) {
        if ($RestoreActionPreference -eq 'OnDemand') {
            $solutionsToRestore = $Solution | ForEach-Object {
                $projectsToBeRestored = @($_.ModernProjects | Where-Object { $null -eq $_.GetProjectAssetsJsonFile($false) })
                if ($projectsToBeRestored) {
                    return $_
                }
            }
            Invoke-ParallelRestore $solutionsToRestore
        }
        else {
            Invoke-ParallelRestore $Solution
        }
    }
    $nugetService = [NugetService]::new()
    $advisoryService = [AdvisoryService]::new()
    $auditor = [VulnerabilityAuditor]::new($nugetService, $advisoryService)

    $auditor.Settings.FindPatchedOnline = $FindPatchedOnline
    $auditor.Settings.IncludeDependencies = !$Minimal
    $auditor.Settings.ScanMode = $ProjectsToScan

    $results = $Solution | ForEach-Object { $auditor.RunSolutionAudit($_) }

    if ($OnlyProjectsWithVulnerabilities) {
        foreach ($solutionAudit in $results) {
            $solutionAudit.Projects = @($solutionAudit.Projects | Where-Object { $_.VulnerabilityCount.Total -gt 0 })
        }
    }

    return $results
}
#endregion

#region Find-SolutionFiles
function Find-Solutions([string]$Path) {
    $slnFiles = @([System.IO.Directory]::EnumerateFiles($Path, '*.sln', [System.IO.SearchOption]::AllDirectories))
    $solutions = @($slnFiles | ForEach-Object { [Solution]::Parse($_) })
    return $solutions
}
#endregion
#endregion

#region MAIN
if (!(Test-Path -Path $SolutionPath)) {
    throw "Provided path does not exist: $SolutionPath"
}

if (Test-Path -Path $SolutionPath -PathType Leaf) {
    [System.IO.FileInfo]$slnFile = $SolutionPath

    if ($slnFile.Extension -ne '.sln') {
        $extension = $slnFile.Extension
        throw "Provided file is not solution file. Invalid file extension - expected: '.sln' but received: '$extension'"
    }
    $solution = [Solution]::Parse($slnFile)
    $finalResult = Invoke-SolutionVulnerabilityScan $solution
}
elseif ($Recurse) {
    $solutions = Find-Solutions -Path $SolutionPath
    if (!$solutions) {
        throw "No solution file found in the provided directory and its subdirectories."
    }
    $finalResult = Invoke-SolutionVulnerabilityScan $solutions
}
else {
    $solution = Find-Solutions -Path $SolutionPath
    if ($null -eq $solution) {
        throw "Provided directory does not contain solution file. Use command with: '-Recurse' switch to search for all solutions in directory tree"
    }
    if ($solution -is [System.Collections.ICollection]) {
        $files = [string]::Join(', ', ($solution | Select-Object -Property File))
        throw "Provided directory contains multiple solution files ($files). Specify solution file directly or use command with: '-Recurse' switch to search for all solutions in directory tree"
    }
    $finalResult = Invoke-SolutionVulnerabilityScan $solution
}

Format-AuditResult $finalResult

#region BuildBreaker
if ($BuildBreaker) {
    if ($BreakOnProjectType -eq 'All' -and $finalResult.VulnerabilityCount.All.GetTotalFromLevel($MinimumBreakLevel) -gt 0) { 
        exit 1 
    }

    if ($BreakOnProjectType -eq 'Modern' -and $finalResult.VulnerabilityCount.Modern.GetTotalFromLevel($MinimumBreakLevel) -gt 0) {
        exit 1
    }

    if ($BreakOnProjectType -eq 'Legacy' -and $finalResult.VulnerabilityCount.Legacy.GetTotalFromLevel($MinimumBreakLevel) -gt 0) {
        exit 1
    }
}
#endregion
#endregion
