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
    [Parameter()][ValidateSet('Low', 'Moderate', 'High', 'Critical')]$BreakOnSeverity = 'Low',
    [Parameter()][ValidateSet('All', 'Legacy', 'Modern')]$BreakOnProjectType = 'All',
    [Parameter()][switch]$FindPatchedOnline,
    [Parameter()][ValidateSet('All', 'Legacy', 'Modern', 'None')]$ProjectsToScan = 'All',
    [Parameter()][switch]$Restore,
    [Parameter()][ValidateSet('OnDemand', 'Force')]$RestoreActionPreference = 'OnDemand',
    [Parameter()][ValidateSet('Dotnet', 'Nuget')]$RestoreToolPreference = 'Dotnet',
    [Parameter()][int]$RestoreMaxParallelism = 0,
    [Parameter()][switch]$OnlyVulnerable,
    [Parameter()][switch]$Minimal
)
#endregion

#region GlobalVariables
[bool]$IsNugetAppAvailable = $true
[bool]$IsDotnetAppAvailable = $true 

if ($Restore) {
    try {
        Get-Command nuget -ErrorAction Stop | Out-Null
    }
    catch {
        $IsNugetAppAvailable = $false
        Write-Warning -Message "nuget app not found in system PATH"
    }
    try {
        Get-Command dotnet -ErrorAction Stop | Out-Null
    }
    catch {
        $IsDotnetAppAvailable = $false
        Write-Warning -Message "dotnet app not found in system PATH"
    }
}
#endregion

#region Exceptions
class RecurseNotEnabledException : System.Exception {
    RecurseNotEnabledException([string]$message) : base($message) {}
}

class NoSolutionFoundException : System.Exception {
    NoSolutionFoundException() : base('No solution file found in the provided directory and its subdirectories.') {}
}

class InvalidFileExtensionException : System.Exception {
    InvalidFileExtensionException([string]$extension) : base("Provided file is not solution file. " + `
            "Invalid file extension - expected: '.sln' but received: '$extension'") {}
}

class PathDoesNotExistException : System.Exception {
    PathDoesNotExistException([string]$path) : base("Provided path does not exist: $SolutionPath") {}
}

class ProjectNotRestoredException : System.Exception {
    ProjectNotRestoredException([string]$projectName) : base("'project.assets.json' file for project: '$projectName' not found! " + `
            "Use '-Restore' switch to automatically restore project or run manually 'nuget restore' or 'dotnet restore' " + `
            "on the project's solution before running this script.") {}
}

class ResilientHttpClientException : System.Exception {
    ResilientHttpClientException([string]$message) : base($message) {}
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
    [System.Collections.Generic.SortedDictionary[string, SolutionAudit]]$Solutions
    [SolutionAuditVulnerabilityCount]$VulnerabilityCount
    [PackageAudit[]]$VulnerablePackages

    SolutionAuditPlural([SolutionAudit[]]$solutions) {
        $counts = $solutions | Select-Object -ExpandProperty VulnerabilityCount
        $this.Solutions = [System.Collections.Generic.SortedDictionary[string, SolutionAudit]]::new()
        foreach ($sln in $solutions) {
            if ($this.Solutions.ContainsKey($sln.SolutionName)) {
                $this.Solutions[$sln.SolutionName + '*'] = $sln
                continue
            }
            $this.Solutions[$sln.SolutionName] = $sln 
        }
        $this.VulnerabilityCount = [SolutionAuditVulnerabilityCount]::SumCounts($counts)
        $this.VulnerablePackages = $this.FindUniqueVulnerablePackages()
    }

    hidden [PackageAudit[]]FindUniqueVulnerablePackages() {
        $packages = @($this.Solutions.Values.VulnerablePackages | Where-Object { $_ })
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
    [System.Collections.Generic.SortedDictionary[string, ProjectAudit]]$Projects
    [PackageAudit[]]$VulnerablePackages
    [string]$SolutionPath
    [string[]]$TargetFrameworks

    hidden [CommandToolsSolution]$Tools
    
    SolutionAudit([System.IO.FileInfo]$solutionFile, [ProjectAudit[]]$legacyAudits, [ProjectAudit[]]$audits) {
        $this.SolutionPath = $solutionFile.FullName
        $this.SolutionName = $solutionFile.BaseName
        $this.Projects = [System.Collections.Generic.SortedDictionary[string, ProjectAudit]]::new()
        ($audits + $legacyAudits) | ForEach-Object { $this.Projects[$_.ProjectName] = $_ }
        $this.VulnerabilityCount = [SolutionAuditVulnerabilityCount]::new($legacyAudits, $audits)
        $this.VulnerablePackages = $this.FindUniqueVulnerablePackages()

        $this.Tools = [CommandToolsSolution]::new($this.Projects.Values.Tools)
        
        [string[]]$frameworks = $audits.TargetFrameworks + $legacyAudits.TargetFrameworks | Where-Object { -not [string]::IsNullOrEmpty($_) }
        $this.TargetFrameworks = [System.Collections.Generic.HashSet[string]]::new($frameworks)
    }

    [CommandToolsSolution]GetTools() {
        return $this.Tools
    }

    [hashtable]GetProjectsDirectDependencies() {
        $projectsDependencies = @{}
        foreach ($project in $this.Projects) {
            $projectsDependencies[$project.ProjectName] = $project.DirectDependencies `
            | Select-Object -ExpandProperty Id
        }
        return $projectsDependencies
    }

    hidden [PackageAudit[]]FindUniqueVulnerablePackages() {
        $packages = @($this.Projects.Values.VulnerablePackages | Where-Object { $_ })
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
    [PackageAudit[]]$VulnerablePackageReferences
    [PackageAudit[]]$VulnerableDirectPackages
    [PackageAudit[]]$VulnerablePackages
    [PackageAudit[]]$PackagesWithVulnerableDependencies
    [Package[]]$DirectDependencies
    [Package[]]$TransitiveDependencies
    [Package[]]$PackageReferences
    [Package[]]$TransitiveOverrides
    [string]$ProjectPath
    [string]$ProjectType
    [string[]]$TargetFrameworks

    hidden [CommandToolsProject]$Tools
    
    ProjectAudit([Project]$project, [PackageAudit[]]$audits, [Package[]]$packages) {
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
        $this.VulnerablePackageReferences = $audits `
        | Where-Object { $_.IsPackageReference } `
        | Sort-Object -Property PackageName
        $counts = $audits | Select-Object -ExpandProperty VulnerabilityCount
        $this.VulnerabilityCount = [VulnerabilityCount]::SumCounts($counts)
        if ($packages) {
            $this.DirectDependencies = $packages | Where-Object { $_.IsDirect() }
            $this.TransitiveDependencies = $packages | Where-Object { $_.IsTransitive() }
            $this.PackageReferences = $packages | Where-Object { $_.IsPackageReference }
            $this.TransitiveOverrides = $packages | Where-Object { $_.IsPackageReference -and $_.IsTransitive() }  
        }
        $this.Tools = [CommandToolsProject]::new($project, $this)
        $this.TargetFrameworks = $project.GetTargetFrameworks()
    }

    [CommandToolsProject]GetTools() {
        return $this.Tools
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
    [bool]$IsPackageReference

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
        $this.IsPackageReference = $package.IsPackageReference
    }

    hidden [string]GetPatchedVersion() {
        [version[]]$versions = @()
        foreach ($vln in @($this.Vulnerabilities | Where-Object { !$_.VersionRange.IsMaxInclusive })) {
            $versions += $vln.VersionRange.Max
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
        foreach ($c in $counts) {
            $count.Total += $c.Total
            $count.Low += $c.Low
            $count.Moderate += $c.Moderate
            $count.High += $c.High
            $count.Critical += $c.Critical
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
    [xml]$CsprojContent
    [System.Collections.Generic.HashSet[string]]$PackageReferences
    hidden [System.IO.FileInfo]$PackagesConfigFile
    hidden [PSCustomObject]$ProjectAssetsContent

    Project([string]$projectPath, [string]$solutionPath) {
        $this.File = $projectPath
        $this.Solution = $solutionPath
        $this.PackagesConfigFile = $this.GetPackagesConfig()
        $this.CsprojContent = [System.IO.File]::ReadAllText($this.File.FullName)
        $this.IsLegacy = !$this.IsSdkStyle()
        $this.PackageReferences = $this.ReadPackageReferences()
        $this.ProjectAssetsContent = $this.LoadProjectAssetsJson()
    }

    [Package[]]GetPackages() {
        [Package[]]$packages = if ($this.IsLegacy) { $this.ReadPackagesConfig() } 
        else { $this.ReadProjectAssetsJson() }
        return $this.FilterOutNotRelatedPackages($packages)
    }

    [Package[]]GetPackages([NugetService]$nugetService) {
        $packageStore = [PackageStore]::new($nugetService)
        [Package[]]$packages = if ($this.IsLegacy) { $this.ReadPackagesConfig($packageStore) } 
        else { $this.ReadProjectAssetsJson($packageStore) }
        return $this.FilterOutNotRelatedPackages($packages)
    }

    [string[]]GetTargetFrameworks() {
        if ($this.IsLegacy) {
            $tfv = $this.CsprojContent.GetElementsByTagName('TargetFrameworkVersion')[0].InnerText
            return $tfv
        }
        return $this.ProjectAssetsContent.targets.PSObject.Properties.Name
    }

    hidden [Package[]]FilterOutNotRelatedPackages([Package[]]$packages) {
        if ($this.IsLegacy) {
            return $packages
        }
        $projectRelatedPackages = [System.Collections.Generic.HashSet[Package]]::new()
        foreach ($package in $packages) {
            $package.IsPackageReference = $this.PackageReferences.Contains($package.Id.Name)
            if ($package.IsPackageReference) {
                $projectRelatedPackages.Add($package)
                $projectRelatedPackages.UnionWith($package.GetAllTransitives())
            }
        }
        return $projectRelatedPackages
    }

    [System.IO.FileInfo]GetProjectAssetsJsonFile() {
        $path = Join-Path -Path $this.File.Directory.FullName -ChildPath 'obj\project.assets.json'
        try {
            return Get-Item -Path $path -ErrorAction Stop -Force
        }
        catch {
            throw [ProjectNotRestoredException]::new($this.ToString())
        }
    }

    [string]ToString() {
        return $this.File.FullName
    }

    hidden [bool]IsSdkStyle() {
        $projectNode = $this.CsprojContent `
        | Select-Xml -XPath './Project' -ErrorAction SilentlyContinue `
        | Select-Object -ExpandProperty Node
        $sdkAttribute = $projectNode.Attributes | Where-Object { $_.Name -eq 'Sdk' }
        return $null -ne $sdkAttribute
    }

    hidden [System.Collections.Generic.HashSet[string]]ReadPackageReferences() {
        if ($this.IsLegacy) {
            return @()
        }
        $prefs = $this.CsprojContent `
        | Select-Xml -XPath './/PackageReference' -ErrorAction SilentlyContinue `
        | Select-Object -ExpandProperty Node
        $set = [System.Collections.Generic.HashSet[string]]::new()
        foreach ($pref in $prefs) {
            $set.Add($pref.Include.Trim().ToLower())
        }
        return $set
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
        [PackageId[]]$ids = @()
        $nodes = [xml]([System.IO.File]::ReadAllText($this.PackagesConfigFile.FullName)) `
        | Select-Xml -XPath './/package' `
        | Select-Object -ExpandProperty Node
        foreach ($node in $nodes) {
            $ids += [PackageId]::Create($node.id, $node.version)
        }
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
                [PackageId[]]$dependencies = @()
                $dependencyEntries = $entry.Value.dependencies.PSObject.Properties | Select-Object -Property Name, Value
                foreach ($depEntry in $dependencyEntries) {
                    $dependencies += [PackageId]::Create($depEntry.Name, $depEntry.Value)
                }
                $packageStore.SetDependencies($packageId, $dependencies)
            }
        }
        return $packageStore.GetAll()
    }

    hidden [PSCustomObject[]]ParseProjectAssetsJson() {
        $targets = @($this.ProjectAssetsContent.targets.PSObject.Properties)[0].Value.PSObject.Properties
        $entries = $targets `
        | Select-Object -Property Name, Value `
        | Where-Object { $_.Value.type -eq 'package' }
        return $entries
    }

    hidden [PSCustomObject]LoadProjectAssetsJson() {
        if ($this.IsLegacy) {
            return $null
        }
        $projectAssetsJsonFile = $this.GetProjectAssetsJsonFile()
        $projectAssetsText = [System.IO.File]::ReadAllText($projectAssetsJsonFile.FullName) 
        $projectAssetsParsed = $projectAssetsText | ConvertFrom-Json
        return $projectAssetsParsed
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

    hidden static $Cache = [System.Collections.Generic.Dictionary[string, PackageId]]::new()

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
    [bool]$IsPackageReference
    [PackageId[]]$MinimalDependencies

    Package([PackageId]$packageId) {
        $this.Id = $packageId
    }

    [bool]IsTransitive() {
        return $this.Dependants.Count -gt 0
    }

    [bool]IsDirect() {
        return -not $this.IsTransitive()
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

    [System.Collections.Generic.HashSet[Package]]GetAllTransitives() {
        $transitives = [System.Collections.Generic.HashSet[Package]]::new()
        $stack = [System.Collections.Generic.Stack[Package]]::new()
        $stack.Push($this)
        while ($stack.Count -gt 0) {
            $pkg = $stack.Pop()
            foreach ($dep in $pkg.Dependencies) {
                if ($transitives.Add($dep)) {
                    $stack.Push($dep)
                }
            }
        }
        return $transitives
    }
}
#endregion

#region PackageStore
class PackageStore {
    hidden [System.Collections.Generic.Dictionary[string, Package]]$Store
    hidden [System.Collections.Generic.Dictionary[string, PackageId[]]]$DependencyMapping

    hidden [NugetService]$NugetService
        
    PackageStore([NugetService]$nugetService) {
        $this.Store = [System.Collections.Generic.Dictionary[string, Package]]::new()
        $this.DependencyMapping = [System.Collections.Generic.Dictionary[string, PackageId[]]]::new()
        $this.NugetService = $nugetService
    }

    [void]Add([PackageId]$packageId) {
        $package = [Package]::new($packageId)
        $this.Store[$packageId.Name] = $package
    }

    [void]SetDependencies([PackageId]$packageId, [PackageId[]]$dependencyIds) {
        $this.DependencyMapping[$packageId.Name] = $dependencyIds
        $package = $this.Store[$packageId.Name]
        $package.MinimalDependencies = $dependencyIds   
    }

    [Package[]]GetAll() {
        $packages = $this.Store.Values
        foreach ($package in $packages) {
            $this.SetupDependencies($package)
            if ($null -ne $this.NugetService) {
                $package.Vulnerabilities = $this.NugetService.FindVulnerabilities($package.Id)
            }
        }
        if ($null -ne $this.NugetService) {
            $this.PropagateVulnerableDependenciesFlag()
        }
        return $packages
    }

    hidden [void]SetupDependencies([Package]$package) {
        $dependencyIds = $this.DependencyMapping[$package.Id.Name]
        foreach ($depId in $dependencyIds) {
            $dep = $this.Store[$depId.Name]
            if (!$dep) {
                Write-Warning "$dep dependency not found in the Package Store"
                continue
            }
            $package.Dependencies += $dep
            $dep.Dependants += $package
        }
    }

    hidden [void]PropagateVulnerableDependenciesFlag() {
        $packagesWithVulnerableDeps = [System.Collections.Generic.Stack[Package]]::new()
        foreach ($package in $this.Store.Values) {
            if ($package.IsVulnerable()) {
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
        throw  [ResilientHttpClientException]::new("HTTP GET: $url - Failed after $maxRetryCount retries")
    }

    hidden static [PSCustomObject]MakeGetRequest([uri]$url) {
        return Invoke-RestMethod -Method Get -Uri $url -UseBasicParsing -ErrorAction Stop
    }

    hidden static [int]GetDelay([int]$retry) {
        return [ResilientHttpClient]::FirstRetryDelayMillis * [math]::Pow(2, $retry)
    }
}
#endregion

#region NugetService
class NugetService {
    hidden [uri]$NugetVulnerabilityIndexUrl
    hidden [uri]$NugetIndexUrl
    hidden [uri]$NugetMetadataUrl
    hidden [System.Collections.Generic.Dictionary[string, Vulnerability[]]]$Base
    hidden [System.Collections.Generic.Dictionary[string, Vulnerability[]]]$Update
    hidden [System.Collections.Generic.Dictionary[string, System.Object]]$Metadata

    hidden static [string]$NugetMetadataType = 'RegistrationsBaseUrl/3.6.0'

    NugetService() {
        $this.NugetVulnerabilityIndexUrl = 'https://api.nuget.org/v3/vulnerabilities/index.json'
        $this.NugetIndexUrl = 'https://api.nuget.org/v3/index.json'
        $this.Metadata = [System.Collections.Generic.Dictionary[string, System.Object]]::new()

        $index = $this.FetchNugetVulnerabilityIndex()
        $this.Base = $this.FetchVulnerabilityData($index.Base)
        $this.Update = $this.FetchVulnerabilityData($index.Update)
    }

    [Vulnerability[]]FindVulnerabilities([PackageId]$package) {
        $vBase = [NugetService]::SearchInVulnerabilityData($this.Base, $package)
        $vUpdate = [NugetService]::SearchInVulnerabilityData($this.Update, $package)
        [Vulnerability[]]$allVulnerabilities = $vBase + $vUpdate
        return $allVulnerabilities
    }

    [version]FindFirstPatchedVersion([PackageId]$package) {
        $data = $this.GetMetadata($package)
        [System.Object[]]$registrationPages = @()
        foreach ($page in $data.items) {
            $vrangeString = '[' + $page.lower + ', ' + $page.upper + ']'
            $vrange = [VersionRange]::Parse($vrangeString)
            if ($vrange.Min -ge $package.Version -or $vrange.CheckInRange($package.Version)) {
                $registrationPages += $page
            }
        }
        [string[]]$entries = $registrationPages.items.catalogEntry `
        | Where-Object { 
            -not $_.vulnerabilities -and $_.version -gt $package.Version.ToString() `
                -and -not $_.version.Contains('-')
        } `
        | Select-Object -ExpandProperty version `
        | Sort-Object

        if (!$entries) {
            return $null
        }
        return [VersionConverter]::Convert($entries[0])
    }

    hidden [string]FetchNugetMetadataUrl() {
        $response = [ResilientHttpClient]::Get($this.NugetIndexUrl)
        return $response.resources `
        | Where-Object { $_.'@type' -eq [NugetService]::NugetMetadataType } `
        | Select-Object -ExpandProperty '@id'
    }
    
    hidden [PSCustomObject]FetchNugetVulnerabilityIndex() {
        $index = [PSCustomObject]@{
            Base       = $null
            Update     = $null
            MetadataId = $null
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

    hidden [System.Object]GetMetadata([PackageId]$package) {
        if ($this.Metadata.ContainsKey($package.Name)) {
            return $this.Metadata[$package.Name]
        }
        if (!$this.NugetMetadataUrl) {
            $this.NugetMetadataUrl = $this.FetchNugetMetadataUrl()
        }
        $url = [uri]::new($this.NugetMetadataUrl, $package.Name + '/index.json')
        $data = [ResilientHttpClient]::Get($url)
        $this.Metadata[$package.Name] = $data
        return $data
    }

    hidden [System.Collections.Generic.Dictionary[string, Vulnerability[]]]FetchVulnerabilityData([string]$indexEntry) {   
        $vulnerabilitiesDict = [System.Collections.Generic.Dictionary[string, Vulnerability[]]]::new()
        $response = [ResilientHttpClient]::Get($indexEntry)
        $properties = $response.PSObject.Properties | Select-Object -Property Name, Value
        foreach ($p in $properties) {
            [Vulnerability[]]$vulnerabilities = @()
            foreach ($entry in $p.Value) {
                $vrange = [VersionRange]::Parse($entry.versions)
                $vulnerabilities += [Vulnerability]::new($entry.severity, $entry.url, $vrange)
            }
            $vulnerabilitiesDict[$p.Name] = $vulnerabilities
        }
        return $vulnerabilitiesDict
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
    None
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
    hidden [System.Collections.Generic.Dictionary[PackageId, PackageAudit]]$AuditWithVulnerabilitiesCache
    hidden [System.Collections.Generic.HashSet[PackageId]]$AuditNoVulnerableSet

    [VulnerabilityAuditorSettings]$Settings

    VulnerabilityAuditor([NugetService]$nugetService) {
        $this.NugetService = $nugetService
        $this.AuditWithVulnerabilitiesCache = [System.Collections.Generic.Dictionary[PackageId, PackageAudit]]::new()
        $this.AuditNoVulnerableSet = [System.Collections.Generic.HashSet[PackageId]]::new()
        $this.Settings = [VulnerabilityAuditorSettings]::new()
    }

    [SolutionAudit]RunSolutionAudit([Solution]$solution) {
        $scanMode = $this.Settings.ScanMode
        if ($scanMode -eq [ProjectScanMode]::All -or $scanMode -eq [ProjectScanMode]::None) {
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

            if ($null -eq $this.NugetService) {
                return [ProjectAudit]::new($project, $audits, $packages)
            }

            foreach ($package in $packages) {
                if ($package.IsVulnerable() -or $package.HasVulnerableDependencies) {
                    $audit = $this.CreatePackageAudit($package)
                    $audits += $audit
                }
            }
            return [ProjectAudit]::new($project, $audits, $packages)
        }
        return $this.RunProjectAuditNoDeps($project)
    }

    hidden [ProjectAudit]RunProjectAuditNoDeps([Project]$project) {
        [Package[]]$packages = $project.GetPackages()
        [PackageAudit[]]$audits = @()

        if ($null -eq $this.NugetService) {
            return [ProjectAudit]::new($project, $audits, $packages)
        }

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
        return [ProjectAudit]::new($project, $audits, $packages)
    }

    [PackageAudit]CreatePackageAudit([Package]$package) {
        $audit = [PackageAudit]::new($package)
        if ($this.Settings.FindPatchedOnline -and $package.IsVulnerable() -and -not $audit.FirstPatchedVersion) {
            $patchedVersion = $this.NugetService.FindFirstPatchedVersion($package.Id)
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
    hidden static [regex]$Regex = [regex]::new("(\d+\.\d+\.?\d*)", [System.Text.RegularExpressions.RegexOptions]::Compiled) 

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

#region CommandTools 
#region CommandToolsSolution
class CommandToolsSolution {
    hidden [CommandToolsProject[]]$ProjectTools

    [CommandAction]$RemoveRedundantTransitiveOverrides

    CommandToolsSolution([CommandToolsProject[]]$projectTools) {
        $this.ProjectTools = $projectTools
        $this.RemoveRedundantTransitiveOverrides = [RemoveRedundantTransitiveOverridesSolution]::new($this)
    }
}
#endregion

#region CommandToolsProject
class CommandToolsProject {
    [CommandAction]$RemoveRedundantTransitiveOverrides

    CommandToolsProject([Project]$project, [ProjectAudit]$audit) {
        $this.RemoveRedundantTransitiveOverrides = [RemoveRedundantTransitiveOverrides]::new($project, $audit)
    }
}
#endregion

#region CommandAction
class CommandAction {
    CommandAction() {}
    
    Run() { throw [System.NotImplementedException]::new() }
    DryRun() { throw [System.NotImplementedException]::new() }
}
#endregion

#region RemoveRedundantTransitiveOverridesSolution
class RemoveRedundantTransitiveOverridesSolution : CommandAction {
    hidden [CommandToolsSolution]$SolutionTools
    
    RemoveRedundantTransitiveOverridesSolution([CommandToolsSolution]$tools) {
        $this.SolutionTools = $tools
    }

    Run() {
        foreach ($tool in $this.SolutionTools.ProjectTools) {
            $tool.RemoveRedundantTransitiveOverrides.Run()
        }
    }

    DryRun() {
        foreach ($tool in $this.SolutionTools.ProjectTools) {
            $tool.RemoveRedundantTransitiveOverrides.DryRun()
        }
    }
}
#endregion

#region RemoveRedundantTransitiveOverrides
class RemoveRedundantTransitiveOverrides : CommandAction {
    hidden [Project]$Project
    hidden [ProjectAudit]$Audit

    RemoveRedundantTransitiveOverrides([Project]$project, [ProjectAudit]$audit) {
        $this.Project = $project
        $this.Audit = $audit
    }

    Run() {
        Write-Host 'Project:' $this.Audit.ProjectName
        $prefs = $this.GetXmlNodes($this.FindRedundantOverrides())
        foreach ($pref in $prefs) {
            $name = $pref.OuterXml
            Write-Host "Removing: $name"
            $pref.ParentNode.RemoveChild($pref)
        }
        $file = $this.Project.File
        $this.Project.CsprojContent.Save($file)
        Write-Host "Updated file: $file"
    }

    DryRun() {
        Write-Host '--- Dry Run ---'
        Write-Host 'Project:' $this.Audit.ProjectName
        $prefs = $this.GetXmlNodes($this.FindRedundantOverrides())
        foreach ($pref in $prefs) {
            $name = $pref.OuterXml
            Write-Host "To be removed: $name"
        }
        if (!$prefs) {
            Write-Host "Nothing to change"
            return 
        }
        $file = $this.Project.File
        Write-Host "File to update: $file"
    }

    hidden [Package[]]FindRedundantOverrides() {
        [Package[]]$tos = $this.Audit.TransitiveOverrides
        [Package[]]$redundant = @()
        foreach ($to in $tos) {
            if ([RemoveRedundantTransitiveOverrides]::IsRedundant($to)) {
                $redundant += $to
            }
          
        }
        return $redundant
    }

    hidden static [bool]IsRedundant([Package]$transitiveOverride) {
        foreach ($dependant in $transitiveOverride.Dependants) {
            [Package]$dependant = $dependant
            [PackageId]$minDep = $dependant.MinimalDependencies | Where-Object { $_.Name -eq $to.Id.Name }
            # check if transitive override is dependant package upgrade
            if ($transitiveOverride.Id.Version -gt $minDep.Version) {
                return $false
            }
        }
        return $true
    }

    hidden [System.Xml.XmlElement[]]GetXmlNodes([Package[]]$packages) {
        [string[]]$pkgNames = @($packages | ForEach-Object { $_.Id.Name })
        [System.Xml.XmlElement[]]$prefs = $this.Project.CsprojContent `
        | Select-Xml -XPath './/PackageReference' `
        | Select-Object -ExpandProperty Node `
        | Where-Object { $pkgNames.Contains($_.Include.Trim().ToLower()) }
        return $prefs
    }
}
#endregion
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
    $SolutionAudit.Projects.Values | Where-Object { $_ } | ForEach-Object { Format-ProjectAuditAsText $_ }
    Write-Output "======= All Vulnerabilities Details ".PadRight(105, '=')
    Write-Output ''
    $SolutionAudit.VulnerablePackages | ForEach-Object { Format-PackageAuditAsText $_ }
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

function Get-CpuCount {
    #if using Powershell Core on unix
    if ($PSVersionTable.PSEdition -eq 'Core' -and $PSVersionTable.Platform -eq 'Unix') {
        return [int](nproc --all)
    }
    # else if using windows powershell or powershell core on windows
    return (Get-CimInstance Win32_ComputerSystem).NumberOfLogicalProcessors
}

#region Invoke-ParallelRestore
function Invoke-ParallelRestore([Solution[]]$Solutions) {
    if (-not ($IsNugetAppAvailable -or $IsDotnetAppAvailable)) {
        throw "No tool for performing the NuGet restore is available on the machine. Install dotnet or nuget"
    }
    $cpuCount = Get-CpuCount
    $jobCount = if ($RestoreMaxParallelism -le 0) { $cpuCount } else { [math]::Min($cpuCount, $RestoreMaxParallelism) }
    $i = 0
    $batches = $Solutions | ForEach-Object {
        [PSCustomObject]@{
            Solution = $_.File.FullName
            BatchId  = $i++ % $jobCount
        }
    } | Group-Object -Property BatchId

    $scriptBlock = {
        $ErrorActionPreference = $using:ErrorActionPreference
        $WarningPreference = $using:WarningPreference   
        $DebugPreference = $using:DebugPreference
        $VerbosePreference = $using:VerbosePreference
        $IsNugetAppAvailable = $using:IsNugetAppAvailable
        $IsDotnetAppAvailable = $using:IsDotnetAppAvailable
        $RestoreActionPreference = $using:RestoreActionPreference
        $RestoreToolPreference = $using:RestoreToolPreference

        #region Invoke-SolutionRestore
        function Invoke-SolutionRestore([System.IO.FileInfo]$TargetSolution) {
            $path = $TargetSolution.FullName
            if ($RestoreToolPreference -eq 'Nuget' -or -not $IsDotnetAppAvailable) {
                if ($IsNugetAppAvailable) {
                    $command = 'nuget'
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
            if ($IsDotnetAppAvailable) {
                $command = 'dotnet'
                $params = 'restore', "$path", '--verbosity', 'quiet', $forceParam
                if ($RestoreActionPreference -eq 'Force') { $params += '--force' }
                Write-Verbose -Message "Executing command: $command $params"
                & $command $params | Write-Verbose
                if ($LASTEXITCODE -ne 0) {
                    Write-Error "$command $params - operation failed - process finished with exit code: $LASTEXITCODE"
                }
                return
            }
        }
        #endregion

        $input.Group `
        | Select-Object -ExpandProperty Solution `
        | ForEach-Object { Invoke-SolutionRestore $_ }
    }

    $isThreadJobAvailable = $true
    try {
        Get-Command -Name Start-ThreadJob -ErrorAction Stop | Out-Null
    }
    catch {
        $isThreadJobAvailable = $false
    }

    if ($isThreadJobAvailable) {
        $batches `
        | ForEach-Object { $_ | Start-ThreadJob -ScriptBlock $scriptBlock } `
        | Receive-Job -Wait -AutoRemoveJob
    }
    else {
        $batches `
        | ForEach-Object { $_ | Start-Job -ScriptBlock $scriptBlock } `
        | Receive-Job -Wait -AutoRemoveJob
    }
}
#endregion

#region Invoke-SolutionVulnerabilityScan
function Invoke-SolutionVulnerabilityScan([Solution[]]$Solutions) {
    if ($Restore) {
        Invoke-ParallelRestore $Solutions
    }

    $nugetService = $null
    if ($ProjectsToScan -ne 'None') {
        $nugetService = [NugetService]::new()
    }
    $auditor = [VulnerabilityAuditor]::new($nugetService)
    
    $auditor.Settings.FindPatchedOnline = $FindPatchedOnline
    $auditor.Settings.IncludeDependencies = !$Minimal
    $auditor.Settings.ScanMode = $ProjectsToScan

    $results = $Solutions | ForEach-Object { $auditor.RunSolutionAudit($_) }

    if (-not $OnlyVulnerable) {
        return $results
    }
    foreach ($solutionAudit in $results) {
        [ProjectAudit[]]$projects = $solutionAudit.Projects.Values
        foreach ($project in $projects) {
            if ($project.VulnerabilityCount.Total -eq 0) {
                $solutionAudit.Projects.Remove($project.ProjectName) | Out-Null
            }
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
    throw [PathDoesNotExistException]::new($SolutionPath)
}

if (Test-Path -Path $SolutionPath -PathType Leaf) {
    [System.IO.FileInfo]$slnFile = $SolutionPath

    if ($slnFile.Extension -ne '.sln') {
        throw [InvalidFileExtensionException]::new($slnFile.Extension)
    }
    $solution = [Solution]::Parse($slnFile)
    $finalResult = Invoke-SolutionVulnerabilityScan $solution
}
elseif ($Recurse) {
    $solutions = Find-Solutions -Path $SolutionPath
    if (!$solutions) {
        throw [NoSolutionFoundException]::new()
    }
    $finalResult = Invoke-SolutionVulnerabilityScan $solutions
}
else {
    $solution = Find-Solutions -Path $SolutionPath
    if ($null -eq $solution) {
        throw [RecurseNotEnabledException]::new('Provided directory does not contain any solution file. Use command with: "-Recurse" switch to search for all solutions in every subdirectory')
    }
    if ($solution -is [System.Collections.ICollection]) {
        throw [RecurseNotEnabledException]::new('Provided directory contains multiple solution files. Specify solution file directly or use command with: "-Recurse" switch to search for all solutions in directory tree')
    }
    $finalResult = Invoke-SolutionVulnerabilityScan $solution
}

Format-AuditResult $finalResult

#region BuildBreaker
if ($BuildBreaker) {
    if ($BreakOnProjectType -eq 'All' -and $finalResult.VulnerabilityCount.All.GetTotalFromLevel($BreakOnSeverity) -gt 0) { 
        exit 1 
    }

    if ($BreakOnProjectType -eq 'Modern' -and $finalResult.VulnerabilityCount.Modern.GetTotalFromLevel($BreakOnSeverity) -gt 0) {
        exit 1
    }

    if ($BreakOnProjectType -eq 'Legacy' -and $finalResult.VulnerabilityCount.Legacy.GetTotalFromLevel($BreakOnSeverity) -gt 0) {
        exit 1
    }
}
#endregion
#endregion
