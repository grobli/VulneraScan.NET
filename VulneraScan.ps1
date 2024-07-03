<# 
.SYNOPSIS
    Performs vulnerability scan of NuGet packages in .NET solutions.
#>

#Requires -Version 5.1

#region Parameters
[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)][string]$SolutionPath,
    [Parameter()][ValidateSet('Json', 'Xml', 'Text')]$Format,
    [Parameter()][switch]$Recurse,
    [Parameter()][switch]$BuildBreaker,
    [Parameter()][ValidateSet('Low', 'Moderate', 'High', 'Critical')]$MinimumBreakLevel = 'Low',
    [Parameter()][ValidateSet('All', 'Legacy', 'Modern')]$BreakOnProjectType = 'All',
    [Parameter()][switch]$FindPatchedOnline,
    [Parameter()][ValidateSet('All', 'Legacy', 'Modern')]$ProjectsToScan = 'All',
    [Parameter()][switch]$Restore,
    [Parameter()][ValidateSet('OnDemand', 'Always', 'Force')]$RestoreActionPreference = 'OnDemand' ,
    [Parameter()][ValidateSet('Dotnet', 'Nuget')]$RestoreToolPreference = 'Dotnet'
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

#region CommonFunctions

#region Get-ProjectAssetsJson
function Get-ProjectAssetsJson([Project]$Project) {
    if ($Restore -and $RestoreActionPreference -ne 'OnDemand') {
        Invoke-ProjectRestore $Project
    }

    $path = Join-Path -Path $Project.File.Directory.FullName -ChildPath 'obj\project.assets.json'
    try {
        Get-ChildItem -Path $path -ErrorAction Stop -Force
    }
    catch {
        if ($Restore) {
            Invoke-ProjectRestore $Project
            return Get-ChildItem -Path $path -ErrorAction SilentlyContinue -Force
        }
        throw "project.assets.json for project: '$Project' not found! Use '-Restore' switch to automatically restore project or run manually 'nuget restore' or 'dotnet restore' on the project's solution before running this script."
    }
}
#endregion
    
#region Invoke-ProjectRestore
function Invoke-ProjectRestore([Project]$Project) {
    $path = $Project.File.FullName 
    if ($RestoreToolPreference -eq 'Nuget' -or -not $IsDotnetExeAvailable) {
        if ($IsNugetExeAvailable) {
            $command = 'nuget.exe'
            $forceParam = if ($RestoreActionPreference -eq 'Force') { '-Force' } else { '' }
            $params = 'restore', "$path", '-NonInteractive', $forceParam
            Write-Debug -Message "Executing command: $command $params"
            & $command $params | Write-Verbose
            return
        }
    }

    if ($IsDotnetExeAvailable) {
        $command = 'dotnet.exe'
        $forceParam = if ($RestoreActionPreference -eq 'Force') { '--force' } else { '' }
        $params = 'restore', "$path", $forceParam
        Write-Debug -Message "Executing command: $command $params"
        & $command $params | Write-Verbose
        return
    }

    throw "No tool for performing the NuGet restore is available on the machine. Install dotnet.exe or nuget.exe."
}
#endregion
#endregion
    
#region DataClasses
enum Severity {
    Low = 0
    Moderate = 1
    High = 2
    Critical = 3
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
        return $this.AdvisoryUrl
    }
}
#endregion

#region SolutionAuditPlural
class SolutionAuditPlural {
    [SolutionAudit[]]$Solutions
    [SolutionAuditVulnerabilityCount]$VulnerabilityCount

    SolutionAuditPlural([SolutionAudit[]]$solutions) {
        $counts = $solutions | Select-Object -ExpandProperty VulnerabilityCount
        $this.Solutions = $solutions
        $this.VulnerabilityCount = [SolutionAuditVulnerabilityCount]::SumCounts($counts)
    }
}
#endregion
    
#region SolutionAudit
class SolutionAudit {
    [string]$SolutionName
    [SolutionAuditVulnerabilityCount]$VulnerabilityCount
    [ProjectAudit[]]$Projects
    [ProjectAudit[]]$LegacyProjects
    [string]$SolutionPath
    
    SolutionAudit([System.IO.FileInfo]$solutionFile, [ProjectAudit[]]$legacyAudits, [ProjectAudit[]]$audits) {
        $this.SolutionPath = $solutionFile.FullName
        $this.SolutionName = $solutionFile.BaseName
        $this.LegacyProjects = $legacyAudits
        $this.Projects = $audits
        $this.VulnerabilityCount = [SolutionAuditVulnerabilityCount]::new($legacyAudits, $audits)
    }
}
#endregion
    
#region ProjectAudit
class ProjectAudit {
    [string]$ProjectName
    [VulnerabilityCount]$VulnerabilityCount
    [PackageAudit[]]$VulnerablePackages
    [string]$ProjectPath
    
    ProjectAudit([Project]$project, [PackageAudit[]]$audits) {
        $this.ProjectName = $project.File.BaseName
        $this.ProjectPath = $project.File.FullName
        $this.VulnerablePackages = $audits
        $counts = $audits | Select-Object -ExpandProperty VulnerabilityCount
        $this.VulnerabilityCount = [VulnerabilityCount]::SumCounts($counts)
    }
}
#endregion

#region PackageAudit
class PackageAudit {
    [string]$PackageName
    [string]$PackageVersion
    [string]$FirstPatchedVersion
    [VulnerabilityCount]$VulnerabilityCount
    [Vulnerability[]]$Vulnerabilities

    PackageAudit([Package]$package) {
        $this.PackageName = $package.Name
        $this.PackageVersion = $package.Version
        $this.Vulnerabilities = $package.Vulnerabilities
        $this.FirstPatchedVersion = $this.GetPatchedVersion()
        $this.VulnerabilityCount = [VulnerabilityCount]::Create($this.Vulnerabilities)
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
        $this.IsLegacy = $null -ne $this.PackagesConfigFile
    }

    [bool]HasPackageReferences() {
        $packageReferences = [xml]([System.IO.File]::ReadAllLines($this.File.FullName)) `
        | Select-Xml -XPath './/PackageReference' -ErrorAction SilentlyContinue `
        | Select-Object -ExpandProperty Node
        return $null -ne $packageReferences
    }

    [string[]]GetPackageIds() {
        if ($this.IsLegacy) { return $this.ReadPackagesConfig() } 
        return $this.ReadProjectAssetsJson()
    }
  
    hidden [string[]]ReadPackagesConfig() {
        $packages = [xml]([System.IO.File]::ReadAllLines($this.PackagesConfigFile.FullName)) `
        | Select-Xml -XPath './/package' `
        | Select-Object -ExpandProperty Node `
        | ForEach-Object {
            $_.id + '/' + $_.version
        }
        if ($packages) { return $packages }
        return @()
    }

    hidden [string[]]ReadProjectAssetsJson() {
        if (!$this.HasPackageReferences()) {
            return @()
        }
        $projectAssetsJsonFile = Get-ProjectAssetsJson $this
        if (!$projectAssetsJsonFile) {
            return @()
        }
        return [Project]::ParseProjectAssetsJson($projectAssetsJsonFile)
    }

    hidden static [string[]]ParseProjectAssetsJson([System.IO.FileInfo]$projectAssetsFile) {
        $projectAssetsText = [System.IO.File]::ReadAllLines($projectAssetsFile.FullName) 
        $projectAssetsParsed = $projectAssetsText | ConvertFrom-Json
        $packageIds = $projectAssetsParsed.libraries.PSObject.Properties `
        | Select-Object -ExpandProperty Value `
        | Where-Object -Property type -eq 'package' `
        | Select-Object -ExpandProperty path
        
        if ($packageIds) { return $packageIds }
        return @()
    }

    hidden [System.IO.FileInfo]GetPackagesConfig() {
        return Get-ChildItem -Path $this.File.Directory.FullName -Filter 'packages.config' -ErrorAction SilentlyContinue -Force
    }

    [string]ToString() {
        return $this.File.FullName
    }
}
#endregion

#region Package
class Package {
    [string]$Name
    [version]$Version
    [Vulnerability[]]$Vulnerabilities
    [string]$Id

    Package([string]$id) {
            ($n, $v) = $id.ToLower().Split('/')
        $this.Name = $n
        $this.Version = [VersionConverter]::Convert($v)
        $this.Id = $id
    }

    Package([string]$name, [string]$version) {
        $this.Name = $name.ToLower()
        $this.Version = [VersionConverter]::Convert($version)
        $this.Id = $this.Name + '/' + $this.Version.ToString()
    }

    [string]ToString() {
        return $this.Id
    }
}
#endregion

#region JsonModels
class NugetVulnerabilityEntry {
    [string]$Url
    [int]$Severity
    [string]$Versions

    NugetVulnerabilityEntry([string]$url, [int]$severity, [string]$versions) {
        $this.Url = $url
        $this.Severity = $severity
        $this.Versions = $versions
    }
}
#endregion
    
#region VulnerabilityAuditor
class VulnerabilityAuditor {
    hidden [string]$NugetVulnerabilityIndexUrl
    hidden [System.Collections.Generic.Dictionary[string, NugetVulnerabilityEntry[]]]$Base
    hidden [System.Collections.Generic.Dictionary[string, NugetVulnerabilityEntry[]]]$Update
    hidden [hashtable]$AdvisoriesCache
    hidden [System.Collections.Generic.Dictionary[string, PackageAudit]]$AuditWithVulnerabilitiesCache
    hidden [System.Collections.Generic.HashSet[string]]$AuditNoVulnerableSet

    VulnerabilityAuditor() {
        $this.NugetVulnerabilityIndexUrl = 'https://api.nuget.org/v3/vulnerabilities/index.json'
        $this.AdvisoriesCache = @{}
        $this.AuditWithVulnerabilitiesCache = [System.Collections.Generic.Dictionary[string, PackageAudit]]::new()
        $this.AuditNoVulnerableSet = [System.Collections.Generic.HashSet[string]]::new()

        $index = $this.FetchNugetIndex()
        $this.Base = $this.FetchNuGetData($index.Base)
        $this.Update = $this.FetchNuGetData($index.Update)
    }

    hidden [PSCustomObject]FetchNugetIndex() {
        $index = [PSCustomObject]@{
            Base   = $null
            Update = $null
        }
        $response = $this.MakeGetRequest($this.NugetVulnerabilityIndexUrl)
        $response | ForEach-Object {
            if ($_.'@name' -eq 'base') {
                $index.Base = $_.'@id'
                return
            }
            $index.Update = $_.'@id'
        }
        return $index
    }

    hidden [PSCustomObject]MakeGetRequest([string]$url) {
        return Invoke-RestMethod -Method Get -Uri $url -UseBasicParsing
    }

    hidden [System.Collections.Generic.Dictionary[string, NugetVulnerabilityEntry[]]]FetchNuGetData([string]$indexEntry) {   
        $entriesDict = [System.Collections.Generic.Dictionary[string, NugetVulnerabilityEntry[]]]::new()
        $response = $this.MakeGetRequest($indexEntry)
        $response.PSObject.Properties `
        | Select-Object -Property Name, Value `
        | ForEach-Object {
            $entries = $_.Value | ForEach-Object {
                [NugetVulnerabilityEntry]::new($_.url, $_.severity, $_.versions)
            }
            $entriesDict[$_.Name] = $entries
        }
        return $entriesDict
    }

    [SolutionAudit]RunSolutionAudit([Solution]$solution, [bool]$findPatchedOnline) {
        $legacyAudits = $solution.LegacyProjects | ForEach-Object { $this.RunProjectAudit($_, $findPatchedOnline) }
        $audits = $solution.ModernProjects | ForEach-Object { $this.RunProjectAudit($_, $findPatchedOnline) }
        return [SolutionAudit]::new($solution.File, $legacyAudits, $audits)
    }

    [SolutionAudit]RunModernSolutionAudit([Solution]$solution, [bool]$findPatchedOnline) {
        $audits = $solution.ModernProjects | ForEach-Object { $this.RunProjectAudit($_, $findPatchedOnline) }
        $solution.LegacyProjects | ForEach-Object {
            Write-Warning -Message "ProjectsToScan='Modern' - Ignoring legacy project: $_"
        }
        return [SolutionAudit]::new($solution.File, @(), $audits)
    }

    [SolutionAudit]RunLegacySolutionAudit([Solution]$solution, [bool]$findPatchedOnline) {
        $legacyAudits = $solution.LegacyProjects | ForEach-Object { $this.RunProjectAudit($_, $findPatchedOnline) }
        $solution.ModernProjects | ForEach-Object {
            Write-Warning -Message "ProjectsToScan='Legacy' - Ignoring modern project: $_"
        }
        return [SolutionAudit]::new($solution.File, $legacyAudits, @())
    }

    hidden [ProjectAudit]RunProjectAudit([Project]$project, [bool]$findPatchedOnline) {
        $packageIds = $project.GetPackageIds()
        $audits = $packageIds `
        | ForEach-Object { 
            if ($this.AuditWithVulnerabilitiesCache.ContainsKey($_)) {
                return $this.AuditWithVulnerabilitiesCache[$_]
            }
            if ($this.AuditNoVulnerableSet.Contains($_)) {
                return
            }
            $package = $this.CreatePackage($_)
            if ($package.Vulnerabilities.Count -eq 0) {
                $this.AuditNoVulnerableSet.Add($_) | Out-Null
                return
            }
            $audit = $this.CreatePackageAudit($package, $findPatchedOnline)
            $this.AuditWithVulnerabilitiesCache[$_] = $audit
            return $audit
        } 
        return [ProjectAudit]::new($project, $audits)
    }

    [PackageAudit]CreatePackageAudit([Package]$package, [bool]$findPatchedOnline) {
        $audit = [PackageAudit]::new($package)
        if ($package.Vulnerabilities.Count -gt 0 -and -not $audit.FirstPatchedVersion -and $findPatchedOnline) {
            $patchedVersion = $this.FindPatchedVersionOnline($package.Vulnerabilities)
            $audit.FirstPatchedVersion = $patchedVersion
        }
        return $audit
    }

    hidden [Package]CreatePackage([string]$packageId) {
        $package = [Package]::new($packageId)
        $vulnerabilities = $this.FindVulnerabilities($package)
        $package.Vulnerabilities = $vulnerabilities
        return $package
    }

    hidden [Vulnerability[]]FindVulnerabilities([Package]$package) {
        $vBase = [VulnerabilityAuditor]::SearchInData($this.Base, $package)
        $vUpdate = [VulnerabilityAuditor]::SearchInData($this.Update, $package)
        $allVulnerabilities = $($vBase; $vUpdate)
        if ($allVulnerabilities) { return $allVulnerabilities }
        return @()
    }
    
    hidden static [Vulnerability[]]SearchInData([System.Collections.Generic.Dictionary[string, NugetVulnerabilityEntry[]]]$data, [Package]$package) {
        if (!$data.ContainsKey($package.Name)) {
            return @()
        }
        $vulnerabilities = $data[$package.Name]  `
        | ForEach-Object {
            $vrange = [VersionRange]::Parse($_.versions)
            [Vulnerability]::new($_.severity, $_.url, $vrange)
        } `
        | Where-Object { $_.VersionRange.CheckInRange($package.Version) }

        if ($vulnerabilities) { return $vulnerabilities }
        return @()
    }

    hidden [version]FindPatchedVersionOnline([Vulnerability[]]$vulnerabilities) {
        $patchedVersions = $vulnerabilities | ForEach-Object {
            if ($this.AdvisoriesCache.ContainsKey($_.GhsaId)) {
                $advisoryData = $this.AdvisoriesCache[$_.GhsaId]
            }
            else {
                $advisoryData = Invoke-RestMethod $_.AdvisoryUrl.Replace('github', 'api.github')
                $this.AdvisoriesCache[$_.GhsaId] = $advisoryData
            }

            $advisoryData `
            | Select-Object -ExpandProperty vulnerabilities `
            | Where-Object { $_.package.ecosystem -eq 'nuget' } `
            | Select-Object -ExpandProperty first_patched_version `
            | ForEach-Object { [VersionConverter]::Convert($_) } `
        }
        return ($patchedVersions | Sort-Object -Descending)[0]
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
        if ($this.Min.Equals($version) -and $this.IsMinInclusive) {
            return $true
        }
        if ($this.Max.Equals($version) -and $this.IsMaxInclusive) {
            return $true
        }
        return $version -gt $this.Min -and $version -lt $this.Max
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

    static [version]Convert([string]$versionString) {
        if ([VersionConverter]::Cache.ContainsKey($versionString)) {
            return [VersionConverter]::Cache[$versionString]
        }
        [version]$version = $null
        $versionString = $versionString.Split('-', 2)[0]
        if ($versionString) {
            $version = $versionString
        }
        [VersionConverter]::Cache[$versionString] = $version
        return $version
    }
}
#endregion


#region MainBlockFunctions
#region Format-AuditResult
function Format-AuditResult($AuditResult) {
  
    if ($Depth -eq 0) {
        $Depth = 6
    }

    if ($AuditResult -is [System.Collections.ICollection]) {
        $AuditResult = [SolutionAuditPlural]::new($AuditResult)
        $Depth = 8
    }

    if ($Format -eq 'Json') {
        return $AuditResult | ConvertTo-Json -Depth $Depth -Compress -WarningAction SilentlyContinue
    }
    
    if ($Format -eq 'Xml') {
        return $AuditResult | ConvertTo-Xml -Depth $Depth -As String -WarningAction SilentlyContinue
    }

    if ($Format -eq 'Text') {
        if ($AuditResult -is [SolutionAuditPlural]) {
            $AuditResult | Select-Object -ExpandProperty Solutions | ForEach-Object {
                Format-SolutionAuditAsText -SolutionAudit $_
                Write-Output =================================================================================================================================================
            }
            return
        }
        else {
            Format-SolutionAuditAsText -SolutionAudit $AuditResult
            return
        }
    }
    
    $AuditResult
}
#endregion

#region Format-SolutionAuditAsText
function Format-SolutionAuditAsText([SolutionAudit]$SolutionAudit) {
    $SolutionAudit | Select-Object -ExcludeProperty Projects, LegacyProjects, VulnerabilityCount | Format-Table
    Write-Output 'Vulnerability Count:'
    $SolutionAudit.VulnerabilityCount | Format-Table
    $SolutionAudit.LegacyProjects | ForEach-Object {
        $_ | Select-Object -ExcludeProperty VulnerablePackages | Format-Table
        $_.VulnerablePackages | ForEach-Object {
            $_ | Select-Object -ExcludeProperty Vulnerabilities | Format-Table 
            $_.Vulnerabilities | Format-List 
        }
    } 
}
#endregion

#region Invoke-SolutionVulnerabilityScan
function Invoke-SolutionVulnerabilityScan([Solution[]]$Solution) {
    $auditor = [VulnerabilityAuditor]::new()
    $results = $Solution | ForEach-Object {
        if ($ProjectsToScan -eq 'All') {
            return $auditor.RunSolutionAudit($_, $FindPatchedOnline)
        }
    
        if ($ProjectsToScan -eq 'Legacy') {
            return $auditor.RunLegacySolutionAudit($_, $FindPatchedOnline)
        }
    
        return $auditor.RunModernSolutionAudit($_, $FindPatchedOnline)
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
