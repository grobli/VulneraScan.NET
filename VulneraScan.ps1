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
    [Parameter()][ValidateSet('Low', 'Moderate', 'High', 'Critical')]$MinimumBreakLevel,
    [Parameter()][ValidateSet('All', 'Legacy', 'Modern')]$BreakOnProjectType,
    [Parameter()][switch]$FindPatchedOnline,
    [Parameter()][switch]$Parallel,
    [Parameter()][ValidateSet('All', 'Legacy', 'Modern')]$ProjectsToScan,
    [Parameter()][switch]$Restore,
    [Parameter()][ValidateSet('OnDemand', 'Always')]$RestoreActionPreference,
    [Parameter()][ValidateSet('Dotnet', 'Nuget')]$RestoreToolPreference
)
#endregion

#region SetDefaults
if ([string]::IsNullOrEmpty($MinimumBreakLevel)) { $MinimumBreakLevel = 'Low' }
if ([string]::IsNullOrEmpty($BreakOnProjectType)) { $BreakOnProjectType = 'All' }
if ([string]::IsNullOrEmpty($ProjectsToScan)) { $ProjectsToScan = 'All' }
if ([string]::IsNullOrEmpty($RestoreActionPreference)) { $RestoreActionPreference = 'OnDemand' }
if ([string]::IsNullOrEmpty($RestoreToolPreference)) { $RestoreToolPreference = 'Dotnet' }
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

# define all custom functions and classes inside wrapper ScriptBlock 
# in order to use them in parallel execution with "Start-Job" 
$CustomDefinitions = {
    #region CommonFunctions

    #region Get-ProjectAssetsJson
    function Get-ProjectAssetsJson([Project]$Project) {
        if ($Restore -and $RestoreActionPreference -eq 'Always') {
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

    #region ConvertTo-Version
    function ConvertTo-Version([string]$versionString) {
        if (!$versionString) { return $null }
        $versionString = $versionString.Split('-')[0]
        return [version]$versionString
    }
    #endregion

    #region ConvertTo-StandardObject
    function ConvertTo-StandardObject($InputObject) {          
        if ($InputObject -is [System.Collections.ICollection]) {
            $newArray = $InputObject | ForEach-Object {
                ConvertTo-StandardObject $_
            }
            return $newArray
        }
    
        if ($null -eq $InputObject -or $InputObject.GetType().FullName.StartsWith('System') -or $InputObject -is [System.Enum]) {
            return $InputObject
        }
    
        $standardObject = [PSCustomObject]::new()
        Get-Member -InputObject $InputObject -MemberType Properties -Force `
        | Where-Object { $_.Name -ne 'pstypenames' } `
        | ForEach-Object {
            $property = ConvertTo-StandardObject $InputObject.($_.Name)
            Add-Member -InputObject $standardObject -NotePropertyName $_.Name -NotePropertyValue $property
        }
        return $standardObject
    }
    #endregion

    #region Invoke-SolutionVulnerabilityScan
    function Invoke-SolutionVulnerabilityScan([VulnerabilityAuditor]$Auditor, [System.IO.FileInfo]$SolutionFilePath, 
        [string]$ProjectsToBeScanned, [bool]$FindPatchedVersionOnline) {
        if ([string]::IsNullOrEmpty($ProjectsToBeScanned) -or $ProjectsToBeScanned -eq 'All') {
            return $Auditor.RunSolutionAudit($SolutionFilePath, $FindPatchedVersionOnline)
        }

        if ($ProjectsToBeScanned -eq 'Legacy') {
            return $Auditor.RunLegacySolutionAudit($SolutionFilePath, $FindPatchedVersionOnline)
        }

        return $Auditor.RunModernSolutionAudit($SolutionFilePath, $FindPatchedVersionOnline)
    }
    #endregion
    
    #region Invoke-ProjectRestore
    function Invoke-ProjectRestore([Project]$Project) {
        $path = $Project.File.FullName 
        if ($RestoreToolPreference -eq 'Nuget' -or -not $IsDotnetExeAvailable) {
            if ($IsNugetExeAvailable) {
                $command = 'nuget.exe'
                $params = 'restore', "$path", '-NonInteractive'
                Write-Debug -Message "Executing command: $command $params"
                & $command $params | Write-Debug
                return
            }
        }

        if ($IsDotnetExeAvailable) {
            $command = 'dotnet.exe'
            $params = 'restore', "$path"
            Write-Debug -Message "Executing command: $command $params"
            & $command $params | Write-Debug
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

        Vulnerability([PSCustomObject]$serialized) {
            $this.Severity = $serialized.Severity
            $this.AdvisoryUrl = $serialized.AdvisoryUrl
            $this.GhsaId = $serialized.GhsaId
            $this.VersionRange = $serialized.VersionRange
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

        SolutionAudit([PSCustomObject]$serialized) {
            $this.SolutionPath = $serialized.SolutionPath
            $this.SolutionName = $serialized.SolutionName
            $this.Projects = $serialized.Projects
            $this.LegacyProjects = $serialized.LegacyProjects
            $this.VulnerabilityCount = $serialized.VulnerabilityCount
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

        ProjectAudit([PSCustomObject]$serialized) {
            $this.ProjectName = $serialized.ProjectName
            $this.ProjectPath = $serialized.ProjectPath
            $this.VulnerablePackages = $serialized.VulnerablePackages
            $this.VulnerabilityCount = $serialized.VulnerabilityCount
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

        PackageAudit([Package]$package, [Vulnerability[]]$vulnerabilities) {
            $this.PackageName = $package.Name
            $this.PackageVersion = $package.Version
            $this.Vulnerabilities = $vulnerabilities
            $this.FirstPatchedVersion = $this.GetPatchedVersion()
            $this.VulnerabilityCount = [VulnerabilityCount]::Create($this.Vulnerabilities)
        }

        PackageAudit([PSCustomObject]$serialized) {
            $this.PackageName = $serialized.PackageName
            $this.PackageVersion = $serialized.PackageVersion
            $this.Vulnerabilities = $serialized.Vulnerabilities
            $this.VulnerabilityCount = $serialized.VulnerabilityCount
            $this.FirstPatchedVersion = $serialized.FirstPatchedVersion
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
            $this.Vulnerabilities | Where-Object { $_.VersionRange.IsMaxInclusive } | ForEach-Object {
                if ($_.VersionRange.Max -gt $maxPatchedVersion) {
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

        VulnerabilityCount([PSCustomObject]$serialized) {
            $this.Total = $serialized.Total
            $this.Low = $serialized.Low
            $this.Moderate = $serialized.Moderate
            $this.High = $serialized.High
            $this.Critical = $serialized.Critical
        }
    
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

        SolutionAuditVulnerabilityCount([PSCustomObject]$serialized) {
            $this.Modern = $serialized.Modern
            $this.Legacy = $serialized.Legacy
            $this.All = $serialized.All
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

    #region Package
    class Package {
        [string]$Name
        [version]$Version

        Package([string]$name, [string]$version) {
            $this.Name = $name.ToLower()
            $this.Version = ConvertTo-Version $version
        }

        [string]ToString() {
            return $this.Name + $this.Version.ToString()
        }
    }
    #endregion

    #region Project
    class Project {
        [System.IO.FileInfo]$File
        [System.IO.FileInfo]$Solution
        [bool]$IsLegacy
        hidden [System.IO.FileInfo]$PackagesConfig

        Project([string]$projectPath, [string]$solutionPath) {
            $this.File = $projectPath
            $this.Solution = $solutionPath
            $this.PackagesConfig = $this.GetPackagesConfig()
            $this.IsLegacy = $null -ne $this.PackagesConfig
        }

        [bool]HasPackageReferences() {
            $packageReferences = [xml](Get-Content -Path $this.File.FullName) `
            | Select-Xml -XPath './/PackageReference' -ErrorAction SilentlyContinue `
            | Select-Object -ExpandProperty Node
            return $null -ne $packageReferences
        }

        hidden [System.IO.FileInfo]GetPackagesConfig() {
            return Get-ChildItem -Path $this.File.Directory.FullName -Filter 'packages.config' -ErrorAction SilentlyContinue -Force
        }
    }
    #endregion
    #endregion
    
    #region VulnerabilityAuditor
    class VulnerabilityAuditor {
        hidden [string]$NugetVulnerabilityIndexUrl
        hidden [hashtable]$Base
        hidden [hashtable]$Update
        hidden [hashtable]$AdvisoriesCache
        hidden [hashtable]$AuditCache

        VulnerabilityAuditor() {
            $this.NugetVulnerabilityIndexUrl = 'https://api.nuget.org/v3/vulnerabilities/index.json'
            $this.AdvisoriesCache = @{}
            $this.AuditCache = @{}

            $index = Invoke-RestMethod $this.NugetVulnerabilityIndexUrl

            $this.Base = [VulnerabilityAuditor]::FetchNuGetData($index, 'base')
            $this.Update = [VulnerabilityAuditor]::FetchNuGetData($index, 'update')
        }

        VulnerabilityAuditor([PSCustomObject]$serialized) {
            $this.NugetVulnerabilityIndexUrl = $serialized.NugetVulnerabilityIndexUrl
            $this.Base = $serialized.Base
            $this.Update = $serialized.Update
            $this.AdvisoriesCache = @{}
            $this.AuditCache = @{}
        }

        hidden static [hashtable]FetchNuGetData($index, [string]$nugetStoreId) {
            $response = Invoke-WebRequest ($index | Where-Object -Property '@name' -eq $nugetStoreId).'@id'
            try {
                return $response.Content | ConvertFrom-Json -AsHashTable
            }
            catch {
                $dict = @{}
                $json = $response.Content | ConvertFrom-Json
                $json.PSObject.Properties | ForEach-Object { $dict[$_.Name] = $_.Value }
                return $dict
            }
        }

        [SolutionAudit]RunSolutionAudit([System.IO.FileInfo]$solutionFile, [bool]$findPatchedOnline) {
            $projects = [VulnerabilityAuditor]::GetModernAndLegacyProjects($solutionFile)
            $legacyAudits = $projects.Legacy | ForEach-Object { $this.RunProjectAudit($_, $findPatchedOnline) }
            $audits = $projects.Modern | ForEach-Object { $this.RunProjectAudit($_, $findPatchedOnline) }
            return [SolutionAudit]::new($solutionFile, $legacyAudits, $audits)
        }

        [SolutionAudit]RunModernSolutionAudit([System.IO.FileInfo]$solutionFile, [bool]$findPatchedOnline) {
            $projects = [VulnerabilityAuditor]::GetModernAndLegacyProjects($solutionFile)
            $audits = $projects.Modern | ForEach-Object { $this.RunProjectAudit($_, $findPatchedOnline) }
            $projects.Legacy | ForEach-Object {
                $name = Join-Path -Path $_.File.Directory.Name -ChildPath $_.File.Name
                Write-Warning -Message "ProjectsToScan='Modern' - Ignoring legacy project: $name"
            }
            return [SolutionAudit]::new($solutionFile, @(), $audits)
        }

        [SolutionAudit]RunLegacySolutionAudit([System.IO.FileInfo]$solutionFile, [bool]$findPatchedOnline) {
            $projects = [VulnerabilityAuditor]::GetModernAndLegacyProjects($solutionFile)
            $legacyAudits = $projects.Legacy | ForEach-Object { $this.RunProjectAudit($_, $findPatchedOnline) }
            $projects.Modern | ForEach-Object {
                $name = Join-Path -Path $_.File.Directory.Name -ChildPath $_.File.Name
                Write-Warning -Message "ProjectsToScan='Legacy' - Ignoring modern project: $name"
            }
            return [SolutionAudit]::new($solutionFile, $legacyAudits, @())
        }

        hidden static [PSCustomObject]GetModernAndLegacyProjects([System.IO.FileInfo]$solutionFile) {
            $projects = [VulnerabilityAuditor]::ParseSolutionFile($solutionFile)
            if (!$projects) {
                return [PSCustomObject]@{
                    Legacy = @()
                    Modern = @()
                }
            }
            return [PSCustomObject]@{
                Legacy = $projects | Where-Object { $_.IsLegacy } 
                Modern = $projects | Where-Object { -not $_.IsLegacy } 
            }
        }

        hidden [ProjectAudit]RunProjectAudit([Project]$project, [bool]$findPatchedOnline) {
            $packages = if ($project.IsLegacy) { [VulnerabilityAuditor]::ReadPackagesConfig($project) } 
            else { [VulnerabilityAuditor]::ReadProjectAssetsJson($project) }

            $audits = $packages `
            | ForEach-Object { $this.RunPackageAudit($_, $findPatchedOnline) } `
            | Where-Object { $_.VulnerabilityCount.Total -gt 0 }
            return [ProjectAudit]::new($project, $audits)
        }

        hidden static [Package[]]ReadPackagesConfig([Project]$project) {
            $packages = [xml](Get-Content $project.PackagesConfig.FullName) `
            | Select-Xml -XPath './/package' `
            | Select-Object -ExpandProperty Node `
            | ForEach-Object {
                [Package]::new($_.id, $_.version)
            }
            if (!$packages) { return @() }
            return $packages
        }

        hidden static [Package[]]ReadProjectAssetsJson([Project]$project) {
            if (!$project.HasPackageReferences()) {
                return @()
            }

            $projectAssetsJson = Get-ProjectAssetsJson $project
            if (!$projectAssetsJson) {
                return @()
            }

            $projectAssetsContent = Get-Content -Path $projectAssetsJson 
            try {
                $projectAssetsParsed = $projectAssetsContent | ConvertFrom-Json -AsHashTable
                $packages = $projectAssetsParsed.libraries.Values `
                | ForEach-Object {
                    if ($_.type -eq 'package') {
                        ($name, $version) = $_.path.Split('/')
                        [Package]::new($name, $version)
                    }
                }
            }
            catch {
                $projectAssetsParsed = $projectAssetsContent | ConvertFrom-Json
                $packages = $projectAssetsParsed.libraries.PSObject.Properties `
                | Select-Object -ExpandProperty Value `
                | ForEach-Object {
                    if ($_.type -eq 'package') {
                        ($name, $version) = $_.path.Split('/')
                        [Package]::new($name, $version)
                    }
                }
            }
            if (!$packages) { return @() }
            return $packages
        }
    
        [PackageAudit]RunPackageAudit([Package]$package, [bool]$findPatchedOnline) {
            $cacheKey = $package.ToString()
            if ($this.AuditCache.ContainsKey($cacheKey)) {
                return $this.AuditCache[$cacheKey]
            }

            $vBase = $this.SearchInData($this.Base, $package)
            $vUpdate = $this.SearchInData($this.Update, $package)
            $allVulnerabilities = $($vBase; $vUpdate)

            $audit = [PackageAudit]::new($package, $allVulnerabilities)
            if ($allVulnerabilities.Count -gt 0 -and -not $audit.FirstPatchedVersion -and $findPatchedOnline) {
                $patchedVersion = $this.FindPatchedVersionOnline($allVulnerabilities)
                $audit.FirstPatchedVersion = $patchedVersion
            }
            
            $this.AuditCache[$cacheKey] = $audit
            return $audit
        }
    
        hidden [Vulnerability[]]SearchInData([hashtable]$data, [Package]$package) {
            if (!$data.ContainsKey($package.Name)) {
                return @()
            }

            $vulnerabilities = $data[$package.Name]  `
            | ForEach-Object {
                $vrange = [VersionRange]::Parse($_.versions)
                [Vulnerability]::new($_.severity, $_.url, $vrange)
            } `
            | Where-Object { $_.VersionRange.CheckInRange($package.Version) }

            if (!$vulnerabilities) {
                return @()
            }
            return $vulnerabilities
        }

        hidden [string]FindPatchedVersionOnline([Vulnerability[]]$vulnerabilities) {
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
                | ForEach-Object { ConvertTo-Version $_ } `
            }
            return ($patchedVersions | Sort-Object -Descending)[0]
        }
    
        hidden static [Project[]]ParseSolutionFile([System.IO.FileInfo]$solutionFile) {
            $content = Get-Content -Path $solutionFile.FullName
            $solutionDir = $solutionFile.Directory.FullName

            $projects = $content `
            | Where-Object { [VulnerabilityAuditor]::IsProjectLine($_) } `
            | ForEach-Object {
                ($name, $path) = $_.Split(',')
                ($path, $guid) = $path.Split('{')
                $path = $path.Replace('"', '').Trim()
                Join-Path -Path $solutionDir -ChildPath $path
            } `
            | Where-Object { Test-Path -Path $_ } `
            | Sort-Object `
            | ForEach-Object { [Project]::new($_, $solutionFile.FullName) }

            if (!$projects) {
                return @()
            }
            return $projects
        }

        hidden static [bool]IsProjectLine([string]$line) {
            $ProjectLineBegin = 'project("'
            $CsprojExtension = '.csproj'
            $line = $line.ToLowerInvariant()
            return $line.Contains($ProjectLineBegin) -and $line.Contains($CsprojExtension)
        }

        [PSCustomObject]Serialize() {
            return [PSCustomObject]@{
                Base                       = $this.Base
                Update                     = $this.Update
                NugetVulnerabilityIndexUrl = $this.NugetVulnerabilityIndexUrl
            }
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
        hidden static [string[]]$Brackets = "(", ")", "[", "]"

        VersionRange() {
            $this.Min = [VersionRange]::DefaultMin
            $this.Max = [VersionRange]::DefaultMax
            $this.IsMinInclusive = $false
            $this.IsMaxInclusive = $false
        }

        VersionRange([psobject]$serialized) {
            $this.Min = $serialized.Min
            $this.Max = $serialized.Max
            $this.IsMinInclusive = $serialized.IsMinInclusive
            $this.IsMaxInclusive = $serialized.IsMaxInclusive
        }
    
        static [VersionRange]Parse([string]$rangeString) {
            ($min, $max) = $rangeString.Split(',')
            $vrange = [VersionRange]::new()
            $vrange.IsMinInclusive = $min.StartsWith('[')
            $vrange.IsMaxInclusive = $max.EndsWith(']')
            
            # set Min version
            $minVersion = ConvertTo-Version ([VersionRange]::RemoveBracketsFromVersionString($min))
            if ($minVersion) {
                $vrange.Min = $minVersion
            }
    
            # set Max version
            $maxVersion = ConvertTo-Version ([VersionRange]::RemoveBracketsFromVersionString($max))
            if ($maxVersion) {
                $vrange.Max = $maxVersion
            }
    
            return $vrange     
        }

        static [string]RemoveBracketsFromVersionString([string]$versionString) {
            [VersionRange]::Brackets | ForEach-Object { $versionString = $versionString.Replace($_, '') }
            return $versionString
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
        #endregion
    }
}
. $CustomDefinitions

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

#region Invoke-PluralScan
function Invoke-PluralScan([System.IO.FileInfo[]]$Solutions) {
    if ($Solutions.Count -eq 1) {
        $auditor = [VulnerabilityAuditor]::new()
        return Invoke-SolutionVulnerabilityScan $auditor $Solutions[0] $ProjectsToScan $FindPatchedOnline
    }  

    if ($Parallel) {
        $cpuCount = (Get-CimInstance Win32_ComputerSystem).NumberOfLogicalProcessors
        $i = 0
        $batches = $Solutions | ForEach-Object {
            [PSCustomObject]@{
                Solution = $_.FullName
                BatchId  = $i++ % $cpuCount
            }
        } | Group-Object -Property BatchId

        $auditor = [VulnerabilityAuditor]::new()
        $auditorSerialized = $auditor.Serialize()
        $scriptBlock = {
            $ErrorActionPreference = $using:ErrorActionPreference
            $WarningPreference = $using:WarningPreference   
            $DebugPreference = $using:DebugPreference
            $IsNugetExeAvailable = $using:IsNugetExeAvailable
            $IsDotnetExeAvailable = $using:IsDotnetExeAvailable
            $FindPatchedOnline = $using:FindPatchedOnline
            $ProjectsToScan = $using:ProjectsToScan
            $Restore = $using:Restore
            $RestoreActionPreference = $using:RestoreActionPreference
            $RestoreToolPreferenc = $using:RestoreToolPreferenc

            $customDefinitions = [scriptblock]::Create($using:CustomDefinitions)
            . $customDefinitions
          
            $paths = $input.Group | Select-Object -ExpandProperty Solution
            $auditor = [VulnerabilityAuditor]::new($using:auditorSerialized)

            return $paths | ForEach-Object {
                $audit = Invoke-SolutionVulnerabilityScan $auditor $_ $using:ProjectsToScan $using:FindPatchedOnline
                ConvertTo-StandardObject $audit
            }
        }

        try {    
            $jobResults = $batches | ForEach-Object {
                $_ | Start-ThreadJob -ScriptBlock $scriptBlock 
            } | Receive-Job -Wait -AutoRemoveJob
        }
        catch {
            $jobResults = $batches | ForEach-Object {
                $_ | Start-Job -ScriptBlock $scriptBlock 
            } | Receive-Job -Wait -AutoRemoveJob
        }
        finally {
            $results = $jobResults | ForEach-Object { [SolutionAudit]::new($_) }
        }   
    }
    else {
        $auditor = [VulnerabilityAuditor]::new()
        $results = $Solutions | ForEach-Object { 
            Invoke-SolutionVulnerabilityScan $auditor $_ $ProjectsToScan $FindPatchedOnline
        }
    }
  
    return $results
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
    $auditor = [VulnerabilityAuditor]::new()
    $finalResult = Invoke-SolutionVulnerabilityScan $auditor $slnFile $ProjectsToScan $FindPatchedOnline
}
elseif ($Recurse) {
    $solutionPaths = Get-ChildItem -Path $SolutionPath -Filter *.sln -Recurse -Force -ErrorAction SilentlyContinue
    $finalResult = Invoke-PluralScan -Solutions $solutionPaths
}
else {
    $slnFile = Get-ChildItem -Path $SolutionPath -Filter *.sln -Force -ErrorAction SilentlyContinue
    if ($null -eq $slnFile) {
        throw "Provided directory does not contain solution file. Use command with: '-Recurse' switch to search for all solutions in directory tree"
    }
    if ($slnFile -is [System.Collections.ICollection]) {
        $files = [string]::Join(', ', $slnFile)
        throw "Provided directory contains multiple solution files ($files). Specify solution file directly or use command with: '-Recurse' switch to search for all solutions in directory tree"
    }
    $auditor = [VulnerabilityAuditor]::new()
    $finalResult = Invoke-SolutionVulnerabilityScan $auditor $slnFile $ProjectsToScan $FindPatchedOnline
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
