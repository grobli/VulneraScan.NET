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
    [Parameter()][ValidateSet('OnDemand', 'Always')]$RestorePreference
)
#endregion
<# 
    define all custom functions and classes inside wrapper ScriptBlock 
    in order to use them in parallel execution with "Start-Job" 
#>

#region SetDefaults
if ([string]::IsNullOrEmpty($MinimumBreakLevel)) { $MinimumBreakLevel = 'Low' }
if ([string]::IsNullOrEmpty($BreakOnProjectType)) { $BreakOnProjectType = 'All' }
if ([string]::IsNullOrEmpty($ProjectsToScan)) { $ProjectsToScan = 'All' }
if ([string]::IsNullOrEmpty($RestorePreference)) { $RestorePreference = 'OnDemand' }
#endregion


$CustomDefinitions = {
    #region CommonFunctions
    #region Get-PackagesConfig
    function Get-PackagesConfig([System.IO.FileInfo]$projectCsproj) {
        Get-ChildItem -Path $projectCsproj.Directory -Filter 'packages.config' -ErrorAction SilentlyContinue -Force
    }
    #endregion

    #region Get-ProjectAssetsJson
    function Get-ProjectAssetsJson([System.IO.FileInfo]$projectCsproj) {
        if ($Restore -and $RestorePreference -eq 'Always') {
            Invoke-DotnetRestore $projectCsproj
        }

        $path = Join-Path -Path $projectCsproj.Directory.FullName -ChildPath 'obj\project.assets.json'
        try {
            Get-ChildItem -Path $path -ErrorAction Stop -Force
        }
        catch {
            if ($Restore) {
                Invoke-DotnetRestore $projectCsproj
                return Get-ChildItem -Path $path -ErrorAction Stop -Force
            }
            throw "project.assets.json for project: '$projectCsproj' not found! Use '-Restore' switch to automatically restore project or run manually 'nuget restore' or 'dotnet restore' on the project's solution before running this script."
        }
    }
    #endregion
    
    #region Test-LegacyNugetProject
    function Test-LegacyNugetProject([System.IO.FileInfo]$projectCsproj) {
        $packageReferences = [xml](Get-Content -Path $projectCsproj.FullName) `
        | Select-Xml -XPath './/PackageReference' -ErrorAction SilentlyContinue `
        | Select-Object -ExpandProperty Node
    
        $packagesConfig = Get-PackagesConfig $projectCsproj
    
        return $packageReferences.Count -eq 0 -and $packagesConfig
    }
    #endregion

    #region Test-ModernNugetProject
    function Test-ModernNugetProject([System.IO.FileInfo]$projectCsproj) {
        $project = [xml](Get-Content -Path $projectCsproj.FullName) `
        | Select-Xml -XPath './Project' -ErrorAction SilentlyContinue `
        | Select-Object -ExpandProperty Node

        if ($null -eq $project) { return $false }
    
        $sdkAttribute = $project.Attributes.GetNamedItem('Sdk')
        return $null -ne $sdkAttribute
    }
    #endregion

    #region Convert-NormalizedVersionString
    function Convert-NormalizedVersionString([string]$versionString) {
        @("(", ")", "[", "]") | ForEach-Object { $versionString = $versionString.Replace($_, '') }
        ($versionString, $_) = $versionString.Split('-')
        return $versionString
    }
    #endregion

    #region Convert-NormalizedVersionString
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
    
    #region Invoke-DotnetRestore
    function Invoke-DotnetRestore([System.IO.FileInfo]$ProjectCsproj) {
        try {
            dotnet.exe restore $ProjectCsproj.FullName | Write-Debug
        }
        catch {
            nuget.exe restore $ProjectCsproj.FullName | Write-Debug
        }
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
        [string]$GhsaId
        [Severity]$Severity
        [VersionRange]$VersionRange
    
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
        [string]$FullPath
    
        SolutionAudit([System.IO.FileInfo]$solutionFile, [ProjectAudit[]]$legacyAudits, [ProjectAudit[]]$audits) {
            $this.FullPath = $solutionFile.FullName
            $this.SolutionName = $solutionFile.Name
            $this.LegacyProjects = $legacyAudits
            $this.Projects = $audits
            $this.VulnerabilityCount = [SolutionAuditVulnerabilityCount]::new($legacyAudits, $audits)
        }

        SolutionAudit([PSCustomObject]$serialized) {
            $this.FullPath = $serialized.FullPath
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
        [string]$FullPath
    
        ProjectAudit([System.IO.FileInfo]$projectCsproj, [PackageAudit[]]$audits) {
            $this.FullPath = $projectCsproj.FullName
            $this.ProjectName = $projectCsproj.Name
            $this.VulnerablePackages = $audits
            $counts = $audits | Select-Object -ExpandProperty VulnerabilityCount
            $this.VulnerabilityCount = [VulnerabilityCount]::SumCounts($counts)
        }

        ProjectAudit([PSCustomObject]$serialized) {
            $this.FullPath = $serialized.FullPath
            $this.ProjectName = $serialized.ProjectName
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

        PackageAudit([string]$name, [version]$version, [Vulnerability[]]$vulnerabilities) {
            $this.PackageName = $name
            $this.PackageVersion = $version
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
                $json | Get-Member -MemberType NoteProperty `
                | Select-Object -ExpandProperty Name `
                | ForEach-Object {
                    $dict[$_] = $json.$_
                }
                return $dict
            }
        }

        [SolutionAudit]RunSolutionAudit([System.IO.FileInfo]$solutionFile, [bool]$findPatchedOnline) {
            $csprojs = [VulnerabilityAuditor]::GetModernAndLegacyCsprojs($solutionFile)
            $legacyAudits = $csprojs.Legacy | ForEach-Object {
                $this.RunLegacyProjectAudit($_, $findPatchedOnline)
            }
            $audits = $csprojs.Modern | ForEach-Object {
                $this.RunProjectAudit($_, $findPatchedOnline)
            }
            return [SolutionAudit]::new($solutionFile, $legacyAudits, $audits)
        }

        [SolutionAudit]RunModernSolutionAudit([System.IO.FileInfo]$solutionFile, [bool]$findPatchedOnline) {
            $csprojs = [VulnerabilityAuditor]::GetModernAndLegacyCsprojs($solutionFile)
            $audits = $csprojs.Modern | ForEach-Object {
                $this.RunProjectAudit($_, $findPatchedOnline)
            }
            $csprojs.Legacy | ForEach-Object {
                $name = Join-Path -Path $_.Directory.Name -ChildPath $_.Name
                Write-Warning -Message "ProjectsToScan='Legacy' - Ignoring project: $name"
            }
            return [SolutionAudit]::new($solutionFile, @(), $audits)
        }

        [SolutionAudit]RunLegacySolutionAudit([System.IO.FileInfo]$solutionFile, [bool]$findPatchedOnline) {
            $csprojs = [VulnerabilityAuditor]::GetModernAndLegacyCsprojs($solutionFile)
            $legacyAudits = $csprojs.Legacy | ForEach-Object {
                $this.RunLegacyProjectAudit($_, $findPatchedOnline)
            }
            $csprojs.Modern | ForEach-Object {
                $name = Join-Path -Path $_.Directory.Name -ChildPath $_.Name
                Write-Warning -Message "ProjectsToScan='Modern' - Ignoring project: $name"
            }
            return [SolutionAudit]::new($solutionFile, $legacyAudits, @())
        }

        hidden static [PSCustomObject]GetModernAndLegacyCsprojs([System.IO.FileInfo]$solutionFile) {
            $projectCsprojs = [VulnerabilityAuditor]::ParseSolutionFile($solutionFile)

            if (!$projectCsprojs) {
                return [PSCustomObject]@{
                    Legacy = @()
                    Modern = @()
                }
            }

            $legacy = $projectCsprojs | Where-Object { Test-LegacyNugetProject $_ } 
            $modern = $projectCsprojs | Where-Object { Test-ModernNugetProject $_ } 
            return [PSCustomObject]@{
                Legacy = $legacy
                Modern = $modern
            }
        }
    
        [ProjectAudit]RunLegacyProjectAudit([System.IO.FileInfo]$projectCsproj, [bool]$findPatchedOnline) {
            $packagesConfig = Get-PackagesConfig $projectCsproj
            $packages = [xml](Get-Content $packagesConfig.FullName) `
            | Select-Xml -XPath './/package' `
            | Select-Object -ExpandProperty Node

            $audits = $packages | ForEach-Object {
                $version = Convert-NormalizedVersionString $_.version
                $audit = $this.RunPackageAudit($_.id, $version, $findPatchedOnline)
                if ($audit.VulnerabilityCount.Total -gt 0) {
                    $audit
                }
            }
            return [ProjectAudit]::new($projectCsproj, $audits)
        }

        [ProjectAudit]RunProjectAudit([System.IO.FileInfo]$projectCsproj, [bool]$findPatchedOnline) {
            $projectAssetsJson = Get-ProjectAssetsJson $projectCsproj
            $projectAssetsContent = Get-Content -Path $projectAssetsJson 

            try {
                $projectAssetsParsed = $projectAssetsContent | ConvertFrom-Json -AsHashTable
                $packages = $projectAssetsParsed.libraries.Values `
                | Where-Object { $_.type -eq 'package' } `
                | ForEach-Object {
                    ($name, $version) = $_.path.Split('/')
                    [PSCustomObject]@{ Name = $name; Version = $version } 
                }
            }
            catch {
                $projectAssetsParsed = $projectAssetsContent | ConvertFrom-Json
                $packages = $projectAssetsParsed.libraries `
                | Get-Member -MemberType NoteProperty `
                | Select-Object -ExpandProperty Name `
                | Where-Object { $projectAssetsParsed.libraries.$_.type -eq 'package' } `
                | ForEach-Object {
                    ($name, $version) = $projectAssetsParsed.libraries.$_.path.Split('/')
                    [PSCustomObject]@{Name = $name; Version = $version } 
                }
            }

            $audits = $packages | ForEach-Object {
                $version = Convert-NormalizedVersionString $_.Version
                $audit = $this.RunPackageAudit($_.Name, $version, $findPatchedOnline)
                if ($audit.VulnerabilityCount.Total -gt 0) {
                    $audit
                }
            }
            return [ProjectAudit]::new($projectCsproj, $audits)
        }
    
        [PackageAudit]RunPackageAudit([string]$packageName, [version]$packageVersion, [bool]$findPatchedOnline) {
            $cacheKey = $packageName + $packageVersion.ToString()
            if ($this.AuditCache.ContainsKey($cacheKey)) {
                return $this.AuditCache[$cacheKey]
            }

            $vBase = $this.SearchInData($this.Base, $packageName, $packageVersion)
            $vUpdate = $this.SearchInData($this.Update, $packageName, $packageVersion)
            $allVulnerabilities = $($vBase; $vUpdate)

            $audit = [PackageAudit]::new($packageName, $packageVersion, $allVulnerabilities)
            if ($allVulnerabilities.Count -gt 0 -and -not $audit.FirstPatchedVersion -and $findPatchedOnline) {
                $patchedVersion = $this.FindPatchedVersionOnline($allVulnerabilities)
                $audit.FirstPatchedVersion = $patchedVersion
            }
            
            $this.AuditCache[$cacheKey] = $audit
            return $audit
        }
    
        hidden [Vulnerability[]]SearchInData([hashtable]$data, [string]$packageName, [version]$packageVersion) {
            if (!$data.ContainsKey($packageName)) {
                return @()
            }

            $vulnerabilities = New-Object Collections.Generic.List[Vulnerability]
            $data[$packageName] | ForEach-Object {
                $vrange = [VersionRange]::Parse($_.versions)
                $vulnerability = [Vulnerability]::new($_.severity, $_.url, $vrange)
                if ($vulnerability.VersionRange.CheckInRange($packageVersion)) {
                    $vulnerabilities.Add($vulnerability)
                }  
            }    
            return $vulnerabilities.ToArray()
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
                | ForEach-Object { [version](Convert-NormalizedVersionString $_) } `
            }
            return ($patchedVersions | Sort-Object -Descending)[0]
        }
    
        hidden static [System.IO.FileInfo[]]ParseSolutionFile([System.IO.FileInfo]$solutionFile) {
            $content = Get-Content -Path $solutionFile.FullName
            $solutionDir = $solutionFile.Directory.FullName

            $projects = $content | Where-Object { [VulnerabilityAuditor]::IsProjectLine($_) } | ForEach-Object {
                ($name, $path) = $_.Split(',')
                ($path, $guid) = $path.Split('{')
                $path = $path.Replace('"', '').Trim()
                [System.IO.FileInfo](Join-Path -Path $solutionDir -ChildPath $path)
            }
            return $projects | Where-Object { Test-Path -Path $_.FullName } | Sort-Object
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
            $minVersionString = Convert-NormalizedVersionString $min
            if (![string]::IsNullOrEmpty($minVersionString)) {
                $vrange.Min = [version]$minVersionString
            }
    
            # set Max version
            $maxVersionString = Convert-NormalizedVersionString $max
            if (![string]::IsNullOrEmpty($maxVersionString)) {
                $vrange.Max = [version]$maxVersionString 
            }
    
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
            $customDefinitions = [scriptblock]::Create($using:CustomDefinitions)
            . $customDefinitions
            $WarningPreference = $using:WarningPreference   
            $DebugPreference = $using:DebugPreference

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
    $solutionPaths = @(Get-ChildItem -Path $SolutionPath -Filter *.sln -Recurse -Force -ErrorAction SilentlyContinue)
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
