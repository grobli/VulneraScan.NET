<# 
.SYNOPSIS
    Performs vulnerability scan of NuGet packages in .NET solutions.
#>

#Requires -Version 5.1
[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)][string]$SolutionPath,
    [Parameter()][ValidateSet('json', 'xml')]$Format,
    [Parameter()][switch]$Recurse,
    [Parameter()][switch]$BuildBreaker,
    [Parameter()][ValidateSet('Low', 'Moderate', 'High', 'Critical')]$MinimumBreakLevel,
    [Parameter()][switch]$FindPatched
)

<# 
    define all custom functions and classes inside wrapper ScriptBlock 
    in order to use them in parallel execution with "Start-Job" 
#>
$CustomDefinitions = {
    #region CommonFunctions
    function Get-PackagesConfig([System.IO.FileInfo]$projectCsproj) {
        Get-ChildItem -Path $projectCsproj.Directory -Filter 'packages.config' -ErrorAction SilentlyContinue -Force
    }

    function Get-ProjectAssetsJson([System.IO.FileInfo]$projectCsproj) {
        $path = Join-Path -Path $projectCsproj.Directory.FullName -ChildPath 'obj\project.assets.json'
        try {
            Get-ChildItem -Path $path -ErrorAction Stop -Force
        }
        catch {
            throw "project.assets.json for project: '$projectCsproj' not found! Run 'nuget restore' or 'dotnet restore' on the project's solution before running this command."
        }
    }
    
    function Test-LegacyNugetProject([System.IO.FileInfo]$projectCsproj) {
        $packageReferences = [xml](Get-Content -Path $projectCsproj.FullName) `
        | Select-Xml -XPath './/PackageReference' -ErrorAction SilentlyContinue `
        | Select-Object -ExpandProperty Node
    
        $packagesConfig = Get-PackagesConfig $projectCsproj
    
        return $packageReferences.Count -eq 0 -and $packagesConfig
    }

    function Test-ModernNugetProject([System.IO.FileInfo]$projectCsproj) {
        $project = [xml](Get-Content -Path $projectCsproj.FullName) `
        | Select-Xml -XPath './Project' -ErrorAction SilentlyContinue `
        | Select-Object -ExpandProperty Node
    
        $sdkAttribute = $project.Attributes.GetNamedItem('Sdk')
        return ([bool]$sdkAttribute)
    }
    
    function Test-HasProperty([System.Object]$object, [string]$propertyName) {
        return [bool](Get-Member -InputObject $object -Name $propertyName -MemberType Properties)
    }

    function Convert-NormalizedVersionString([string]$versionString) {
        @("(", ")", "[", "]") | ForEach-Object { $versionString = $versionString.Replace($_, '') }
        ($versionString, $_) = $versionString.Split('-')
        return $versionString
    }

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
    
        $standardObject = [psobject]::new()
        Get-Member -InputObject $InputObject -MemberType Properties -Force `
        | Where-Object { $_.Name -ne 'pstypenames' } `
        | ForEach-Object {
            $property = ConvertTo-StandardObject $InputObject.($_.Name)
            Add-Member -InputObject $standardObject -NotePropertyName $_.Name -NotePropertyValue $property
        }
        return $standardObject
    }
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
        [string]$GhsaId
        [Severity]$Severity
        [VersionRange]$VersionRange
        [string]$AdvisoryUrl
    
        Vulnerability([int]$severity, [string]$url, [VersionRange]$vrange) {
            $this.Severity = $severity
            $this.AdvisoryUrl = $url
            $lastIndexOfUriSeparator = $this.AdvisoryUrl.LastIndexOf('/') + 1
            $this.GhsaId = $this.AdvisoryUrl.Substring($lastIndexOfUriSeparator)
            $this.VersionRange = $vrange
        }

        Vulnerability([psobject]$serialized) {
            $this.Severity = $serialized.Severity
            $this.AdvisoryUrl = $serialized.AdvisoryUrl
            $this.GhsaId = $serialized.GhsaId
            $this.VersionRange = $serialized.VersionRange
        }
    }
    #endregion

    #region SolutionAuditPlural
    class SolutionAuditPlural {
        [SolutionAudit[]]$Solutions
        [VulnerabilityCount]$VulnerabilityCount

        SolutionAuditPlural([SolutionAudit[]]$solutions) {
            $counts = $solutions | Select-Object -ExpandProperty VulnerabilityCount
            $this.Solutions = $solutions
            $this.VulnerabilityCount = [VulnerabilityCount]::SumCounts($counts)
        }
    }
    #endregion
    
    #region SolutionAudit
    class SolutionAudit {
        [string]$SolutionName
        [VulnerabilityCount]$VulnerabilityCount
        [ProjectAudit[]]$Projects
        [ProjectAudit[]]$LegacyProjects
        [string]$FullPath
    
        SolutionAudit([System.IO.FileInfo]$solutionFile, [ProjectAudit[]]$legacyAudits, [ProjectAudit[]]$audits) {
            $this.FullPath = $solutionFile.FullName
            $this.SolutionName = $solutionFile.Name
            $this.LegacyProjects = $legacyAudits
            $this.Projects = $audits
            $counts = $($this.LegacyProjects; $this.Projects) | Select-Object -ExpandProperty VulnerabilityCount
            $this.VulnerabilityCount = [VulnerabilityCount]::SumCounts($counts)
        }

        SolutionAudit([psobject]$serialized) {
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

        ProjectAudit([psobject]$serialized) {
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

        PackageAudit([string]$name, [version]$version, [Vulnerability[]]$vulnerabilities, [string]$firstPatchedVersion) {
            $this.PackageName = $name
            $this.PackageVersion = $version
            $this.Vulnerabilities = $vulnerabilities
            $this.FirstPatchedVersion = $firstPatchedVersion
            $this.VulnerabilityCount = [VulnerabilityCount]::Create($this.Vulnerabilities)
        }

        PackageAudit([string]$name, [version]$version, [Vulnerability[]]$vulnerabilities) {
            $this.PackageName = $name
            $this.PackageVersion = $version
            $this.Vulnerabilities = $vulnerabilities
            $this.VulnerabilityCount = [VulnerabilityCount]::Create($this.Vulnerabilities)
        }

        PackageAudit([psobject]$serialized) {
            $this.PackageName = $serialized.PackageName
            $this.PackageVersion = $serialized.PackageVersion
            $this.Vulnerabilities = $serialized.Vulnerabilities
            $this.VulnerabilityCount = $serialized.VulnerabilityCount
            $this.FirstPatchedVersion = $serialized.FirstPatchedVersion
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

        VulnerabilityCount() {}

        VulnerabilityCount([psobject]$serialized) {
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
    #endregion
    
    #region VulnerabilityAuditor
    class VulnerabilityAuditor {
        hidden [string]$NugetVulnerabilityIndexUrl
        hidden [System.Object]$Base
        hidden [System.Object]$Update
        hidden [hashtable]$AdvisoriesCache

        VulnerabilityAuditor() {
            $this.NugetVulnerabilityIndexUrl = 'https://api.nuget.org/v3/vulnerabilities/index.json'
            $this.AdvisoriesCache = @{}

            $index = Invoke-RestMethod $this.NugetVulnerabilityIndexUrl

            $this.Base = Invoke-RestMethod ($index | Where-Object -Property '@name' -eq base).'@id'
            $this.Update = Invoke-RestMethod ($index | Where-Object -Property '@name' -eq update).'@id'
        }

        VulnerabilityAuditor([psobject]$serialized) {
            $this.NugetVulnerabilityIndexUrl = $serialized.NugetVulnerabilityIndexUrl
            $this.Base = $serialized.Base
            $this.Update = $serialized.Update
        }

        [SolutionAudit]RunSolutionAudit([System.IO.FileInfo]$solutionFile, [bool]$findPatched) {
            $projectCsprojs = [VulnerabilityAuditor]::ParseSolutionFile($solutionFile)
            $legacyAudits = $projectCsprojs | Where-Object { Test-LegacyNugetProject $_ } | ForEach-Object {
                $this.RunLegacyProjectAudit($_, $findPatched)
            }
            $audits = $projectCsprojs | Where-Object { Test-ModernNugetProject $_ } | ForEach-Object {
                $this.RunProjectAudit($_, $findPatched)
            }

            return [SolutionAudit]::new($solutionFile, $legacyAudits, $audits)
        }
    
        [ProjectAudit]RunLegacyProjectAudit([System.IO.FileInfo]$projectCsproj, [bool]$findPatched) {
            $packagesConfig = Get-PackagesConfig $projectCsproj
            $packages = [xml](Get-Content $packagesConfig.FullName) `
            | Select-Xml -XPath './/package' `
            | Select-Object -ExpandProperty Node

            $audits = $packages | ForEach-Object {
                $version = Convert-NormalizedVersionString $_.version
                $audit = $this.RunPackageAudit($_.id, $version, $findPatched)
                if ($audit.VulnerabilityCount.Total -gt 0) {
                    $audit
                }
            }
            return [ProjectAudit]::new($projectCsproj, $audits)
        }

        [ProjectAudit]RunProjectAudit([System.IO.FileInfo]$projectCsproj, [bool]$findPatched) {
            $projectAssetsJson = Get-ProjectAssetsJson $projectCsproj
            $projectAssetsParsed = Get-Content -Path $projectAssetsJson | ConvertFrom-Json -AsHashtable

            $packages = $projectAssetsParsed.libraries.Values `
            | Where-Object { $_.type -eq 'package' } `
            | Select-Object -ExpandProperty path `
            | ForEach-Object {
                ($name, $version) = $_.Split('/')
                @{Name = $name; Version = $version } 
            }

            $audits = $packages | ForEach-Object {
                $version = Convert-NormalizedVersionString $_.Version
                $audit = $this.RunPackageAudit($_.Name, $version, $findPatched)
                if ($audit.VulnerabilityCount.Total -gt 0) {
                    $audit
                }
            }
            return [ProjectAudit]::new($projectCsproj, $audits)
        }
    
        [PackageAudit]RunPackageAudit([string]$packageName, [version]$packageVersion, [bool]$findPatched) {
            $vBase = [VulnerabilityAuditor]::SearchInData($this.Base, $packageName, $packageVersion)
            $vUpdate = [VulnerabilityAuditor]::SearchInData($this.Update, $packageName, $packageVersion)
            $allVulnerabilities = $($vBase; $vUpdate)

            if ($allVulnerabilities.Count -gt 0 -and $findPatched) {
                $patchedVersion = $this.FindPatchedVersion($allVulnerabilities)
                return [PackageAudit]::new($packageName, $packageVersion, $allVulnerabilities, $patchedVersion)
            }
            return [PackageAudit]::new($packageName, $packageVersion, $allVulnerabilities)
        }

        hidden [string]FindPatchedVersion([Vulnerability[]]$vulnerabilities) {
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
    
        hidden static [Vulnerability[]]SearchInData([System.Object]$data, [string]$packageName, [version]$packageVersion) {
            $vulnerabilities = New-Object Collections.Generic.List[Vulnerability]
            if (Test-HasProperty -object $data -propertyName $packageName) {
                $data.$packageName | ForEach-Object {
                    $vrange = [VersionRange]::Parse($_.versions)
                    $vulnerability = [Vulnerability]::new($_.severity, $_.url, $vrange)
                    if ($vulnerability.VersionRange.CheckInRange($packageVersion)) {
                        $vulnerabilities.Add($vulnerability)
                    }  
                }    
            } 
            return $vulnerabilities.ToArray()
        }
    
        hidden static [string[]]ParseSolutionFile([System.IO.FileInfo]$solutionFile) {
            $content = Get-Content -Path $solutionFile.FullName
            $solutionDir = $solutionFile.Directory.FullName

            $projects = $content | Where-Object { [VulnerabilityAuditor]::IsProjectLine($_) } | ForEach-Object {
                ($name, $path) = $_.Split(',')
                ($path, $guid) = $path.Split('{')
                $path = $path.Replace('"', '').Trim()
                Join-Path -Path $solutionDir -ChildPath $path
            }
            return $projects | Sort-Object
        }

        hidden static [bool]IsProjectLine([string]$line) {
            $ProjectLineBegin = 'project("'
            $CsprojExtension = '.csproj'
            $line = $line.ToLowerInvariant()
            return $line.Contains($ProjectLineBegin) -and $line.Contains($CsprojExtension)
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
function Format-AuditResult($AuditResult) {
    if ($Depth -eq 0) {
        $Depth = 6
    }

    if ($AuditResult -is [System.Collections.ICollection]) {
        $AuditResult = [SolutionAuditPlural]::new($AuditResult)
        $Depth = 8
    }

    if ($Format -eq 'json') {
        return $AuditResult | ConvertTo-Json -Depth $Depth -Compress 
    }
    
    if ($Format -eq 'xml') {
        return $AuditResult | ConvertTo-Xml -Depth $Depth -As String
    }
    
    $AuditResult
}

function Invoke-ScannerInParallel([System.IO.FileInfo[]]$Solutions, [Parameter(Mandatory = $false)][bool]$FindPatchedVersion) {
    $auditor = [VulnerabilityAuditor]::new()

    if ($Solutions.Count -eq 1) {
        $result = $auditor.RunSolutionAudit($Solutions[0], $FindPatchedVersion)
        $result
    }  

    try {
        Get-Command -Name Start-ThreadJob -ErrorAction Stop | Out-Null

        $scriptBlock = {
            param([psobject]$auditorObject)
            
            $path = $input | Select-Object -ExpandProperty FullName
    
            $customDefinitions = [scriptblock]::Create($using:CustomDefinitions)
            . $customDefinitions
    
            [VulnerabilityAuditor]$a = $auditorObject
            $audit = $a.RunSolutionAudit($path, $using:FindPatchedVersion)
    
            ConvertTo-StandardObject $audit
        }

        $jobResults = $Solutions | ForEach-Object {
            $_ | Start-ThreadJob -ScriptBlock $scriptBlock -ArgumentList (ConvertTo-StandardObject $auditor)
        } | Receive-Job -Wait -AutoRemoveJob
        $results = $jobResults | ForEach-Object { [SolutionAudit]$_ }
    }
    catch {
        # if Start-ThreadJob not found then fallback to sequential execution - Start-Job is to heavy
        $results = $Solutions | ForEach-Object { $auditor.RunSolutionAudit($_, $FindPatchedVersion) }
    }   

    return $results
}
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
    $finalResult = $auditor.RunSolutionAudit($slnFile, $FindPatched)
}
elseif ($Recurse) {
    $solutionPaths = @(Get-ChildItem -Path $SolutionPath -Filter *.sln -Recurse -Force -ErrorAction SilentlyContinue)
    $finalResult = Invoke-ScannerInParallel -Solutions $solutionPaths -FindPatchedVersion $FindPatched
}
else {
    $auditor = [VulnerabilityAuditor]::new()
    $slnFile = Get-ChildItem -Path $SolutionPath -Filter *.sln -Force -ErrorAction SilentlyContinue
    if ($null -eq $slnFile) {
        throw "Provided directory does not contain solution file. Use command with: '-Recurse' switch to search for all solutions in directory tree"
    }
    if ($slnFile -is [System.Collections.ICollection]) {
        $files = [string]::Join(', ', $slnFile)
        throw "Provided directory contains multiple solution files ($files). Specify solution file directly or use command with: '-Recurse' switch to search for all solutions in directory tree"
    }
    $finalResult = $auditor.RunSolutionAudit($slnFile, $FindPatched)
}

Format-AuditResult $finalResult

if ($BuildBreaker) {
    if ($null -eq $MinimumBreakLevel) {
        if ($finalResult.VulnerabilityCount.Total -gt 0) { exit 1 }
        exit 0
    }
    if ($finalResult.VulnerabilityCount.GetTotalFromLevel($MinimumBreakLevel) -gt 0) { exit 1 }
}
#endregion
