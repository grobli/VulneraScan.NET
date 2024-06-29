#Requires -Version 5.1

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)][string]$SolutionPath,
    [Parameter()][ValidateSet('json', 'xml')]$OutputTo,
    [Parameter()][switch]$Recurse
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
    
    function Test-LegacyNugetProject([System.IO.FileInfo]$projectCsproj) {
        $packageReferences = [xml](Get-Content -Path $projectCsproj.FullName) `
        | Select-Xml -XPath './/PackageReference' -ErrorAction SilentlyContinue `
        | Select-Object -ExpandProperty Node
    
        $packagesConfig = Get-PackagesConfig $projectCsproj
    
        return $packageReferences.Count -eq 0 -and $packagesConfig
    }
    
    function Test-HasProperty([System.Object]$object, [string]$propertyName) {
        return [bool](Get-Member -InputObject $object -Name $propertyName -MemberType Properties)
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

    class Vulnerability {
        [Severity]$Severity
        [string]$AdvisoryUrl
        [VersionRange]$VersionRange
    
        Vulnerability([int]$severity, [string]$url, [VersionRange]$vrange) {
            $this.Severity = $severity
            $this.AdvisoryUrl = $url
            $this.VersionRange = $vrange
        }

        Vulnerability([psobject]$serialized) {
            $this.Severity = $serialized.Severity
            $this.AdvisoryUrl = $serialized.AdvisoryUrl
            $this.VersionRange = $serialized.VersionRange
        }
    }
    
    class SolutionAudit {
        [string]$SolutionName
        [VulnerabilityCount]$VulnerabilityCount
        [ProjectAudit[]]$LegacyProjects
        [string]$FullPath
    
        SolutionAudit([System.IO.FileInfo]$solutionFile, [ProjectAudit[]]$audits) {
            $this.FullPath = $solutionFile.FullName
            $this.SolutionName = $solutionFile.Name
            $this.LegacyProjects = $audits
            $counts = $audits | Select-Object -ExpandProperty VulnerabilityCount
            $this.VulnerabilityCount = [VulnerabilityCount]::SumCounts($counts)
        }

        SolutionAudit([psobject]$serialized) {
            $this.FullPath = $serialized.FullPath
            $this.SolutionName = $serialized.SolutionName
            $this.LegacyProjects = $serialized.LegacyProjects
            $this.VulnerabilityCount = $serialized.VulnerabilityCount
        }
    }
    
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
    
    class PackageAudit {
        [string]$PackageName
        [string]$PackageVersion
        [VulnerabilityCount]$VulnerabilityCount
        [Vulnerability[]]$Vulnerabilities 
    
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
        }
    }
    
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
    
    #region VulnerabilityAuditor
    class VulnerabilityAuditor {
        hidden [string]$NugetVulnerabilityIndexUrl
        hidden [System.Object]$Base
        hidden [System.Object]$Update

        VulnerabilityAuditor() {
            $this.NugetVulnerabilityIndexUrl = 'https://api.nuget.org/v3/vulnerabilities/index.json'

            $index = Invoke-RestMethod $this.NugetVulnerabilityIndexUrl

            $this.Base = Invoke-RestMethod ($index | Where-Object -Property '@name' -eq base).'@id'
            $this.Update = Invoke-RestMethod ($index | Where-Object -Property '@name' -eq update).'@id'
        }

        VulnerabilityAuditor([psobject]$serialized) {
            $this.NugetVulnerabilityIndexUrl = $serialized.NugetVulnerabilityIndexUrl
            $this.Base = $serialized.Base
            $this.Update = $serialized.Update
        }

        [SolutionAudit]RunSolutionAudit([System.IO.FileInfo]$solutionFile) {
            $projectCsprojs = [VulnerabilityAuditor]::ParseSolutionFile($solutionFile)
            $projectAudits = $projectCsprojs | Where-Object { Test-LegacyNugetProject $_ } | ForEach-Object {
                $this.RunProjectAudit($_)
            }
            return [SolutionAudit]::new($solutionFile, $projectAudits)
        }
    
        [ProjectAudit]RunProjectAudit([System.IO.FileInfo]$projectCsproj) {
            $packagesConfig = Get-PackagesConfig $projectCsproj
            $packages = [xml](Get-Content $packagesConfig.FullName) | Select-Xml -XPath './/package' | Select-Object -ExpandProperty Node
            $audits = $packages | ForEach-Object {
                $audit = $this.RunPackageAudit($_.id, $_.version)
                if ($audit.VulnerabilityCount.Total -gt 0) {
                    $audit
                }
            }
            return [ProjectAudit]::new($projectCsproj, $audits)
        }
    
        [PackageAudit]RunPackageAudit([string]$packageName, [version]$packageVersion) {
            $vBase = [VulnerabilityAuditor]::SearchInData($this.Base, $packageName, $packageVersion)
            $vUpdate = [VulnerabilityAuditor]::SearchInData($this.Update, $packageName, $packageVersion)
            return [PackageAudit]::new($packageName, $packageVersion, $($vBase; $vUpdate))
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
            $content = Get-Content -Path $solutionFile.FullName -Raw
            $allMatches = ([regex]'Project.*= (?<project>".*").*"{.*}"\sEndProject').Matches($content)
            $solutionParentDir = $solutionFile.Directory.Parent.FullName
            $paths = $allMatches | ForEach-Object {
                ([string]$name, [string]$path) = ($_.Groups['project'].Value).Split(',')
                $path = $path.Replace('"', '').Trim()
                Join-Path -Path $solutionParentDir -ChildPath $path
            }
            return $paths
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
            $minVersionString = [VersionRange]::NormalizeVersionString($min)
            if (![string]::IsNullOrEmpty($minVersionString)) {
                $vrange.Min = [version]$minVersionString
            }
    
            # set Max version
            $maxVersionString = [VersionRange]::NormalizeVersionString($max)
            if (![string]::IsNullOrEmpty($maxVersionString)) {
                $vrange.Max = [version]$maxVersionString 
            }
    
            return $vrange     
        }
    
        hidden static [string]NormalizeVersionString([string]$versionString) {
            @("(", ")", "[", "]") | ForEach-Object { $versionString = $versionString.Replace($_, '') }
            ($versionString, $_) = $versionString.Split('-')
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
function Format-AuditResult($AuditResult, [Parameter(Mandatory = $false)][int]$Depth) {
    if ($Depth -eq 0) {
        $Depth = 6
    }

    if ($OutputTo -eq 'json') {
        $AuditResult | ConvertTo-Json -Depth $Depth -Compress
        return
    }
    
    if ($OutputTo -eq 'xml') {
        $AuditResult | ConvertTo-Xml -Depth $Depth -As String
        return
    }
    
    $AuditResult
}

function Invoke-ScannerInParallel([System.IO.FileInfo[]]$Solutions) {
    $auditor = [VulnerabilityAuditor]::new()

    if ($Solutions.Count -eq 1) {
        $result = $auditor.RunSolutionAudit($Solutions[0])
        return Format-AuditResult $result
    }  

    $scriptBlock = {
        param([psobject]$auditorObject)
        
        $path = $input | Select-Object -ExpandProperty FullName

        $customDefinitions = [scriptblock]::Create($using:CustomDefinitions)
        . $customDefinitions

        [VulnerabilityAuditor]$a = $auditorObject
        $audit = $a.RunSolutionAudit($path)

        ConvertTo-StandardObject $audit
    }

    try {
        Get-Command -Name Start-ThreadJob -ErrorAction Stop
        $jobResults = $Solutions | ForEach-Object {
            $_ | Start-ThreadJob -ScriptBlock $scriptBlock -ArgumentList (ConvertTo-StandardObject $auditor)
        } | Receive-Job -Wait -AutoRemoveJob
    }
    catch {
        $jobResults = $Solutions | ForEach-Object {
            $_ | Start-Job -ScriptBlock $scriptBlock -ArgumentList (ConvertTo-StandardObject $auditor)
        } | Receive-Job -Wait -AutoRemoveJob
    }   

    $results = $jobResults | ForEach-Object { [SolutionAudit]$_ }
    return Format-AuditResult $results -Depth 7
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
    return Format-AuditResult $auditor.RunSolutionAudit($slnFile)
}

if ($Recurse) {
    $solutionPaths = @(Get-ChildItem -Path $SolutionPath -Filter *.sln -Recurse -Force -ErrorAction SilentlyContinue)
    return Invoke-ScannerInParallel -Solutions $solutionPaths 
}

$auditor = [VulnerabilityAuditor]::new()
$slnFile = Get-ChildItem -Path $SolutionPath -Filter *.sln -Force -ErrorAction SilentlyContinue
if ($null -eq $slnFile) {
    throw "Provided directory does not contain solution file. Use command with: '-Recurse' switch to search for all solutions in directory tree"
}
Format-AuditResult $auditor.RunSolutionAudit($slnFile)
#endregion
