[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)][System.IO.FileInfo]$SolutionFile,
    [Parameter()][ValidateSet('json', 'xml')]$OutputTo
)

function Main {
    if (!(Test-Path -Path $SolutionFile -PathType Leaf)) {
        throw "Provided path does not exist or is not a file: $SolutionFile"
    }

    if ($SolutionFile.Extension -ne '.sln') {
        $extension = $SolutionFile.Extension
        throw "Provided file is not solution file. Invalid file extension - expected: '.sln' but received: '$extension'"
    }

    $auditor = [VulnerabilityAuditor]::new()
    $solutionAudit = $auditor.RunSolutionAudit($SolutionFile)

    $depth = 6
    if ($OutputTo -eq 'json') {
        $solutionAudit | ConvertTo-Json -Depth $depth -Compress
        return
    }

    if ($OutputTo -eq 'xml') {
        $solutionAudit | ConvertTo-Xml -Depth $depth -As String
        return
    }

    $solutionAudit 
}

function Get-PackagesConfig([System.IO.FileInfo]$projectCsproj) {
    Get-ChildItem -Path $projectCsproj.Directory -Filter 'packages.config' -ErrorAction SilentlyContinue -Force
}

function Test-LegacyNugetProject([System.IO.FileInfo]$projectCsproj) {
    $packageReferences = [xml](Get-Content -Path $projectCsproj.FullName) `
    | Select-Xml -XPath './/PackageReference' `
    | Select-Object -ExpandProperty Node

    $packagesConfig = Get-PackagesConfig $projectCsproj

    return $packageReferences.Count -eq 0 -and $packagesConfig
}

function Test-HasProperty([System.Object]$object, [string]$propertyName) {
    return [bool](Get-Member -InputObject $object -Name $propertyName -MemberType Properties)
}

function IIf($if, $right, $wrong) { if ($if) { $right } else { $wrong } }

enum Severity {
    Low = 0
    Moderate = 1
    High = 2
    Critical = 3
}


class SolutionAudit {
    [string]$SolutionName
    [string]$FullPath
    [ProjectAudit[]]$LegacyProjects
    [VulnerabilityCount]$Count

    SolutionAudit([System.IO.FileInfo]$solutionFile, [ProjectAudit[]]$audits) {
        $this.FullPath = $solutionFile.FullName
        $this.SolutionName = $solutionFile.Name
        $this.LegacyProjects = $audits
        $counts = $audits | Select-Object -ExpandProperty Count
        $this.Count = [VulnerabilityCount]::SumCounts($counts)
    }
}

class ProjectAudit {
    [string]$ProjectName
    [string]$FullPath
    [PackageAudit[]]$VulnerablePackages
    [VulnerabilityCount]$Count

    ProjectAudit([System.IO.FileInfo]$projectCsproj, [PackageAudit[]]$audits) {
        $this.FullPath = $projectCsproj.FullName
        $this.ProjectName = $projectCsproj.Name
        $this.VulnerablePackages = $audits
        $counts = $audits | Select-Object -ExpandProperty Count
        $this.Count = [VulnerabilityCount]::SumCounts($counts)
    }
}

class PackageAudit {
    [string]$PackageName
    [string]$PackageVersion
    [Vulnerability[]]$Vulnerabilities 
    [VulnerabilityCount]$Count

    PackageAudit([string]$name, [version]$version, [Vulnerability[]]$vulnerabilities) {
        $this.PackageName = $name
        $this.PackageVersion = $version
        $this.Vulnerabilities = $vulnerabilities
        $this.Count = [VulnerabilityCount]::Create($this.Vulnerabilities)
    }
}

class VulnerabilityCount {
    [int]$Total
    [int]$Low
    [int]$Moderate
    [int]$High
    [int]$Critical

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

    [SolutionAudit]RunSolutionAudit([System.IO.FileInfo]$solutionFile) {
        $projectCsprojs = [VulnerabilityAuditor]::ParseSolutionFile($solutionFile)
        $projectAudits = $projectCsprojs | Where-Object { Test-LegacyNugetProject $_ } | ForEach-Object {
            $this.RunProjectAudit($_)
        }
        return New-Object SolutionAudit $solutionFile, $projectAudits
    }

    [ProjectAudit]RunProjectAudit([System.IO.FileInfo]$projectCsproj) {
        $packagesConfig = Get-PackagesConfig $projectCsproj
        $packages = [xml](Get-Content $packagesConfig.FullName) | Select-Xml -XPath './/package' | Select-Object -ExpandProperty Node
        $audits = $packages | ForEach-Object {
            $audit = $this.RunPackageAudit($_.id, $_.version)
            if ($audit.Count.Total -gt 0) {
                $audit
            }
        }
        return New-Object ProjectAudit $projectCsproj, $audits
    }

    [PackageAudit]RunPackageAudit([string]$packageName, [version]$packageVersion) {
        $vBase = [VulnerabilityAuditor]::SearchInData($this.Base, $packageName, $packageVersion)
        $vUpdate = [VulnerabilityAuditor]::SearchInData($this.Update, $packageName, $packageVersion)
        return New-Object PackageAudit $packageName, $packageVersion, $($vBase; $vUpdate)
    }

    hidden static [Vulnerability[]]SearchInData([System.Object]$data, [string]$packageName, [version]$packageVersion) {
        $vulnerabilities = New-Object Collections.Generic.List[Vulnerability]
        if (Test-HasProperty -object $data -propertyName $packageName) {
            $data.$packageName | ForEach-Object {
                $vrange = [VersionRange]::Parse($_.versions)
                $vulnerability = New-Object Vulnerability $_.severity, $_.url, $vrange
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

class Vulnerability {
    [Severity]$Severity
    [string]$AdvisoryUrl
    [VersionRange]$VersionRange

    Vulnerability([int]$severity, [string]$url, [VersionRange]$vrange) {
        $this.Severity = $severity
        $this.AdvisoryUrl = $url
        $this.VersionRange = $vrange
    }
}

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
        $versionString = $versionString.Replace('(', '')
        $versionString = $versionString.Replace('[', '')
        $versionString = $versionString.Replace(')', '')
        $versionString = $versionString.Replace(']', '')
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
        $prefix = IIf $this.IsMinInclusive '[' '('
        $suffix = IIf $this.IsMaxInclusive ']' ')'
        $minString = IIf $this.Min.Equals([VersionRange]::DefaultMin) '' $this.Min.ToString()
        $maxString = IIf $this.Max.Equals([VersionRange]::DefaultMax) '' $this.Max.ToString()
        return "$prefix$minString, $maxString$suffix"
    }
}

Main