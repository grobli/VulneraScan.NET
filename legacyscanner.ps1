[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)][string]$SolutionDirectory,
    [Parameter()][ValidateSet('json', 'xml')]$OutputTo
)

function Main {
    if (!(Test-Path -Path $SolutionDirectory -PathType Container)) {
        throw "Provided path does not exist or is not directory: $SolutionDirectory"
    }

    $solutionFile = Get-ChildItem -Path $SolutionDirectory -Filter *.sln 
    if (!$solutionFile) {
        throw "Provided directory does not contain solution file: $SolutionDirectory"
    }

    $auditor = [VulnerabilityAuditor]::new()

    $solutionAudit = $auditor.RunSolutionAudit($SolutionDirectory)

    $depth = 6
    if ($OutputTo -eq 'json') {
        Write-Output $solutionAudit | ConvertTo-Json -Depth $depth -Compress
        return
    }

    if ($OutputTo -eq 'xml') {
        Write-Output $solutionAudit | ConvertTo-Xml -Depth $depth -As String
        return
    }

    $solutionAudit 
}

function HasProperty ([System.Object]$object, [string]$propertyName) {
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
    [string]$FullPath
    [string]$LeafName
    [string]$SolutionName
    [ProjectAudit[]]$LegacyProjects
    [VulnerabilityCount]$Count

    SolutionAudit([System.IO.DirectoryInfo]$solutionDirectory, [ProjectAudit[]]$audits) {
        $this.FullPath = $solutionDirectory.FullName
        $this.LeafName = $solutionDirectory.BaseName
        $this.SolutionName = Get-ChildItem -Path $SolutionDirectory -Filter *.sln | Select-Object -Index 0
        $this.LegacyProjects = $audits
        $counts = $audits | Select-Object -ExpandProperty Count
        $this.Count = [VulnerabilityCount]::SumCounts($counts)
    }
}

class ProjectAudit {
    [string]$FullPath
    [string]$LeafName
    [string]$ProjectName
    [PackageAudit[]]$VulnerablePackages
    [VulnerabilityCount]$Count

    ProjectAudit([System.IO.FileInfo]$packagesConfig, [PackageAudit[]]$audits) {
        $this.FullPath = $packagesConfig.Directory.FullName
        $this.LeafName = $packagesConfig.Directory.BaseName
        $this.ProjectName = Get-ChildItem -Path $this.FullPath -Filter *.csproj | Select-Object -Index 0
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
}

class VulnerabilityAuditor {
    [string]$NugetVulnerabilityIndexUrl
    [System.Object]$Base
    [System.Object]$Update

    VulnerabilityAuditor() {
        $this.NugetVulnerabilityIndexUrl = 'https://api.nuget.org/v3/vulnerabilities/index.json'

        $index = Invoke-RestMethod $this.NugetVulnerabilityIndexUrl

        $this.Base = Invoke-RestMethod ($index | Where-Object -Property '@name' -eq base).'@id'
        $this.Update = Invoke-RestMethod ($index | Where-Object -Property '@name' -eq update).'@id'
    }

    [SolutionAudit]RunSolutionAudit([System.IO.DirectoryInfo]$solutionDirectory) {
        $projectAudits = New-Object Collections.Generic.List[ProjectAudit]
        $packagesConfigFilePaths = Get-ChildItem -Path $solutionDirectory -Filter 'packages.config' -Recurse -ErrorAction SilentlyContinue -Force
        $packagesConfigFilePaths | ForEach-Object {
            $projectAudit = $this.RunProjectAudit($_)
            $projectAudits.Add($projectAudit)
        }
        return New-Object SolutionAudit $solutionDirectory, $projectAudits
    }

    [ProjectAudit]RunProjectAudit([System.IO.FileInfo]$packagesConfig) {
        $packages = [xml](Get-Content $packagesConfig.FullName) | Select-Xml -XPath './/package' | Select-Object -ExpandProperty Node
        $audits = New-Object Collections.Generic.List[PackageAudit]
        $packages | ForEach-Object {
            $audit = $this.RunPackageAudit($_.id, $_.version)
            if ($audit.Vulnerabilities.Count -gt 0) {
                $audits.Add($audit)
            }
        }
        return New-Object ProjectAudit $packagesConfig, $audits
    }

    [PackageAudit]RunPackageAudit([string]$packageName, [version]$packageVersion) {
        # search in Base
        $vBase = [VulnerabilityAuditor]::SearchInData($this.Base, $packageName, $packageVersion)
        
        # search in Update
        $vUpdate = [VulnerabilityAuditor]::SearchInData($this.Update, $packageName, $packageVersion)

        return New-Object PackageAudit $packageName, $packageVersion, $($vBase; $vUpdate)
    }

    static [Vulnerability[]]SearchInData([System.Object]$data, [string]$packageName, [version]$packageVersion) {
        $vulnerabilities = New-Object Collections.Generic.List[Vulnerability]

        if (HasProperty -object $data -propertyName $packageName) {
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

    static [version]$DefaultMin = [version]'0.0.0'
    static [version]$DefaultMax = [version]'9999.9999.9999'

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

    static [string]NormalizeVersionString([string]$versionString) {
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