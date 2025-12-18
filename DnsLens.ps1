<#
.SYNOPSIS
  DnsLens - PowerShell-first DNS analysis + exports + optional diagrams.

.DESCRIPTION
  Collects DNS configuration, zones, records, and optional DNS Analytical log summaries
  from one or more Windows DNS servers (incl. Domain Controllers).
  Produces CSV/JSON exports, a "gaps" report, and optional GraphViz diagrams.

REQUIREMENTS
  - Run as Administrator on the DNS server (recommended).
  - DnsServer PowerShell module available (Windows Server DNS role / RSAT DNS tools).
  - For PNG/SVG diagram rendering: GraphViz installed (dot.exe in PATH).
    Otherwise DnsLens outputs a .dot file you can render elsewhere.

REFERENCES
  - DNS logging/diagnostics guidance and analytic events are documented by Microsoft.
  - DNS Analytical log enabling is described in Microsoft Learn docs.

USAGE EXAMPLES
  # Local DNS server/DC, export config + zones + records
  .\DnsLens.ps1 -OutputPath C:\Temp\DnsLens -CollectConfig -CollectZones -CollectRecords

  # Multiple DNS servers (requires remoting/permissions)
  .\DnsLens.ps1 -ComputerName dc1,dc2 -OutputPath \\fileserver\share\DnsLens -CollectConfig -CollectZones -CollectRecords

  # Add "how DNS operates" capture (Analytical log), 15 minutes, plus topology diagram
  .\DnsLens.ps1 -OutputPath C:\Temp\DnsLens -CollectConfig -CollectZones -CollectRecords -CaptureQueries -QueryCaptureMinutes 15 -Diagram

#>

[CmdletBinding()]
param(
  [Parameter(Mandatory=$false)]
  [string[]] $ComputerName = @($env:COMPUTERNAME),

  [Parameter(Mandatory=$true)]
  [string] $OutputPath,

  [switch] $CollectConfig,
  [switch] $CollectZones,
  [switch] $CollectRecords,

  [switch] $CaptureQueries,
  [ValidateRange(1, 240)]
  [int] $QueryCaptureMinutes = 15,

  [switch] $CollectErrorEvents,
  [ValidateRange(1, 720)]
  [int] $ErrorLookbackHours = 24,

  [switch] $Diagram,
  [ValidateSet("png","svg","dot")]
  [string] $DiagramFormat = "png",

  [bool] $GenerateBestPractices = $true,

  # Zone filtering
  [string[]] $IncludeZone = @(),   # wildcard patterns, e.g. "*.corp.contoso.com"
  [string[]] $ExcludeZone = @(),   # wildcard patterns
  [ValidateSet("All","CommonOnly")]
  [string] $RecordMode = "All",    # CommonOnly = A,AAAA,CNAME,MX,NS,SRV,TXT,PTR

  # Performance controls
  [int] $MaxRecordsPerZone = 0,    # 0 = unlimited; otherwise caps export for very large zones

  [switch] $ForceEnableAnalyticalLog,  # will attempt to enable analytical logging if disabled
  [switch] $IncludeTopClientsInDiagram, # uses captured query summary (if available)
  [int] $TopClients = 10
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ----------------------------
# Helpers
# ----------------------------
function New-Directory {
  param([Parameter(Mandatory=$true)][string]$Path)
  if (-not (Test-Path -LiteralPath $Path)) {
    New-Item -ItemType Directory -Path $Path -Force | Out-Null
  }
}

function Write-Info { param([string]$Message) Write-Host "[INFO] $Message" -ForegroundColor Cyan }
function Write-Warn { param([string]$Message) Write-Host "[WARN] $Message" -ForegroundColor Yellow }
function Write-Err  { param([string]$Message) Write-Host "[ERR ] $Message" -ForegroundColor Red }

function Get-Timestamp { (Get-Date).ToString("yyyyMMdd-HHmmss") }

function Test-Admin {
  try {
    $current = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($current)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  } catch { return $false }
}

function Ensure-DnsServerModule {
  if (-not (Get-Module -ListAvailable -Name DnsServer)) {
    throw "DnsServer module not found. Install DNS RSAT tools or run on a DNS Server/DC with the DNS role."
  }
  Import-Module DnsServer -ErrorAction Stop
}

function Matches-AnyPattern {
  param(
    [Parameter(Mandatory=$true)][string]$Value,
    [string[]]$Patterns
  )
  if (-not $Patterns -or $Patterns.Count -eq 0) { return $true }
  foreach ($p in $Patterns) {
    if ($Value -like $p) { return $true }
  }
  return $false
}

function Should-IncludeZone {
  param([string]$ZoneName)
  $include = Matches-AnyPattern -Value $ZoneName -Patterns $IncludeZone
  $exclude = $false
  if ($ExcludeZone -and $ExcludeZone.Count -gt 0) {
    foreach ($p in $ExcludeZone) { if ($ZoneName -like $p) { $exclude = $true; break } }
  }
  return ($include -and -not $exclude)
}

function Convert-RecordDataToString {
  param([Parameter(Mandatory=$true)]$RecordData)
  if ($null -eq $RecordData) { return "" }
  try {
    # Most DnsServer RecordData objects serialize well to JSON
    return ($RecordData | ConvertTo-Json -Compress -Depth 6)
  } catch {
    return ($RecordData | Out-String).Trim()
  }
}

function Export-CsvSafe {
  param(
    [Parameter(Mandatory=$true)]$Object,
    [Parameter(Mandatory=$true)][string]$Path
  )
  $Object | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $Path
}

function Export-JsonSafe {
  param(
    [Parameter(Mandatory=$true)]$Object,
    [Parameter(Mandatory=$true)][string]$Path,
    [int] $Depth = 6
  )
  ($Object | ConvertTo-Json -Depth $Depth) | Out-File -FilePath $Path -Encoding UTF8
}

function Invoke-Remote {
  param(
    [Parameter(Mandatory=$true)][string]$Computer,
    [Parameter(Mandatory=$true)][scriptblock]$ScriptBlock,
    [Parameter(Mandatory=$false)]$ArgumentList = @()
  )
  if ($Computer -ieq $env:COMPUTERNAME -or $Computer -ieq "localhost") {
    return & $ScriptBlock @ArgumentList
  }

  # Try PowerShell remoting. If blocked, caller will see gap.
  return Invoke-Command -ComputerName $Computer -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList -ErrorAction Stop
}

# Robustly find the DNS analytical log name on the target server.
# Common log names observed:
#   - Microsoft-Windows-DNSServer/Analytical  (provider-focused)
#   - Microsoft-Windows-DNS-Server/Analytical (role-focused)
function Get-DnsAnalyticalLogName {
  param([Parameter(Mandatory=$true)][string]$Computer)

  $sb = {
    $names = @()
    try {
      $names = & wevtutil.exe el 2>$null
    } catch { $names = @() }

    $candidates = @(
      "Microsoft-Windows-DNSServer/Analytical",
      "Microsoft-Windows-DNS-Server/Analytical",
      "Microsoft-Windows-DNS-Server/Analytic",
      "Microsoft-Windows-DNSServer/Analytic"
    )

    foreach ($c in $candidates) {
      if ($names -contains $c) { return $c }
    }

    # fallback: find any log with DNS + Analytical in name
    $fallback = $names | Where-Object { $_ -match "DNS" -and $_ -match "Analyt" } | Select-Object -First 1
    return $fallback
  }

  Invoke-Remote -Computer $Computer -ScriptBlock $sb
}

function Get-LogEnabled {
  param([Parameter(Mandatory=$true)][string]$Computer, [Parameter(Mandatory=$true)][string]$LogName)

  $sb = {
    param($ln)
    try {
      $info = & wevtutil.exe gl $ln 2>$null
      if (-not $info) { return $false }
      return ($info | Select-String -Pattern "^enabled:\s*true" -Quiet)
    } catch { return $false }
  }
  Invoke-Remote -Computer $Computer -ScriptBlock $sb -ArgumentList @($LogName)
}

function Enable-Log {
  param([Parameter(Mandatory=$true)][string]$Computer, [Parameter(Mandatory=$true)][string]$LogName)

  $sb = {
    param($ln)
    # Enable and set a larger max size (15MB). Adjust as needed.
    & wevtutil.exe sl $ln /ms:15000000 /e:true | Out-Null
    return $true
  }
  Invoke-Remote -Computer $Computer -ScriptBlock $sb -ArgumentList @($LogName) | Out-Null
}

function Parse-DnsAnalyticalEvent {
  param([Parameter(Mandatory=$true)]$Event)

  # We parse the rendered Message, because property indexes vary.
  # The Microsoft Learn documentation includes message patterns with key=value pairs (QNAME=, QTYPE=, Destination=, etc.)
  $msg = $Event.Message
  $id  = $Event.Id

  $o = [ordered]@{
    TimeCreated = $Event.TimeCreated
    EventId     = $id
    Provider    = $Event.ProviderName
    MachineName = $Event.MachineName
    QNAME       = $null
    QTYPE       = $null
    Destination = $null
    InterfaceIP = $null
    RCODE       = $null
    Zone        = $null
    PolicyName  = $null
    TCP         = $null
  }

  if ($msg) {
    foreach ($k in @("QNAME","QTYPE","Destination","InterfaceIP","RCODE","Zone","PolicyName","TCP")) {
      $pattern = [regex]::Escape($k) + "=([^;]+)"
      $m = [regex]::Match($msg, $pattern)
      if ($m.Success) { $o[$k] = $m.Groups[1].Value.Trim() }
    }
  }

  [pscustomobject]$o
}

function Summarise-DnsQueries {
  param(
    [Parameter(Mandatory=$true)][string]$Computer,
    [Parameter(Mandatory=$true)][string]$OutDir,
    [Parameter(Mandatory=$true)][int]$Minutes
  )

  $logName = Get-DnsAnalyticalLogName -Computer $Computer
  if (-not $logName) {
    return @{ ok=$false; gap="DNS Analytical log name not found via wevtutil. Cannot capture query behaviour." }
  }

  $enabled = Get-LogEnabled -Computer $Computer -LogName $logName
  if (-not $enabled) {
    if ($ForceEnableAnalyticalLog) {
      try {
        Enable-Log -Computer $Computer -LogName $logName
        $enabled = $true
      } catch {
        return @{ ok=$false; gap="DNS Analytical log '$logName' is disabled and could not be enabled (permissions/policy). Cannot capture query behaviour." }
      }
    } else {
      return @{ ok=$false; gap="DNS Analytical log '$logName' is disabled. Enable it to capture query behaviour (Analytical logs are disabled by default)." }
    }
  }

  $end = Get-Date
  $start = $end.AddMinutes(-$Minutes)

  $sb = {
    param($ln, $st, $en)
    # IDs per Microsoft Learn include 257-260; some environments also emit 256 (undocumented in some references).
    $filter = @{
      LogName = $ln
      StartTime = $st
      EndTime   = $en
      Id = 257,258,259,260,256
    }
    try {
      Get-WinEvent -FilterHashtable $filter -ErrorAction Stop
    } catch {
      # Fallback: query without Id filter if the channel is active but IDs differ
      Get-WinEvent -FilterHashtable @{ LogName=$ln; StartTime=$st; EndTime=$en } -ErrorAction Stop
    }
  }

  $events = Invoke-Remote -Computer $Computer -ScriptBlock $sb -ArgumentList @($logName, $start, $end)

  if (-not $events -or $events.Count -eq 0) {
    return @{ ok=$true; gap=$null; note="No events found in the selected interval. Either no traffic, or logging not producing viewable events in that window." }
  }

  $parsed = foreach ($e in $events) { Parse-DnsAnalyticalEvent -Event $e }

  # Summaries
  $byQname = $parsed | Where-Object { $_.QNAME } | Group-Object QNAME | Sort-Object Count -Descending |
    Select-Object -First 200 @{n="QNAME";e={$_.Name}}, Count

  $byDest = $parsed | Where-Object { $_.Destination } | Group-Object Destination | Sort-Object Count -Descending |
    Select-Object -First 200 @{n="Destination";e={$_.Name}}, Count

  $byType = $parsed | Where-Object { $_.QTYPE } | Group-Object QTYPE | Sort-Object Count -Descending |
    Select-Object @{n="QTYPE";e={$_.Name}}, Count

  New-Directory -Path $OutDir
  Export-CsvSafe -Object $parsed -Path (Join-Path $OutDir "dns_analytical_events_parsed.csv")
  Export-CsvSafe -Object $byQname -Path (Join-Path $OutDir "summary_top_qname.csv")
  Export-CsvSafe -Object $byDest -Path (Join-Path $OutDir "summary_top_destination.csv")
  Export-CsvSafe -Object $byType -Path (Join-Path $OutDir "summary_qtype.csv")

  return @{ ok=$true; gap=$null; note="Captured and summarised DNS analytical events from $logName." }
}

function Get-DnsErrorEvents {
  param(
    [Parameter(Mandatory=$true)][string]$Computer,
    [Parameter(Mandatory=$true)][int]$LookbackHours
  )

  $sb = {
    param($hours)
    $start = (Get-Date).AddHours(-1 * [math]::Abs($hours))
    $providers = @("Microsoft-Windows-DNS-Server-Service", "DNS-Server-Service", "Microsoft-Windows-DNS-Client")
    $filter = @{ LogName = "System"; ProviderName = $providers; StartTime = $start; Level = 1,2,3 }
    try {
      Get-WinEvent -FilterHashtable $filter -ErrorAction Stop |
        Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message
    } catch {
      @()
    }
  }

  Invoke-Remote -Computer $Computer -ScriptBlock $sb -ArgumentList @($LookbackHours)
}

function Get-DnsConfig {
  param([Parameter(Mandatory=$true)][string]$Computer)

  $sb = {
    # Forwarders and conditional forwarders are core for "how DNS operates"
    $forwarders = @()
    try { $forwarders = Get-DnsServerForwarder -ErrorAction Stop } catch { $forwarders = @() }

    $cond = @()
    try { $cond = Get-DnsServerConditionalForwarderZone -ErrorAction Stop } catch { $cond = @() }

    $recursion = $null
    try { $recursion = Get-DnsServerRecursion -ErrorAction Stop } catch { $recursion = $null }

    $rootHints = @()
    try { $rootHints = Get-DnsServerRootHint -ErrorAction Stop } catch { $rootHints = @() }

    $scav = $null
    try { $scav = Get-DnsServerScavenging -ErrorAction Stop } catch { $scav = $null }

    [pscustomobject]@{
      Forwarders = $forwarders
      ConditionalForwarders = $cond
      Recursion = $recursion
      RootHints = $rootHints
      Scavenging = $scav
    }
  }

  Invoke-Remote -Computer $Computer -ScriptBlock $sb
}

function Get-DnsZones {
  param([Parameter(Mandatory=$true)][string]$Computer)

  $sb = { Get-DnsServerZone -ErrorAction Stop }
  $zones = Invoke-Remote -Computer $Computer -ScriptBlock $sb
  $zones | Where-Object { Should-IncludeZone -ZoneName $_.ZoneName }
}

function Get-DnsRecords {
  param(
    [Parameter(Mandatory=$true)][string]$Computer,
    [Parameter(Mandatory=$true)][string]$ZoneName
  )

  $sb = {
    param($zn)
    Get-DnsServerResourceRecord -ZoneName $zn -ErrorAction Stop
  }
  $rrs = Invoke-Remote -Computer $Computer -ScriptBlock $sb -ArgumentList @($ZoneName)

  if ($RecordMode -eq "CommonOnly") {
    $common = @("A","AAAA","CNAME","MX","NS","SRV","TXT","PTR")
    $rrs = $rrs | Where-Object { $common -contains $_.RecordType.ToString() }
  }

  if ($MaxRecordsPerZone -gt 0) {
    $rrs = $rrs | Select-Object -First $MaxRecordsPerZone
  }

  return $rrs
}

function Export-DnsZoneFiles {
  param(
    [Parameter(Mandatory=$true)][string]$Computer,
    [Parameter(Mandatory=$true)]$Zones,
    [Parameter(Mandatory=$true)][string]$OutDir
  )

  # Zone export is "best effort": it may fail depending on zone type/settings.
  $results = @()
  foreach ($z in $Zones) {
    $zn = $z.ZoneName
    $file = ($zn -replace "[^A-Za-z0-9\.\-_]","_") + ".dns"
    $target = Join-Path $OutDir $file

    $sb = {
      param($zone, $path)
      try {
        Export-DnsServerZone -Name $zone -FileName $path -ErrorAction Stop | Out-Null
        return @{ Zone=$zone; Exported=$true; Path=$path; Error=$null }
      } catch {
        return @{ Zone=$zone; Exported=$false; Path=$path; Error=$_.Exception.Message }
      }
    }

    $r = Invoke-Remote -Computer $Computer -ScriptBlock $sb -ArgumentList @($zn, $target)
    $results += [pscustomobject]$r
  }
  $results
}

function Get-ServerIPAddresses {
  param([Parameter(Mandatory=$true)][string]$Computer)

  $sb = {
    try {
      Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |
        Where-Object { $_.IPAddress -notlike "127.*" -and $_.IPAddress -notlike "169.254.*" } |
        Select-Object -ExpandProperty IPAddress
    } catch {
      @()
    }
  }

  $ips = @()
  try { $ips = Invoke-Remote -Computer $Computer -ScriptBlock $sb } catch { $ips = @() }
  $ips | Where-Object { $_ } | Select-Object -Unique
}

function Test-GraphViz {
  try {
    $null = Get-Command dot -ErrorAction Stop
    return $true
  } catch { return $false }
}

function Write-DotFile {
  param(
    [Parameter(Mandatory=$true)][string]$Path,
    [Parameter(Mandatory=$true)][string]$Dot
  )
  $Dot | Out-File -FilePath $Path -Encoding UTF8
}

function Render-Dot {
  param(
    [Parameter(Mandatory=$true)][string]$DotPath,
    [Parameter(Mandatory=$true)][string]$OutPath,
    [Parameter(Mandatory=$true)][ValidateSet("png","svg")]$Format
  )
  & dot -T$Format $DotPath -o $OutPath | Out-Null
}

function New-DnsTopologyDot {
  param(
    [Parameter(Mandatory=$true)][string]$Computer,
    [Parameter(Mandatory=$true)]$Config,
    [Parameter(Mandatory=$true)]$Zones,
    [Parameter(Mandatory=$false)]$QuerySummaryDir
  )

  # Basic topology:
  #   Clients (optional) -> DNS Server -> Forwarders/RootHints
  #   DNS Server -> Conditional Forwarder Targets (by zone)
  #   Zones hosted on server (clustered visually)

  $serverNode = $Computer.ToUpper()

  $forwarders = @()
  if ($Config.Forwarders) {
    foreach ($f in $Config.Forwarders) {
      # Forwarder cmdlet returns objects; IPs often in IPAddress property.
      if ($f.IPAddress) { $forwarders += ($f.IPAddress | ForEach-Object { $_.ToString() }) }
      elseif ($f | Get-Member -Name "IPAddress") { $forwarders += ($f.IPAddress | ForEach-Object { $_.ToString() }) }
    }
  }
  $forwarders = $forwarders | Where-Object { $_ } | Select-Object -Unique

  $rootHints = @()
  if ($Config.RootHints) {
    foreach ($rh in $Config.RootHints) {
      if ($rh.IPAddress) { $rootHints += ($rh.IPAddress | ForEach-Object { $_.ToString() }) }
    }
  }
  $rootHints = $rootHints | Where-Object { $_ } | Select-Object -Unique

  $condZones = @()
  if ($Config.ConditionalForwarders) {
    foreach ($cz in $Config.ConditionalForwarders) {
      $ips = @()
      try { $ips = $cz.MasterServers | ForEach-Object { $_.IPAddress.ToString() } } catch {}
      $condZones += [pscustomobject]@{
        ZoneName = $cz.Name
        Masters  = ($ips | Where-Object { $_ } | Select-Object -Unique)
      }
    }
  }

  $zonesList = $Zones | Sort-Object ZoneName

  # Optional clients from query summary: we don't have client IP directly in the Microsoft Learn message table,
  # but "Destination" is present in Response events. If you collect client IP via other methods/SIEM,
  # you can extend this. For now, we optionally show top "Destination" nodes (typically client endpoint in logs).
  $clientNodes = @()
  if ($IncludeTopClientsInDiagram -and $QuerySummaryDir -and (Test-Path (Join-Path $QuerySummaryDir "summary_top_destination.csv"))) {
    try {
      $top = Import-Csv (Join-Path $QuerySummaryDir "summary_top_destination.csv") | Select-Object -First $TopClients
      foreach ($t in $top) { if ($t.Destination) { $clientNodes += $t.Destination } }
      $clientNodes = $clientNodes | Select-Object -Unique
    } catch {}
  }

  $dot = @()
  $dot += "digraph DNS_TOPOLOGY {"
  $dot += "  rankdir=LR;"
  $dot += "  node [shape=box, style=rounded];"
  $dot += f'  "{serverNode}" [shape=box, style="rounded,filled"];'

  # Clients cluster
  if ($clientNodes.Count -gt 0) {
    $dot += "  subgraph cluster_clients {"
    $dot += '    label="Observed Clients (from Analytical log Destination)";'
    $dot += "    style=rounded;"
    foreach ($c in $clientNodes) {
      $dot += f'    "{c}" [shape=ellipse];'
      $dot += f'    "{c}" -> "{serverNode}" [label="DNS query"];'
    }
    $dot += "  }"
  } else {
    # still show a generic client box to explain flow
    $dot += '  "Clients" [shape=ellipse];'
    $dot += f'  "Clients" -> "{serverNode}" [label="DNS query"];'
  }

  # Forwarders / Root hints
  if ($forwarders.Count -gt 0) {
    foreach ($ip in $forwarders) {
      $dot += f'  "FWD {ip}" [shape=box];'
      $dot += f'  "{serverNode}" -> "FWD {ip}" [label="Forwarder"];'
    }
  } else {
    # If no forwarders, show root hints path
    if ($rootHints.Count -gt 0) {
      foreach ($ip in $rootHints) {
        $dot += f'  "RootHint {ip}" [shape=box];'
        $dot += f'  "{serverNode}" -> "RootHint {ip}" [label="Root Hints"];'
      }
    } else {
      $dot += '  "Internet/Upstream DNS" [shape=box];'
      $dot += f'  "{serverNode}" -> "Internet/Upstream DNS" [label="Recursion"];'
    }
  }

  # Conditional forwarders
  if ($condZones.Count -gt 0) {
    $dot += "  subgraph cluster_conditional {"
    $dot += '    label="Conditional Forwarders";'
    $dot += "    style=rounded;"
    foreach ($cz in $condZones) {
      $zn = $cz.ZoneName
      $dot += f'    "CFZ {zn}" [shape=folder];'
      $dot += f'    "{serverNode}" -> "CFZ {zn}" [label="Conditional forward"];'
      foreach ($m in $cz.Masters) {
        $dot += f'    "CFM {m}" [shape=box];'
        $dot += f'    "CFZ {zn}" -> "CFM {m}" [label="Master"];'
      }
    }
    $dot += "  }"
  }

  # Zones hosted
  if ($zonesList.Count -gt 0) {
    $dot += "  subgraph cluster_zones {"
    $dot += '    label="Hosted Zones";'
    $dot += "    style=rounded;"
    foreach ($z in $zonesList) {
      $zn = $z.ZoneName
      $dot += f'    "ZONE {zn}" [shape=component];'
      $dot += f'    "{serverNode}" -> "ZONE {zn}" [label="Authoritative"];'
    }
    $dot += "  }"
  }

  $dot += "}"
  return ($dot -join "`n")
}

function New-DnsInterlinkDot {
  param(
    [Parameter(Mandatory=$true)]$ServersData
  )

  $dot = @()
  $dot += "digraph DNS_INTERLINK {"
  $dot += "  rankdir=LR;"
  $dot += "  node [shape=box, style=rounded];"

  $ipToServer = @{}
  foreach ($sd in $ServersData) {
    foreach ($ip in ($sd.IPAddresses | Where-Object { $_ })) {
      if (-not $ipToServer.ContainsKey($ip)) { $ipToServer[$ip] = @() }
      $ipToServer[$ip] += $sd.Server
    }
  }

  foreach ($sd in $ServersData) {
    $dot += f'  "{($sd.Server.ToUpper())}" [shape=box, style="rounded,filled"];'
  }

  $edgeLines = New-Object System.Collections.Generic.List[string]
  $nodeLines = New-Object System.Collections.Generic.List[string]

  foreach ($sd in $ServersData) {
    $serverNode = $sd.Server.ToUpper()
    $cfg = $sd.Config

    # Forwarders
    $forwarders = @()
    if ($cfg -and $cfg.Forwarders) {
      foreach ($f in $cfg.Forwarders) {
        if ($f.IPAddress) { $forwarders += ($f.IPAddress | ForEach-Object { $_.ToString() }) }
      }
    }
    $forwarders = $forwarders | Where-Object { $_ } | Select-Object -Unique

    foreach ($ip in $forwarders) {
      $targets = $ipToServer[$ip]
      if ($targets -and $targets.Count -gt 0) {
        foreach ($t in ($targets | Select-Object -Unique)) {
          $edgeLines.Add(f'  "{serverNode}" -> "{t.ToUpper()}" [label="Forwarder"];')
        }
      } else {
        $nodeLines.Add(f'  "FWD {ip}" [shape=box];')
        $edgeLines.Add(f'  "{serverNode}" -> "FWD {ip}" [label="Forwarder"];')
      }
    }

    # Conditional forwarders
    $condZones = @()
    if ($cfg -and $cfg.ConditionalForwarders) {
      foreach ($cz in $cfg.ConditionalForwarders) {
        $ips = @()
        try { $ips = $cz.MasterServers | ForEach-Object { $_.IPAddress.ToString() } } catch {}
        $condZones += [pscustomobject]@{ ZoneName=$cz.Name; Masters=($ips | Where-Object { $_ } | Select-Object -Unique) }
      }
    }

    foreach ($cz in $condZones) {
      $zoneNode = "CFZ " + $cz.ZoneName
      $nodeLines.Add(f'  "{zoneNode}" [shape=folder];')
      $edgeLines.Add(f'  "{serverNode}" -> "{zoneNode}" [label="Conditional forward"];')
      foreach ($m in $cz.Masters) {
        $targets = $ipToServer[$m]
        if ($targets -and $targets.Count -gt 0) {
          foreach ($t in ($targets | Select-Object -Unique)) {
            $edgeLines.Add(f'  "{zoneNode}" -> "{t.ToUpper()}" [label="Master"];')
          }
        } else {
          $nodeLines.Add(f'  "CFM {m}" [shape=box];')
          $edgeLines.Add(f'  "{zoneNode}" -> "CFM {m}" [label="Master"];')
        }
      }
    }
  }

  foreach ($line in ($nodeLines | Select-Object -Unique)) { $dot += $line }
  foreach ($line in ($edgeLines | Select-Object -Unique)) { $dot += $line }

  $dot += "}"
  return ($dot -join "`n")
}

function Write-BestPracticesReport {
  param(
    [Parameter(Mandatory=$true)][string]$Server,
    [Parameter(Mandatory=$true)][string]$Path,
    [Parameter(Mandatory=$false)]$Config,
    [Parameter(Mandatory=$false)]$Zones,
    [Parameter(Mandatory=$false)]$ErrorEvents
  )

  $observations = New-Object System.Collections.Generic.List[string]
  $remediations = New-Object System.Collections.Generic.List[string]

  if (-not $Config) {
    $observations.Add("DNS configuration was not captured; best-practices review is limited.")
    $remediations.Add("Re-run DnsLens with -CollectConfig to enable configuration-aware guidance.")
  } else {
    $hasForwarders = $false
    if ($Config.Forwarders) {
      foreach ($f in $Config.Forwarders) { if ($f.IPAddress -and $f.IPAddress.Count -gt 0) { $hasForwarders = $true; break } }
    }
    if (-not $hasForwarders -and (-not $Config.RootHints -or $Config.RootHints.Count -eq 0)) {
      $observations.Add("No forwarders or root hints detected; recursive resolution may fail or depend on stale caches.")
      $remediations.Add("Configure upstream forwarders (e.g., internal resolvers or trusted public DNS) or repopulate root hints.")
    }

    if ($Config.Scavenging -and ($Config.Scavenging | Get-Member -Name "ScavengingState" -ErrorAction SilentlyContinue)) {
      if (-not $Config.Scavenging.ScavengingState) {
        $observations.Add("Scavenging is disabled; stale records may accumulate.")
        $remediations.Add("Enable scavenging with conservative intervals on the DNS server and zones once timestamps are accurate.")
      }
    }

    if ($Config.Recursion -and ($Config.Recursion | Get-Member -Name "EnableRecursion" -ErrorAction SilentlyContinue)) {
      if (-not $Config.Recursion.EnableRecursion) {
        $observations.Add("Recursion is disabled; clients can only resolve zones hosted or forwarded explicitly.")
        $remediations.Add("Leave recursion disabled intentionally or document the design; otherwise enable recursion or forwarders.")
      }
    }

    if ($Zones) {
      $staticZones = $Zones | Where-Object { $_.DynamicUpdate -and $_.DynamicUpdate -eq "None" }
      if ($staticZones.Count -gt 0) {
        $znames = ($staticZones | Select-Object -First 5 | ForEach-Object { $_.ZoneName }) -join ", "
        $observations.Add("One or more zones block dynamic updates: $znames.")
        $remediations.Add("Review whether zones should permit secure dynamic updates to reduce manual record drift.")
      }
    }
  }

  if ($ErrorEvents -and $ErrorEvents.Count -gt 0) {
    $errors = $ErrorEvents | Where-Object { $_.LevelDisplayName -eq "Error" }
    $warnings = $ErrorEvents | Where-Object { $_.LevelDisplayName -eq "Warning" }
    if ($errors.Count -gt 0) { $observations.Add("Detected $($errors.Count) DNS error events in the lookback window.") }
    if ($warnings.Count -gt 0) { $observations.Add("Detected $($warnings.Count) DNS warning events in the lookback window.") }
    $remediations.Add("Address the most frequent DNS Server error IDs first (e.g., replication, zone load, or network binding issues).")
  }

  if ($remediations.Count -eq 0) {
    $remediations.Add("No blocking issues detected in collected data. Maintain monitoring and validation of DNS logs and backups.")
  }

  $lines = @()
  $lines += "# DNS Best Practices – $Server"
  $lines += ""
  $lines += "## Observations"
  if ($observations.Count -gt 0) {
    foreach ($o in $observations) { $lines += "- $o" }
  } else {
    $lines += "- No critical observations based on collected data."
  }
  $lines += ""
  $lines += "## Remediation steps"
  foreach ($r in ($remediations | Select-Object -Unique)) { $lines += "- $r" }
  $lines += ""
  $lines += "## General DNS hygiene checklist"
  $lines += "- Monitor DNS event logs regularly and alert on error or warning IDs."
  $lines += "- Keep DNS servers patched and validate backup/restore of zone data."
  $lines += "- Restrict recursion to trusted clients and prefer secure dynamic updates."
  $lines += "- Validate forwarders or root hints availability and latency."
  $lines += "- Enable auditing/logging for query patterns when investigating client issues."

  $lines | Out-File -FilePath $Path -Encoding UTF8

  return [pscustomobject]@{
    Server = $Server
    Observations = $observations
    Remediations = $remediations
    Path = $Path
  }
}

# ----------------------------
# Main
# ----------------------------
$ts = Get-Timestamp
New-Directory -Path $OutputPath

$runDir = Join-Path $OutputPath ("run_" + $ts)
New-Directory -Path $runDir

$invDir  = Join-Path $runDir "inventory"
$cfgDir  = Join-Path $runDir "config"
$logDir  = Join-Path $runDir "logs"
$diaDir  = Join-Path $runDir "diagrams"
$gapDir  = Join-Path $runDir "gaps"

New-Directory -Path $invDir
New-Directory -Path $cfgDir
New-Directory -Path $logDir
New-Directory -Path $diaDir
New-Directory -Path $gapDir

$gaps = New-Object System.Collections.Generic.List[object]

if (-not (Test-Admin)) {
  $gaps.Add([pscustomobject]@{ Category="Permissions"; Item="Administrator"; Gap="Not running elevated. Some DNS queries/log controls may fail."; Recommendation="Run PowerShell as Administrator on the DNS server/DC." })
  Write-Warn "Not running as Administrator. Continuing, but some collection may fail."
}

try {
  Ensure-DnsServerModule
} catch {
  $gaps.Add([pscustomobject]@{ Category="Prereq"; Item="DnsServer module"; Gap=$_.Exception.Message; Recommendation="Install RSAT DNS tools or run on a DNS server/DC with DNS role." })
  throw
}

$graphVizAvailable = Test-GraphViz
if ($Diagram -and $DiagramFormat -ne "dot" -and -not $graphVizAvailable) {
  $gaps.Add([pscustomobject]@{ Category="Prereq"; Item="GraphViz (dot.exe)"; Gap="GraphViz not found in PATH; cannot render PNG/SVG. DOT will still be generated."; Recommendation="Install GraphViz and ensure dot.exe is in PATH, or render the DOT file elsewhere." })
  Write-Warn "GraphViz (dot.exe) not found. Will output DOT only."
}

$allZoneRows    = @()
$allRecordRows  = @()
$allFwdRows     = @()
$allCondRows    = @()
$allZoneExports = @()
$allNotes       = @()
$serverSummaries= @()
$allBestPracticeSummaries = @()

foreach ($c in $ComputerName) {
  $server = $c
  Write-Info "Processing DNS server: $server"

  $serverDir = Join-Path $runDir ($server -replace "[^A-Za-z0-9\-_\.]","_")
  New-Directory -Path $serverDir

  $serverInvDir = Join-Path $serverDir "inventory"
  $serverCfgDir = Join-Path $serverDir "config"
  $serverLogDir = Join-Path $serverDir "logs"
  $serverDiaDir = Join-Path $serverDir "diagrams"
  $serverGapDir = Join-Path $serverDir "gaps"

  New-Directory -Path $serverInvDir
  New-Directory -Path $serverCfgDir
  New-Directory -Path $serverLogDir
  New-Directory -Path $serverDiaDir
  New-Directory -Path $serverGapDir

  $config = $null
  $zones  = @()
  $dnsErrorEvents = @()
  $serverIps = @()

  try {
    $serverIps = Get-ServerIPAddresses -Computer $server
  } catch {
    $serverIps = @()
    $gaps.Add([pscustomobject]@{ Category="Collection"; Item="IP addresses"; Server=$server; Gap=$_.Exception.Message; Recommendation="Ensure remoting and networking cmdlets are allowed to gather server bindings." })
  }

  # Config
  if ($CollectConfig) {
    try {
      $config = Get-DnsConfig -Computer $server

      # Forwarders table
      if ($config.Forwarders) {
        foreach ($f in $config.Forwarders) {
          $ips = @()
          try { $ips = $f.IPAddress | ForEach-Object { $_.ToString() } } catch {}
          if (-not $ips -or $ips.Count -eq 0) { $ips = @("") }
          foreach ($ip in $ips) {
            $allFwdRows += [pscustomobject]@{
              Server = $server
              IPAddress = $ip
              UseRootHint = ($f.UseRootHint)
              Timeout = ($f.Timeout)
            }
          }
        }
      }

      # Conditional forwarders table
      if ($config.ConditionalForwarders) {
        foreach ($cz in $config.ConditionalForwarders) {
          $masters = @()
          try { $masters = $cz.MasterServers | ForEach-Object { $_.IPAddress.ToString() } } catch {}
          if (-not $masters) { $masters = @("") }
          foreach ($m in $masters) {
            $allCondRows += [pscustomobject]@{
              Server = $server
              ZoneName = $cz.Name
              MasterServer = $m
              ReplicationScope = $cz.ReplicationScope
              Store = $cz.Store
            }
          }
        }
      }

      Export-JsonSafe -Object $config -Path (Join-Path $serverCfgDir "dns_config.json") -Depth 8

    } catch {
      $gaps.Add([pscustomobject]@{ Category="Collection"; Item="DNS config"; Server=$server; Gap=$_.Exception.Message; Recommendation="Ensure permissions/remoting and that DNS role/tools are installed." })
      Write-Warn "Config collection failed on $server: $($_.Exception.Message)"
    }
  }

  # Zones
  if ($CollectZones -or $CollectRecords) {
    try {
      $zones = Get-DnsZones -Computer $server

      $zoneRows = foreach ($z in $zones) {
        [pscustomobject]@{
          Server = $server
          ZoneName = $z.ZoneName
          ZoneType = $z.ZoneType
          IsDsIntegrated = $z.IsDsIntegrated
          IsReverseLookupZone = $z.IsReverseLookupZone
          DynamicUpdate = $z.DynamicUpdate
          ReplicationScope = $z.ReplicationScope
          IsAutoCreated = $z.IsAutoCreated
          IsSigned = $z.IsSigned
        }
      }

      $allZoneRows += $zoneRows
      Export-CsvSafe -Object $zoneRows -Path (Join-Path $serverInvDir "zones.csv")
      Export-JsonSafe -Object $zones -Path (Join-Path $serverInvDir "zones.json") -Depth 6

      # Best-effort zone file exports
      $zoneExportDir = Join-Path $serverInvDir "zone_exports"
      New-Directory -Path $zoneExportDir
      try {
        $exports = Export-DnsZoneFiles -Computer $server -Zones $zones -OutDir $zoneExportDir
        $allZoneExports += $exports | ForEach-Object {
          $_ | Add-Member -NotePropertyName Server -NotePropertyValue $server -PassThru
        }
        Export-CsvSafe -Object $exports -Path (Join-Path $serverInvDir "zone_export_results.csv")
      } catch {
        $gaps.Add([pscustomobject]@{ Category="Collection"; Item="Zone export"; Server=$server; Gap=$_.Exception.Message; Recommendation="Zone export can fail by zone type/settings; treat as best-effort." })
      }

    } catch {
      $gaps.Add([pscustomobject]@{ Category="Collection"; Item="Zones"; Server=$server; Gap=$_.Exception.Message; Recommendation="Ensure permissions/remoting and DNS role/tools." })
      Write-Warn "Zone collection failed on $server: $($_.Exception.Message)"
      $zones = @()
    }
  }

  # Records
  if ($CollectRecords) {
    if (-not $zones -or $zones.Count -eq 0) {
      $gaps.Add([pscustomobject]@{ Category="Collection"; Item="Records"; Server=$server; Gap="No zones collected; cannot enumerate records."; Recommendation="Enable zone collection and ensure permissions." })
    } else {
      foreach ($z in $zones) {
        $zn = $z.ZoneName
        Write-Info "  Records: $server :: $zn"

        try {
          $rrs = Get-DnsRecords -Computer $server -ZoneName $zn

          $rows = foreach ($rr in $rrs) {
            [pscustomobject]@{
              Server    = $server
              ZoneName  = $zn
              HostName  = $rr.HostName
              RecordType= $rr.RecordType
              TTL       = $rr.TimeToLive
              Timestamp = $rr.Timestamp
              RecordData= (Convert-RecordDataToString -RecordData $rr.RecordData)
            }
          }

          $allRecordRows += $rows

          $zoneSafe = ($zn -replace "[^A-Za-z0-9\.\-_]","_")
          $outCsv = Join-Path $serverInvDir ("records_" + $zoneSafe + ".csv")
          Export-CsvSafe -Object $rows -Path $outCsv

        } catch {
          $gaps.Add([pscustomobject]@{ Category="Collection"; Item="Records"; Server=$server; Zone=$zn; Gap=$_.Exception.Message; Recommendation="Large zones may be slow; consider -RecordMode CommonOnly or -MaxRecordsPerZone." })
          Write-Warn "  Record collection failed for zone $zn on $server: $($_.Exception.Message)"
        }
      }
    }
  }

  # Query capture ("how DNS operates")
  if ($CaptureQueries) {
    Write-Info "Capturing DNS analytical events on $server for last $QueryCaptureMinutes minutes"
    try {
      $res = Summarise-DnsQueries -Computer $server -OutDir $serverLogDir -Minutes $QueryCaptureMinutes
      if (-not $res.ok -and $res.gap) {
        $gaps.Add([pscustomobject]@{ Category="Logging"; Item="Analytical log capture"; Server=$server; Gap=$res.gap; Recommendation="Enable the DNS Server Analytical log and rerun with -CaptureQueries." })
        Write-Warn $res.gap
      } elseif ($res.note) {
        $allNotes += [pscustomobject]@{ Server=$server; Note=$res.note }
      }
    } catch {
      $gaps.Add([pscustomobject]@{ Category="Logging"; Item="Analytical log capture"; Server=$server; Gap=$_.Exception.Message; Recommendation="Ensure analytical logging is enabled and Get-WinEvent can read the log." })
      Write-Warn "Query capture failed on $server: $($_.Exception.Message)"
    }
  }

  if ($CollectErrorEvents) {
    Write-Info "Reviewing DNS-related errors/warnings on $server for last $ErrorLookbackHours hours"
    try {
      $dnsErrorEvents = Get-DnsErrorEvents -Computer $server -LookbackHours $ErrorLookbackHours
      if ($dnsErrorEvents -and $dnsErrorEvents.Count -gt 0) {
        Export-CsvSafe -Object $dnsErrorEvents -Path (Join-Path $serverLogDir "dns_errors.csv")

        $topIds = $dnsErrorEvents | Group-Object Id | Sort-Object Count -Descending | Select-Object -First 5 @{n="EventId";e={$_.Name}}, Count
        if ($topIds) {
          Export-CsvSafe -Object $topIds -Path (Join-Path $serverLogDir "dns_error_eventid_summary.csv")
        }

        $allNotes += [pscustomobject]@{ Server=$server; Note="Captured $($dnsErrorEvents.Count) DNS error/warning events in last $ErrorLookbackHours hours." }
      } else {
        $allNotes += [pscustomobject]@{ Server=$server; Note="No DNS error or warning events found in last $ErrorLookbackHours hours." }
      }
    } catch {
      $gaps.Add([pscustomobject]@{ Category="Logging"; Item="DNS event log"; Server=$server; Gap=$_.Exception.Message; Recommendation="Ensure System log is accessible via remoting and DNS Server/Client providers are present." })
      Write-Warn "DNS event log review failed on $server: $($_.Exception.Message)"
    }
  }

  # Diagram
  if ($Diagram) {
    if (-not $config) {
      try { $config = Get-DnsConfig -Computer $server } catch { $config = $null }
    }
    if (-not $zones -or $zones.Count -eq 0) {
      try { $zones = Get-DnsZones -Computer $server } catch { $zones = @() }
    }

    if (-not $config) {
      $gaps.Add([pscustomobject]@{ Category="Diagram"; Item="Topology"; Server=$server; Gap="Config not available, cannot build meaningful topology."; Recommendation="Run with -CollectConfig and ensure permissions." })
    } else {
      $qDir = $null
      if ($CaptureQueries) { $qDir = $serverLogDir }

      $dot = New-DnsTopologyDot -Computer $server -Config $config -Zones $zones -QuerySummaryDir $qDir
      $dotPath = Join-Path $serverDiaDir "dns_topology.dot"
      Write-DotFile -Path $dotPath -Dot $dot

      if ($DiagramFormat -eq "dot") {
        Write-Info "Diagram DOT written: $dotPath"
      } else {
        if ($graphVizAvailable) {
          $outImg = Join-Path $serverDiaDir ("dns_topology." + $DiagramFormat)
          try {
            Render-Dot -DotPath $dotPath -OutPath $outImg -Format $DiagramFormat
            Write-Info "Diagram rendered: $outImg"
          } catch {
            $gaps.Add([pscustomobject]@{ Category="Diagram"; Item="Render"; Server=$server; Gap=$_.Exception.Message; Recommendation="Ensure GraphViz dot.exe is installed and accessible." })
          }
        } else {
          Write-Info "DOT written (GraphViz not available to render image): $dotPath"
        }
      }
    }
  }

  if ($GenerateBestPractices) {
    $bpPath = Join-Path $serverDir "best_practices.md"
    try {
      $bp = Write-BestPracticesReport -Server $server -Path $bpPath -Config $config -Zones $zones -ErrorEvents $dnsErrorEvents
      $allBestPracticeSummaries += $bp
    } catch {
      $gaps.Add([pscustomobject]@{ Category="Guidance"; Item="Best practices"; Server=$server; Gap=$_.Exception.Message; Recommendation="Ensure configuration and zone data are collected to enable best-practice hints." })
    }
  }

  $serverSummaries += [pscustomobject]@{
    Server = $server
    Config = $config
    Zones = $zones
    IPAddresses = $serverIps
  }
}

if ($Diagram -and $serverSummaries.Count -gt 0) {
  try {
    $interlinkDot = New-DnsInterlinkDot -ServersData $serverSummaries
    $interlinkPath = Join-Path $diaDir "dns_interlink.dot"
    Write-DotFile -Path $interlinkPath -Dot $interlinkDot

    if ($DiagramFormat -eq "dot") {
      Write-Info "Interlink diagram DOT written: $interlinkPath"
    } elseif ($graphVizAvailable) {
      $interImg = Join-Path $diaDir ("dns_interlink." + $DiagramFormat)
      try {
        Render-Dot -DotPath $interlinkPath -OutPath $interImg -Format $DiagramFormat
        Write-Info "Interlink diagram rendered: $interImg"
      } catch {
        $gaps.Add([pscustomobject]@{ Category="Diagram"; Item="Interlink Render"; Server="All"; Gap=$_.Exception.Message; Recommendation="Ensure GraphViz dot.exe is installed and accessible." })
      }
    } else {
      Write-Info "Interlink DOT written (GraphViz not available to render image): $interlinkPath"
    }
  } catch {
    $gaps.Add([pscustomobject]@{ Category="Diagram"; Item="Interlink"; Server="All"; Gap=$_.Exception.Message; Recommendation="Inspect DNS config collection and rerun diagram generation." })
  }
}

if ($allBestPracticeSummaries.Count -gt 0) {
  $bpLines = @("# DNS Best Practices Summary")
  foreach ($bp in $allBestPracticeSummaries) {
    $bpLines += ""
    $bpLines += "## $($bp.Server)"
    if ($bp.Observations -and $bp.Observations.Count -gt 0) {
      $bpLines += "### Observations"
      foreach ($o in $bp.Observations) { $bpLines += "- $o" }
    }
    if ($bp.Remediations -and $bp.Remediations.Count -gt 0) {
      $bpLines += "### Remediation steps"
      foreach ($r in ($bp.Remediations | Select-Object -Unique)) { $bpLines += "- $r" }
    }
    $bpLines += "### Detailed report"
    $bpLines += "- $($bp.Path)"
  }

  $bpSummaryPath = Join-Path $runDir "best_practices_summary.md"
  $bpLines | Out-File -FilePath $bpSummaryPath -Encoding UTF8
}

# Export combined outputs
if ($allZoneRows.Count -gt 0) { Export-CsvSafe -Object $allZoneRows -Path (Join-Path $invDir "all_zones.csv") }
if ($allRecordRows.Count -gt 0) { Export-CsvSafe -Object $allRecordRows -Path (Join-Path $invDir "all_records.csv") }
if ($allFwdRows.Count -gt 0) { Export-CsvSafe -Object $allFwdRows -Path (Join-Path $cfgDir "all_forwarders.csv") }
if ($allCondRows.Count -gt 0) { Export-CsvSafe -Object $allCondRows -Path (Join-Path $cfgDir "all_conditional_forwarders.csv") }
if ($allZoneExports.Count -gt 0) { Export-CsvSafe -Object $allZoneExports -Path (Join-Path $invDir "all_zone_export_results.csv") }
if ($allNotes.Count -gt 0) { Export-CsvSafe -Object $allNotes -Path (Join-Path $runDir "notes.csv") }

# Gaps report (explicitly tells you what couldn't be collected / why)
$gapsPathCsv = Join-Path $gapDir "gaps.csv"
$gapsPathJson = Join-Path $gapDir "gaps.json"
if ($gaps.Count -gt 0) {
  Export-CsvSafe -Object $gaps -Path $gapsPathCsv
  Export-JsonSafe -Object $gaps -Path $gapsPathJson -Depth 6
  Write-Warn "Gaps were detected. See: $gapsPathCsv"
} else {
  Write-Info "No gaps detected by DnsLens preflight/collection."
}

Write-Info "Done. Output: $runDir"
