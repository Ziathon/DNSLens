<#
.SYNOPSIS
  Collects DNS configuration evidence per DNS server (per VM/DC) to close assessment gaps.

.PREREQS
  - Run as an account with rights to read DNS server config (typically Domain Admin / DNSAdmins).
  - RSAT DNS tools available on the machine running the script (DnsServer module).
  - Network access to TCP/UDP 53 and RPC/WMI as needed.

.OUTPUT
  - C:\Temp\DNS-GapEvidence\<server>\*.csv / *.txt
  - C:\Temp\DNS-GapEvidence\_Index.csv
#>

param(
  [Parameter(Mandatory=$true)]
  [string[]] $Servers,

  [string] $OutputRoot = "C:\Temp\DNS-GapEvidence"
)

$ErrorActionPreference = "Stop"

# Ensure output root exists
New-Item -ItemType Directory -Path $OutputRoot -Force | Out-Null

# Try to load DNS module (RSAT / on-DC)
try { Import-Module DnsServer -ErrorAction Stop } catch {
  throw "DnsServer module not available. Install RSAT DNS tools or run on a DNS server/DC."
}

function Export-Safely {
  param(
    [string]$Server,
    [string]$OutDir,
    [string]$Name,
    [scriptblock]$Command,
    [ValidateSet("Csv","Txt")] [string]$Type = "Csv"
  )
  try {
    $result = & $Command
    if ($Type -eq "Csv") {
      $result | Export-Csv -NoTypeInformation -Path (Join-Path $OutDir "$Name.csv")
    } else {
      $result | Out-File -FilePath (Join-Path $OutDir "$Name.txt") -Encoding utf8
    }
    return [pscustomobject]@{ Server=$Server; Artifact=$Name; Status="OK"; Detail="" }
  }
  catch {
    # Write an error marker file and return status
    $msg = $_.Exception.Message
    $errPath = Join-Path $OutDir "$Name.ERROR.txt"
    $msg | Out-File -FilePath $errPath -Encoding utf8
    return [pscustomobject]@{ Server=$Server; Artifact=$Name; Status="ERROR"; Detail=$msg }
  }
}

$index = New-Object System.Collections.Generic.List[object]

foreach ($s in $Servers) {
  $outDir = Join-Path $OutputRoot $s
  New-Item -ItemType Directory -Path $outDir -Force | Out-Null

  # --- Host / OS context (useful for feature availability) ---
  $index.Add((Export-Safely -Server $s -OutDir $outDir -Name "HostInfo" -Type "Txt" -Command {
    $ci = Get-ComputerInfo -ComputerName $s -ErrorAction Stop
    @(
      "CsName: $($ci.CsName)"
      "WindowsProductName: $($ci.WindowsProductName)"
      "WindowsVersion: $($ci.WindowsVersion)"
      "OsVersion: $($ci.OsVersion)"
    )
  }))

  # --- Core DNS server settings (recursion, cache, etc.) ---
  $index.Add((Export-Safely -Server $s -OutDir $outDir -Name "DnsServerSetting" -Command {
    Get-DnsServerSetting -ComputerName $s | Select-Object *
  }))

  # --- Forwarders / root hints / conditional forwarders ---
  $index.Add((Export-Safely -Server $s -OutDir $outDir -Name "DnsForwarders" -Command {
    Get-DnsServerForwarder -ComputerName $s | Select-Object *
  }))

  $index.Add((Export-Safely -Server $s -OutDir $outDir -Name "DnsRootHints" -Command {
    Get-DnsServerRootHint -ComputerName $s | Select-Object *
  }))

  $index.Add((Export-Safely -Server $s -OutDir $outDir -Name "DnsZones" -Command {
    Get-DnsServerZone -ComputerName $s | Select-Object *
  }))

  $index.Add((Export-Safely -Server $s -OutDir $outDir -Name "DnsConditionalForwarders" -Command {
    Get-DnsServerZone -ComputerName $s |
      Where-Object { $_.ZoneType -eq "Forwarder" } |
      Select-Object *
  }))

  # --- Zone configuration: dynamic updates, aging/scavenging, transfers, DNSSEC status ---
  $index.Add((Export-Safely -Server $s -OutDir $outDir -Name "ZoneAgingSettings" -Command {
    $zones = Get-DnsServerZone -ComputerName $s | Where-Object { $_.ZoneType -ne "Forwarder" }
    foreach ($z in $zones) {
      $aging = Get-DnsServerZoneAging -ComputerName $s -Name $z.ZoneName
      [pscustomobject]@{
        ZoneName        = $z.ZoneName
        ZoneType        = $z.ZoneType
        IsDsIntegrated  = $z.IsDsIntegrated
        DynamicUpdate   = $z.DynamicUpdate
        AgingEnabled    = $aging.AgingEnabled
        NoRefresh       = $aging.NoRefreshInterval
        Refresh         = $aging.RefreshInterval
        ScavengeServers = ($aging.ScavengeServers -join ", ")
      }
    }
  }))

  # Zone transfer settings (for non-AD integrated zones primarily, but still evidence)
  $index.Add((Export-Safely -Server $s -OutDir $outDir -Name "ZoneTransferSettings" -Command {
    $zones = Get-DnsServerZone -ComputerName $s | Where-Object { $_.ZoneType -ne "Forwarder" }
    foreach ($z in $zones) {
      $zt = Get-DnsServerZoneTransferPolicy -ComputerName $s -ZoneName $z.ZoneName
      # Some servers may not support this cmdlet; handled by Export-Safely
      $zt | Select-Object @{n="ZoneName";e={$z.ZoneName}}, *
    }
  }))

  # DNSSEC zone settings (where applicable)
  $index.Add((Export-Safely -Server $s -OutDir $outDir -Name "DnsSecZoneSettings" -Command {
    $zones = Get-DnsServerZone -ComputerName $s | Where-Object { $_.ZoneType -ne "Forwarder" }
    foreach ($z in $zones) {
      try {
        $dnssec = Get-DnsServerDnsSecZoneSetting -ComputerName $s -ZoneName $z.ZoneName -ErrorAction Stop
        $dnssec | Select-Object @{n="ZoneName";e={$z.ZoneName}}, *
      } catch {
        # Not signed or not supported; record minimal row rather than fail whole artifact
        [pscustomobject]@{ ZoneName=$z.ZoneName; DnsSec="NotSignedOrNotSupported" }
      }
    }
  }))

  # --- Server scavenging schedule and status ---
  $index.Add((Export-Safely -Server $s -OutDir $outDir -Name "ScavengingServerSettings" -Command {
    $set = Get-DnsServerSetting -ComputerName $s
    [pscustomobject]@{
      Server                 = $s
      ScavengingEnabled      = $set.EnableScavenging
      ScavengingInterval     = $set.ScavengingInterval
      DefaultNoRefresh       = $set.DefaultNoRefreshInterval
      DefaultRefresh         = $set.DefaultRefreshInterval
    }
  }))

  # --- Response Rate Limiting (RRL) ---
  $index.Add((Export-Safely -Server $s -OutDir $outDir -Name "ResponseRateLimiting" -Command {
    Get-DnsServerResponseRateLimiting -ComputerName $s | Select-Object *
  }))

  # --- Socket pool / cache locking (via dnscmd + registry evidence) ---
  $index.Add((Export-Safely -Server $s -OutDir $outDir -Name "DnsCmd_ConfigDump" -Type "Txt" -Command {
    # dnscmd requires RSAT or running on a server with tools installed.
    # /info dumps the service configuration; useful for socket pool, cache lock, recursion-related flags in older OSes.
    cmd /c "dnscmd $s /info"
  }))

  $index.Add((Export-Safely -Server $s -OutDir $outDir -Name "DnsRegistryParams" -Command {
    # Captures common DNS hardening/perf registry keys if present
    $path = "\\$s\HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters"
    $props = @(
      "SocketPoolSize","CacheLockingPercent","EnableEDnsProbes","EnableDnsSec",
      "MaximumUdpPacketSize","EnableRRl","QueryIpMatching","NoRecursion",
      "SecureResponses","EnablePollutionProtection"
    )

    $rows = foreach ($p in $props) {
      try {
        $v = (Get-ItemProperty -Path $path -Name $p -ErrorAction Stop).$p
        [pscustomobject]@{ Server=$s; Key=$p; Value=$v }
      } catch {
        [pscustomobject]@{ Server=$s; Key=$p; Value=$null }
      }
    }
    $rows
  }))

  # --- DNS logging / auditing evidence ---
  $index.Add((Export-Safely -Server $s -OutDir $outDir -Name "DnsDebugLogSettings" -Command {
    # DNS debug logging settings live in server settings
    # (fields vary by OS; Select * captures what is available)
    Get-DnsServerSetting -ComputerName $s | Select-Object * | Select-Object -Property *Debug*
  }))

  $index.Add((Export-Safely -Server $s -OutDir $outDir -Name "DnsEventLogs_Status" -Command {
    # Check if DNS Analytical/Admin logs exist and whether enabled
    $logs = @(
      "Microsoft-Windows-DNS-Server/Analytical",
      "Microsoft-Windows-DNS-Server/Audit",
      "DNS Server"
    )
    foreach ($l in $logs) {
      try {
        $info = Get-WinEvent -ListLog $l -ComputerName $s -ErrorAction Stop
        [pscustomobject]@{ Server=$s; LogName=$l; IsEnabled=$info.IsEnabled; RecordCount=$info.RecordCount; LogMode=$info.LogMode; MaxSizeInBytes=$info.MaximumSizeInBytes }
      } catch {
        [pscustomobject]@{ Server=$s; LogName=$l; IsEnabled=$null; RecordCount=$null; LogMode=$null; MaxSizeInBytes=$null }
      }
    }
  }))

  # --- NIC DNS client settings on the DNS server (detect “external resolvers on NIC”) ---
  $index.Add((Export-Safely -Server $s -OutDir $outDir -Name "NicDnsClientConfig" -Command {
    Invoke-Command -ComputerName $s -ScriptBlock {
      Get-DnsClientServerAddress -AddressFamily IPv4 |
        Select-Object InterfaceAlias, ServerAddresses
    }
  }))

  # --- Optional: dump a small set of zone metadata + record counts (lightweight, avoids huge exports) ---
  $index.Add((Export-Safely -Server $s -OutDir $outDir -Name "ZoneRecordCounts" -Command {
    $zones = Get-DnsServerZone -ComputerName $s | Where-Object { $_.ZoneType -ne "Forwarder" }
    foreach ($z in $zones) {
      try {
        $count = (Get-DnsServerResourceRecord -ComputerName $s -ZoneName $z.ZoneName -ErrorAction Stop | Measure-Object).Count
        [pscustomobject]@{ Server=$s; ZoneName=$z.ZoneName; RecordCount=$count }
      } catch {
        [pscustomobject]@{ Server=$s; ZoneName=$z.ZoneName; RecordCount=$null }
      }
    }
  }))
}

# Write consolidated index
$index | Export-Csv -NoTypeInformation -Path (Join-Path $OutputRoot "_Index.csv")

Write-Host "Completed. Output root: $OutputRoot"
Write-Host "Index file: $(Join-Path $OutputRoot '_Index.csv')"
