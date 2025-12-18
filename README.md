# DnsLens (PowerShell) – DNS Inventory + “How DNS Operates” Exports + Diagrams

## What it does
DnsLens collects:
- **DNS configuration**: forwarders, conditional forwarders, recursion, root hints, scavenging
- **Zones** (filtered by include/exclude patterns)
- **Records** per zone (CSV per zone + combined CSV)
- Optional: **DNS Analytical log summaries** (to visualise/query “how DNS operates”)
- Optional: **Topology diagram** (DOT always, PNG/SVG if GraphViz is installed)

It always writes a **gaps report** stating what it couldn’t collect and why.

## Requirements
- Run on a Windows DNS server / DC with DNS role (recommended), or a workstation with DNS RSAT.
- PowerShell with the `DnsServer` module available.
- For image rendering: GraphViz (`dot.exe`) on PATH.
- For query behaviour: DNS **Analytical** log enabled (can be enabled by script if you pass `-ForceEnableAnalyticalLog`).

## Quick start (local)
```powershell
Set-Location C:\Temp
.\DnsLens.ps1 -OutputPath C:\Temp\DnsLens -CollectConfig -CollectZones -CollectRecords
```

## Add “how DNS operates” capture + diagram
```powershell
.\DnsLens.ps1 -OutputPath C:\Temp\DnsLens `
  -CollectConfig -CollectZones -CollectRecords `
  -CaptureQueries -QueryCaptureMinutes 15 -ForceEnableAnalyticalLog `
  -Diagram -DiagramFormat png
```

## Target multiple DNS servers (requires permissions/remoting)
```powershell
.\DnsLens.ps1 -ComputerName dc1,dc2 -OutputPath \\server\share\DnsLens `
  -CollectConfig -CollectZones -CollectRecords -Diagram
```

## Outputs
- `inventory/` – zones + records exports
- `config/` – forwarders, conditional forwarders, config JSON
- `logs/` – parsed DNS Analytical events + summaries (top QNAME, destination, QTYPE)
- `diagrams/` – `dns_topology.dot` (+ `.png`/`.svg` if enabled)
- `gaps/` – `gaps.csv` and `gaps.json` listing anything missing

## Notes / limitations
- “Client IP” isn’t reliably present as a single structured field in all event variants; DnsLens uses the **rendered message** and extracts key=value pairs where present.
- If the analytical channel is enabled but Event Viewer can’t show it (known behaviour), `Get-WinEvent` still works in most cases.
- Zone exports are “best effort” and can fail depending on zone type/settings; failures are recorded in `zone_export_results.csv`.
