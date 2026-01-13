$Server = $env:COMPUTERNAME 
$Out = "C:\Temp\DNS-Audit-$Server"
 New-Item -ItemType Directory -Path $Out -Force | Out-Null 
 
 Import-Module DnsServer
 
 # --- Server Settings --- 
 Get-DnsServerSetting -ComputerName $Server | 
 Select * | Export-Csv "$Out\ServerSettings.csv" -NoTypeInformation
 
 # --- Forwarders --- 
 
 Get-DnsServerForwarder -ComputerName $Server | 
 Export-Csv "$Out\Forwarders.csv" -NoTypeInformation 
 
 # --- Root Hints --- 
 
 Get-DnsServerRootHint -ComputerName $Server | 
 Export-Csv "$Out\RootHints.csv" -NoTypeInformation 
 
 # --- Conditional Forwarders --- 
 
 Get-DnsServerZone -ComputerName $Server | 
 Where-Object {$_.ZoneType -eq "Forwarder"} | 
 Export-Csv "$Out\ConditionalForwarders.csv" -NoTypeInformation 
 
 # --- All Zones --- 
 Get-DnsServerZone -ComputerName $Server | 
 Export-Csv "$Out\Zones.csv" -NoTypeInformation 
 
 # --- Dump all records for every AD zone --- 
 $zones = Get-DnsServerZone -ComputerName $Server | 
 Where-Object {$_.ZoneType -ne "Forwarder"} foreach ($z in $zones) 
 { Get-DnsServerResourceRecord -ComputerName $Server -ZoneName $z.ZoneName | Export-Csv "$Out\Zone-$($z.ZoneName).csv" -NoTypeInformation } 
 
 # --- DC registration & DNS health ---
 dcdiag /test:dns /v > "$Out\DCDIAG-DNS.txt" 
 nltest /dsgetdc:$(Get-ADDomain).DNSRoot > "$Out\NLTEST.txt"
 
 Write-Host "DNS forensic dump completed: $Out"
