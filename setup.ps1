#Requires -RunAsAdministrator
<#
.SYNOPSIS
  CTF firewall setup (Windows Defender Firewall).
.DESCRIPTION
  - Resolves every domain in ai_blocklist.txt and creates outbound BLOCK rules (TCP+UDP) for those IPs/ports.
  - Resolves the hosts in ctf_whitelist.txt and creates outbound ALLOW rules for the whitelisted TCP ports.
  - Windows Firewall gives Block rules priority over Allow rules, so any IP shared between the
    whitelist and the blocklist (e.g. same CDN) is EXCLUDED from the block rules.
  - Idempotent: re-run to refresh DNS results. Use remove.ps1 to undo.
.EXAMPLE
  .\setup.ps1
  .\setup.ps1 -WhitelistPath C:\x\ctf_whitelist.txt -BlocklistPath C:\x\ai_blocklist.txt
#>
[CmdletBinding()]
param(
    [string]$WhitelistPath = (Join-Path $PSScriptRoot 'ctf_whitelist.txt'),
    [string]$BlocklistPath = (Join-Path $PSScriptRoot 'ai_blocklist.txt'),
    [int]$ChunkSize = 400          # max addresses per firewall rule
)

$ErrorActionPreference = 'Stop'
$BlockGroup = 'CTF-AI-Blocklist'
$AllowGroup = 'CTF-Whitelist'

foreach ($p in $WhitelistPath, $BlocklistPath) {
    if (-not (Test-Path -LiteralPath $p)) { throw "File not found: $p" }
}

function Read-Clean([string]$Path) {
    Get-Content -LiteralPath $Path | ForEach-Object { ($_ -replace '\s*#.*$', '').Trim() } | Where-Object { $_ }
}

function Resolve-Host([string]$Name) {
    try { [System.Net.Dns]::GetHostAddresses($Name) } catch { @() }
}

# Skip loopback / unspecified / private / link-local / v4-mapped (sinkholed DNS, LAN) - never block these
function Test-Blockable([System.Net.IPAddress]$Ip) {
    if ([System.Net.IPAddress]::IsLoopback($Ip)) { return $false }
    if ($Ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
        $b = $Ip.GetAddressBytes()
        if ($b[0] -in 0, 10, 127) { return $false }
        if ($b[0] -eq 169 -and $b[1] -eq 254) { return $false }
        if ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31) { return $false }
        if ($b[0] -eq 192 -and $b[1] -eq 168) { return $false }
    } else {
        if ($Ip.IsIPv6LinkLocal -or $Ip.IsIPv6SiteLocal -or $Ip.IsIPv6Multicast -or $Ip.IsIPv4MappedToIPv6) { return $false }
        if ($Ip.ToString() -eq '::' -or $Ip.ToString() -match '^f[cd]') { return $false }
    }
    return $true
}

# ------------------------------------------------------------ parse whitelist
$wl = @(Read-Clean $WhitelistPath)

$ctfHosts = @($wl | Where-Object { $_ -notmatch '^(tcp|udp):' } | ForEach-Object {
        ($_ -replace '^[a-z]+://', '' -replace '^\*\.', '' -replace '[/:].*$', '').ToLower()
    } | Sort-Object -Unique)

$tcpPorts = @($wl | Where-Object { $_ -match '^tcp:' } | ForEach-Object {
        ($_ -replace '^tcp:', '') -split ','
    } | ForEach-Object { $_.Trim() } | Where-Object { $_ } | Sort-Object -Unique)

if ($tcpPorts.Count -eq 0) { throw "No 'TCP:' port lines found in $WhitelistPath" }
foreach ($p in $tcpPorts) { if ($p -notmatch '^\d+(-\d+)?$') { throw "Bad port entry: $p" } }
if ($wl | Where-Object { $_ -match '^udp:' }) { Write-Warning 'UDP whitelist lines are ignored by this script.' }

# ------------------------------------------------------------ remove previous rules
foreach ($g in $BlockGroup, $AllowGroup) {
    Get-NetFirewallRule -Group $g -ErrorAction SilentlyContinue | Remove-NetFirewallRule
}

# ------------------------------------------------------------ resolve CTF hosts
Write-Host "[*] Resolving $($ctfHosts.Count) CTF host(s)..."
$ctfIps = New-Object 'System.Collections.Generic.HashSet[string]'
foreach ($h in $ctfHosts) {
    foreach ($ip in (Resolve-Host $h)) { [void]$ctfIps.Add($ip.ToString()) }
}
if ($ctfIps.Count -eq 0) { Write-Warning 'No CTF hosts resolved - whitelist rule will not be created.' }

# ------------------------------------------------------------ parse + resolve blocklist
$hostPorts = @{}
foreach ($line in (Read-Clean $BlocklistPath)) {
    if ($line -match '^([^:\s]+):(\d+)$') {
        $h = $Matches[1].ToLower(); $port = $Matches[2]
        if (-not $hostPorts.ContainsKey($h)) { $hostPorts[$h] = New-Object 'System.Collections.Generic.HashSet[string]' }
        [void]$hostPorts[$h].Add($port)
    } else {
        Write-Warning "Skipping unparseable blocklist line: $line"
    }
}

Write-Host "[*] Resolving $($hostPorts.Count) blocklisted host(s) (this can take a few minutes)..."
$portIps    = @{}   # port -> set of IPs
$unresolved = 0
$excluded   = 0
$i = 0
foreach ($h in $hostPorts.Keys) {
    $i++
    Write-Progress -Activity 'Resolving blocklist' -Status $h -PercentComplete (100 * $i / $hostPorts.Count)
    $ips = @(Resolve-Host $h)
    if ($ips.Count -eq 0) { $unresolved++; continue }
    foreach ($ip in $ips) {
        if (-not (Test-Blockable $ip)) { continue }
        $s = $ip.ToString()
        if ($ctfIps.Contains($s)) { $excluded++; continue }     # whitelist wins over blocklist
        foreach ($port in $hostPorts[$h]) {
            if (-not $portIps.ContainsKey($port)) { $portIps[$port] = New-Object 'System.Collections.Generic.HashSet[string]' }
            [void]$portIps[$port].Add($s)
        }
    }
}
Write-Progress -Activity 'Resolving blocklist' -Completed

# ------------------------------------------------------------ create rules
$ruleCount = 0

if ($ctfIps.Count -gt 0) {
    $all = @($ctfIps | Sort-Object)
    $n = 0
    for ($o = 0; $o -lt $all.Count; $o += $ChunkSize) {
        $n++
        $slice = $all[$o..([Math]::Min($o + $ChunkSize, $all.Count) - 1)]
        New-NetFirewallRule -DisplayName "CTF Whitelist #$n" -Group $AllowGroup -Direction Outbound `
            -Action Allow -Protocol TCP -RemotePort $tcpPorts -RemoteAddress $slice -Profile Any -Enabled True | Out-Null
        $ruleCount++
    }
}

foreach ($port in ($portIps.Keys | Sort-Object { [int]$_ })) {
    $all = @($portIps[$port] | Sort-Object)
    $n = 0
    for ($o = 0; $o -lt $all.Count; $o += $ChunkSize) {
        $n++
        $slice = $all[$o..([Math]::Min($o + $ChunkSize, $all.Count) - 1)]
        foreach ($proto in 'TCP', 'UDP') {     # UDP covers QUIC / HTTP3 on 443
            New-NetFirewallRule -DisplayName "CTF AI Block $proto/$port #$n" -Group $BlockGroup -Direction Outbound `
                -Action Block -Protocol $proto -RemotePort $port -RemoteAddress $slice -Profile Any -Enabled True | Out-Null
            $ruleCount++
        }
    }
}

$blockedIps = ($portIps.Values | ForEach-Object { $_ } | Sort-Object -Unique).Count
Write-Host "[+] Created $ruleCount firewall rule(s)"
Write-Host "    CTF whitelist : $($ctfHosts.Count) hosts -> $($ctfIps.Count) IPs, TCP ports $($tcpPorts -join ',')"
Write-Host "    AI blocklist  : $($hostPorts.Count) hosts -> $blockedIps IPs ($unresolved unresolved, $excluded shared-with-CTF IPs excluded)"
Write-Host "    Remove        : .\remove.ps1"
