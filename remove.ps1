#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Removes every firewall rule created by setup.ps1.
#>
$ErrorActionPreference = 'Stop'

$removed = 0
foreach ($g in 'CTF-AI-Blocklist', 'CTF-Whitelist') {
    $rules = @(Get-NetFirewallRule -Group $g -ErrorAction SilentlyContinue)
    if ($rules.Count -gt 0) {
        $rules | Remove-NetFirewallRule
        $removed += $rules.Count
    }
}

if ($removed -gt 0) { Write-Host "[+] Removed $removed firewall rule(s). Restrictions lifted." }
else { Write-Host '[*] Nothing to remove.' }
