<#
Runs a manual smoke test for the Alighieri Windows Service integration.

Run from an elevated Administrator PowerShell on a Windows host after building
or installing alighieri.exe. This script touches the Service Control Manager,
HKLM Event Log source registration, and C:\ProgramData\Alighieri.
#>

[CmdletBinding()]
param(
    [string]$Alighieri = "alighieri",
    [string]$Config = "C:\ProgramData\Alighieri\alighieri.conf",
    [int]$StartTimeoutSeconds = 30,
    [switch]$SkipCleanup
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    $adminRole = [Security.Principal.WindowsBuiltInRole]::Administrator
    if (-not $principal.IsInRole($adminRole)) {
        throw "Run this smoke test from an elevated Administrator PowerShell."
    }
}

function Invoke-Alighieri {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)

    Write-Host "> $Alighieri $($Arguments -join ' ')"
    & $Alighieri @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed with exit code ${LASTEXITCODE}: $Alighieri $($Arguments -join ' ')"
    }
}

function Show-EventLogEntries {
    Write-Host ""
    Write-Host "Recent Alighieri Application log events:"
    $events = Get-WinEvent -FilterHashtable @{
        LogName = "Application"
        ProviderName = "Alighieri"
    } -MaxEvents 10 -ErrorAction SilentlyContinue

    if (-not $events) {
        Write-Warning "No Alighieri Event Log entries were found."
        return
    }

    $events |
        Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message |
        Format-Table -AutoSize -Wrap
}

function Wait-ServiceState {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$State,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        $service = Get-Service -Name $Name -ErrorAction SilentlyContinue
        if ($service -and $service.Status.ToString() -eq $State) {
            return
        }
        Start-Sleep -Milliseconds 500
    }

    $actual = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if ($actual) {
        throw "Timed out waiting for service '$Name' to reach '$State'; current state is '$($actual.Status)'."
    }

    throw "Timed out waiting for service '$Name' to reach '$State'; service was not found."
}

function Stop-ServiceIfPresent {
    $service = Get-Service -Name "Alighieri" -ErrorAction SilentlyContinue
    if ($service -and $service.Status -ne "Stopped") {
        Invoke-Alighieri @("service", "stop")
    }
}

Assert-Administrator

if (-not (Test-Path -LiteralPath $Config)) {
    throw "Configuration file not found: $Config"
}

Write-Host "Alighieri Windows Service smoke test"
Write-Host "Executable: $Alighieri"
Write-Host "Config:     $Config"
Write-Host ""

$serviceInstalled = $false
try {
    Invoke-Alighieri @("--check", $Config)
    Invoke-Alighieri @("service", "install", "--config", $Config)
    $serviceInstalled = $true
    Invoke-Alighieri @("service", "start")
    Wait-ServiceState -Name "Alighieri" -State "Running" -TimeoutSeconds $StartTimeoutSeconds
    Invoke-Alighieri @("service", "status")
    Invoke-Alighieri @("service", "reload")
    Start-Sleep -Seconds 1
    Show-EventLogEntries
    Invoke-Alighieri @("service", "stop")
} finally {
    if ($SkipCleanup) {
        Write-Warning "Skipping service uninstall because -SkipCleanup was provided."
    } elseif ($serviceInstalled) {
        Stop-ServiceIfPresent
        Invoke-Alighieri @("service", "uninstall")
    } else {
        Write-Warning "Skipping cleanup because service installation did not complete."
    }
}

Write-Host ""
Write-Host "Smoke test completed."
