[CmdletBinding()]
param(
  [int]$ApiPort = 4000
)

$ErrorActionPreference = 'Stop'
$preferredRepo = 'C:\Users\Hemant\Desktop\Projects\GigBit'
if (Test-Path $preferredRepo) {
  $repo = Resolve-Path $preferredRepo
} else {
  $repo = Resolve-Path (Join-Path $PSScriptRoot '..')
}

function Wait-HttpOk([string]$Url, [int]$Seconds = 60) {
  $deadline = (Get-Date).AddSeconds($Seconds)
  while ((Get-Date) -lt $deadline) {
    try {
      $r = Invoke-WebRequest -UseBasicParsing -TimeoutSec 2 -Uri $Url
      if ($r.StatusCode -ge 200 -and $r.StatusCode -lt 300) { return $true }
    } catch {
      Start-Sleep -Milliseconds 500
    }
  }
  return $false
}

function Wait-Tcp([string]$Hostname, [int]$Port, [int]$Seconds = 60) {
  $deadline = (Get-Date).AddSeconds($Seconds)
  while ((Get-Date) -lt $deadline) {
    try {
      $ok = Test-NetConnection -ComputerName $Hostname -Port $Port -WarningAction SilentlyContinue
      if ($ok.TcpTestSucceeded) { return $true }
    } catch {
      # ignore
    }
    Start-Sleep -Milliseconds 500
  }
  return $false
}

function Stop-PortConflicts([int]$Port) {
  try {
    $listeners = Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue
    if (-not $listeners) { return }
    $pids = $listeners | Select-Object -ExpandProperty OwningProcess -Unique
    foreach ($pid in $pids) {
      if (-not $pid -or $pid -le 0) { continue }
      try {
        $proc = Get-Process -Id $pid -ErrorAction Stop
        if ($proc.ProcessName -ieq 'com.docker.backend') { continue }
        Write-Host "Stopping process on port ${Port}: $($proc.ProcessName) (PID $pid)"
        Stop-Process -Id $pid -Force -ErrorAction Stop
      } catch {
        # ignore individual process stop failures
      }
    }
  } catch {
    # ignore if net tcp query not available
  }
}

function Stop-LegacyRepoNodeWatchers() {
  $legacyPattern = 'Desktop\\Projects\\GigBit'
  try {
    $procs = Get-CimInstance Win32_Process -Filter "Name = 'node.exe'" -ErrorAction SilentlyContinue |
      Where-Object { $_.CommandLine -match $legacyPattern }
    foreach ($p in $procs) {
      try {
        Write-Host "Stopping legacy backend process: PID $($p.ProcessId)"
        Stop-Process -Id $p.ProcessId -Force -ErrorAction Stop
      } catch {
        # ignore
      }
    }
  } catch {
    # ignore
  }
}

Set-Location $repo
Stop-LegacyRepoNodeWatchers
Stop-PortConflicts -Port $ApiPort

Write-Host "Bringing up Docker stack (Postgres + Redis + API)..."
docker compose up -d --build | Out-Host

Write-Host "Waiting for Postgres (127.0.0.1:5433)..."
if (-not (Wait-Tcp '127.0.0.1' 5433 60)) {
  throw 'Postgres did not become ready on 127.0.0.1:5433'
}

Write-Host "Waiting for API health..."
if (-not (Wait-HttpOk "http://127.0.0.1:$ApiPort/health" 90)) {
  Write-Host "API logs:" 
  docker logs --tail 120 gigbit-api | Out-Host
  throw "API did not become healthy on http://127.0.0.1:$ApiPort/health"
}

Write-Host "Setting up adb reverse (device tcp:$ApiPort -> host tcp:$ApiPort)..."
try {
  $devices = (& adb devices) | Select-String -Pattern '\tdevice$' | ForEach-Object { ($_ -split '\t')[0] }
  foreach ($d in $devices) {
    & adb -s $d reverse tcp:$ApiPort tcp:$ApiPort | Out-Null
  }
  if ($devices.Count -gt 0) {
    Write-Host "adb reverse configured for: $($devices -join ', ')"
  } else {
    Write-Host "No adb devices detected (this is ok)."
  }
} catch {
  Write-Host "adb not available; skipping adb reverse."
}

Write-Host "Ready: http://127.0.0.1:$ApiPort/health"
Write-Host "Emulator alt: http://10.0.2.2:$ApiPort"
