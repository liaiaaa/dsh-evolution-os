# Weekly memory audit wrapper (for Windows Task Scheduler).
# ASCII-only on purpose: Windows PowerShell 5.1 reads BOM-less files as ANSI/GBK,
# which corrupts non-ASCII characters and breaks parsing. All Chinese text is
# produced by weekly_audit.py (Python, explicit UTF-8) instead.
#
# This script does NOT modify any memory. Cleanup still requires user approval.

$ErrorActionPreference = 'Continue'

$Py     = 'python'
$Script = Join-Path $PSScriptRoot 'weekly_audit.py'
$Dir    = Join-Path $PSScriptRoot '..\knowledge\Inbox\_reports'
$State  = Join-Path $Dir '.audit-state.json'

if (-not (Test-Path $Dir)) { New-Item -ItemType Directory -Path $Dir -Force | Out-Null }

$log = Join-Path $Dir ('audit-run-{0}.log' -f (Get-Date -Format 'yyyyMMdd-HHmmss'))

# Force the child Python to emit UTF-8 regardless of the console codepage.
# Without this, Python writes GBK bytes when stdout is redirected, and the
# resulting log is mojibake even though it is stored as UTF-8.
$env:PYTHONIOENCODING = 'utf-8'
$prev = [Console]::OutputEncoding
try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch { }
& $Py $Script *>&1 | Out-File -FilePath $log -Encoding utf8
try { [Console]::OutputEncoding = $prev } catch { }

# Keep only the 20 most recent run logs.
Get-ChildItem $Dir -Filter 'audit-run-*.log' -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending |
    Select-Object -Skip 20 |
    Remove-Item -Force -ErrorAction SilentlyContinue

# Best-effort desktop balloon. Non-interactive sessions may not show it.
try {
    if (Test-Path $State) {
        $s = Get-Content $State -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($s.pending_alert) {
            $n = [int]$s.inbox_candidates
            $msg = 'Memory audit: pending items found (inbox candidates: ' + $n + '). Open any agent to review.'
            Add-Type -AssemblyName System.Windows.Forms
            Add-Type -AssemblyName System.Drawing
            $ni = New-Object System.Windows.Forms.NotifyIcon
            $ni.Icon = [System.Drawing.SystemIcons]::Information
            $ni.Visible = $true
            $ni.ShowBalloonTip(15000, 'Memory audit: action needed', $msg, [System.Windows.Forms.ToolTipIcon]::Info)
            Start-Sleep -Seconds 16
            $ni.Dispose()
        }
    }
} catch { }
