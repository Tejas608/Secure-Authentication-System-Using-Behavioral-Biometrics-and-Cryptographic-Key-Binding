<#
 Quick start script for secure-auth-system
 Robustly finds Python in a venv even if the project is nested.
 Usage: .\run.ps1
#>

Push-Location $PSScriptRoot
try {
	$env:AUTH_POLICY = $env:AUTH_POLICY -as [string]
	if (-not $env:AUTH_POLICY -or $env:AUTH_POLICY.Trim() -eq '') { $env:AUTH_POLICY = "balanced" }

	$app = Join-Path $PSScriptRoot 'backend/app.py'

	$candidates = @(
		(Join-Path $PSScriptRoot '..\.venv\Scripts\python.exe'),
		(Join-Path $PSScriptRoot '..\..\.venv\Scripts\python.exe'),
		(Join-Path $PSScriptRoot '.venv\Scripts\python.exe'),
		'python',
		'py'
	)

	$pythonCmd = $null
	foreach ($c in $candidates) {
		if ($c -in @('python','py')) {
			if (Get-Command $c -ErrorAction SilentlyContinue) { $pythonCmd = $c; break }
		} else {
			if (Test-Path $c) { $pythonCmd = $c; break }
		}
	}

	if (-not $pythonCmd) {
		Write-Error 'Could not find Python. Ensure a venv exists (./.venv) or python is on PATH.'
		exit 1
	}

	Write-Host "Using Python: $pythonCmd" -ForegroundColor Cyan
	Write-Host "AUTH_POLICY=$($env:AUTH_POLICY)" -ForegroundColor Cyan

	& $pythonCmd $app
}
finally {
	Pop-Location
}
