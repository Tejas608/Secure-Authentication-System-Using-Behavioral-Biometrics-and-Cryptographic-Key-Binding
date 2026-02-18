<#
 Quick training script for ML model
 Robustly finds Python in a venv or on PATH.
 Usage: .\train.ps1
#>

Push-Location $PSScriptRoot
try {
	$trainScript = Join-Path $PSScriptRoot 'ml/train_model.py'

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
	& $pythonCmd $trainScript
	$modelPath = Join-Path $PSScriptRoot 'ml/model.pkl'
	if (Test-Path $modelPath) {
		Write-Host "`nModel trained! Now run .\\run.ps1 to start the server." -ForegroundColor Green
	} else {
		Write-Warning "Training did not produce a model artifact (ml/model.pkl). See messages above for details."
	}
}
finally {
	Pop-Location
}
