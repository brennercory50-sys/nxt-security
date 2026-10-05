# Create a virtualenv and install NXT-Security in editable mode with dev tools (Windows).
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
$py = if ($env:PYTHON) { $env:PYTHON } else { "py" }
& $py -m venv .venv
& .\.venv\Scripts\python.exe -m pip install --upgrade pip
& .\.venv\Scripts\python.exe -m pip install -e ".[dev]"
if (-not (Test-Path config\scope.yaml)) { Copy-Item config\scope.example.yaml config\scope.yaml }
Write-Host "Done. Run: .\run.ps1 --help"
Write-Host "Edit config\scope.yaml so it lists ONLY systems you are authorized to test."
