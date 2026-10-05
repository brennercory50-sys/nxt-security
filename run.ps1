# Run nxtsec from the project virtualenv: .\run.ps1 scope check 127.0.0.1
Set-Location $PSScriptRoot
& .\.venv\Scripts\python.exe -m nxtsec @args
exit $LASTEXITCODE
