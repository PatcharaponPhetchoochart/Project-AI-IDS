# รันทุก service บน Windows (ต้องเปิด PowerShell แบบ Run as administrator)
#   .\run_all.ps1            # = python run_all.py
#   .\run_all.ps1 --monitor inline
Set-Location $PSScriptRoot
python run_all.py @args
