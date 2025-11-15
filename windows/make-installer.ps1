$ErrorActionPreference = "Stop"

$NssmZip = "$env:TEMP\nssm.zip"
$NssmUrl = "https://nssm.cc/release/nssm-2.24.zip"

$InstallerDir = "$PSScriptRoot\installer"

# Prepare installer folder
if (Test-Path $InstallerDir) {
    Remove-Item $InstallerDir -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $InstallerDir | Out-Null

# Download NSSM zip if not exists in temp
if (!(Test-Path $NssmZip)) {
    Write-Host "Downloading NSSM..."
    Invoke-WebRequest -Uri $NssmUrl -OutFile $NssmZip
}

Write-Host "Extracting NSSM into installer folder..."
Expand-Archive -Path $NssmZip -DestinationPath $InstallerDir -Force

# Rename extracted folder from nssm-2.24 to nssm
$ExtractedFolder = Join-Path $InstallerDir "nssm-2.24"
$RenamedFolder = Join-Path $InstallerDir "nssm"

if (Test-Path $RenamedFolder) {
    Remove-Item $RenamedFolder -Recurse -Force
}

Rename-Item -Path $ExtractedFolder -NewName "nssm"

Write-Host "NSSM extracted and renamed to 'nssm' folder inside Installer."

# Copy your exe, web, tls folders as needed
$ReleaseExe = "$PSScriptRoot\..\target\release\packet-speed-monitoring.exe"
$WebDir = "$PSScriptRoot\..\web"
$TlsDir = "$PSScriptRoot\..\tls"

Write-Host "Copying executable..."
Copy-Item $ReleaseExe -Destination $InstallerDir

Write-Host "Copying web folder..."
Copy-Item $WebDir -Destination $InstallerDir -Recurse

Write-Host "Copying tls folder..."
Copy-Item $TlsDir -Destination $InstallerDir -Recurse

Write-Host "=== Installer folder ready ==="
Write-Host "Location: $InstallerDir"
Write-Host "=== Done! ==="


# Define the install script content as a here-string
$installScriptContent = @"
# Auto-generated install script
# Copies nssm folder to C:\ and other files to user bin, updates PATH

`$InstallerDir = "`$PSScriptRoot"
`$NssmSource = Join-Path `$InstallerDir "nssm"
`$TlsSource = Join-Path `$InstallerDir "tls"
`$WebSource = Join-Path `$InstallerDir "web"
`$ExeSource = Join-Path `$InstallerDir "packet-speed-monitoring.exe"

`$NssmDest = "C:\nssm"
`$UserBinDir = Join-Path `$env:USERPROFILE "bin"

Write-Host "Starting installation..."

if (!(Test-Path `$NssmDest)) {
    Write-Host "Copying NSSM folder to `$NssmDest"
    Copy-Item -Path `$NssmSource -Destination `$NssmDest -Recurse -Force
}

if (!(Test-Path `$UserBinDir)) {
    Write-Host "Creating `$UserBinDir"
    New-Item -ItemType Directory -Force -Path `$UserBinDir | Out-Null
}

Write-Host "Copying tls folder to `$UserBinDir"
Copy-Item -Path `$TlsSource -Destination `$UserBinDir -Recurse -Force

Write-Host "Copying web folder to `$UserBinDir"
Copy-Item -Path `$WebSource -Destination `$UserBinDir -Recurse -Force

Write-Host "Copying packet-speed-monitoring.exe to `$UserBinDir"
Copy-Item -Path `$ExeSource -Destination `$UserBinDir -Force

# Add NSSM bin path to user PATH environment variable
`$nssmBinPath = "C:\nssm\win64"
`$currentUserPath = [Environment]::GetEnvironmentVariable("Path", "User")

if (-not (`$currentUserPath.Split(';') -contains `$nssmBinPath)) {
    Write-Host "Adding `$nssmBinPath to user PATH environment variable"
    `$newUserPath = "`$currentUserPath;`$nssmBinPath"
    [Environment]::SetEnvironmentVariable("Path", `$newUserPath, "User")
    Write-Host "PATH updated. You may need to restart your terminal or log off/on for changes to take effect."
}
else {
    Write-Host "`$nssmBinPath is already in the user PATH."
}

# Update System PATH
try {
    `$currentSystemPath = [Environment]::GetEnvironmentVariable("Path", "Machine")
    if (-not (`$currentSystemPath.Split(';') -contains `$nssmBinPath)) {
        Write-Host "Adding `$nssmBinPath to System PATH environment variable"
        `$newSystemPath = "`$currentSystemPath;`$nssmBinPath"
        [Environment]::SetEnvironmentVariable("Path", `$newSystemPath, "Machine")
        Write-Host "System PATH updated. You may need to restart your computer for changes to take effect."
    }
    else {
        Write-Host "`$nssmBinPath is already in the System PATH."
    }
}
catch {
    Write-Warning "Failed to update System PATH. Try running this script as Administrator."
}

Write-Host "Installation complete!"

# === Register new Windows service ===
Write-Host "=== Registering new service using NSSM ==="

`$NssmPath = "C:\nssm\win64\nssm.exe"
& `$NssmPath install `$ServiceName "`$UserBinDir\`$ExecutableName"
& `$NssmPath set `$ServiceName AppDirectory `$UserBinDir
& `$NssmPath set `$ServiceName Start SERVICE_AUTO_START
& `$NssmPath start `$ServiceName

# Verify
Write-Host "=== Checking service status ==="
Get-Service -Name `$ServiceName
Write-Host "Installation complete ✅"
"@

# Write the install.ps1 file inside installer folder
$installScriptPath = Join-Path $InstallerDir "install.ps1"
Set-Content -Path $installScriptPath -Value $installScriptContent -Encoding UTF8

Write-Host "Generated install script at $installScriptPath"


$installBatPath = Join-Path $InstallerDir "install.bat"
# Batch file content to run install.ps1 with PowerShell
$installBatContent = @"
@echo off
PowerShell -NoProfile -ExecutionPolicy Bypass -File "install.ps1"
"@

# Write install.bat file
Set-Content -Path $installBatPath -Value $installBatContent -Encoding ASCII

Write-Host "Generated install batch file at $installBatPath"