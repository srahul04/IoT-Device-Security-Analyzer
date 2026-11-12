# Param so it can be called from cmd.exe: powershell -ExecutionPolicy Bypass -File launch.ps1
param()

$USB = $PSScriptRoot

# Add bundled tools to PATH if present
if (Test-Path "$USB\tools\node\node.exe") { $env:PATH = "$USB\tools\node;$env:PATH" }
if (Test-Path "$USB\tools\python\python.exe") { $env:PATH = "$USB\tools\python;$env:PATH" }

# Load .env
$envFile = Join-Path $USB ".env"
if (Test-Path $envFile) {
    Get-Content $envFile | ForEach-Object {
        if ($_ -match "^\s*([^#=]+)=(.+)$") {
            [System.Environment]::SetEnvironmentVariable($matches[1].Trim(), $matches[2].Trim(), "Process")
        }
    }
}

# Check Node
if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
    Write-Error "Node.js not found. Install Node 18+ or place it in $USB\tools\node\"; exit 1
}

# Check Python
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Error "Python not found. Install Python 3.10+ or place it in $USB\tools\python\"; exit 1
}

# Install backend deps if missing
$backendDir = Join-Path $USB "backend"
if (-not (Test-Path "$backendDir\node_modules")) {
    Write-Host "Installing backend dependencies..."
    Push-Location $backendDir
    npm install --silent
    Pop-Location
}

# Start backend
$backend = Join-Path $USB "backend"
Start-Process -FilePath "node" -ArgumentList "server.js" -WorkingDirectory $backend -WindowStyle Minimized

# Wait and open browser
Start-Sleep -Seconds 3
Start-Process "http://localhost:5000"

Write-Host "IDSA is running at http://localhost:5000"
Write-Host "Close the Node.js window to stop the server."

