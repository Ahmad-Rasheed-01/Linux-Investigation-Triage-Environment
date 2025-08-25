# LITE Application Startup Script for PowerShell
# This script sets up the virtual environment and starts the Flask application

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Linux Investigation & Triage Environment" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Function to check if command exists
function Test-Command($cmdname) {
    return [bool](Get-Command -Name $cmdname -ErrorAction SilentlyContinue)
}

# Check if Python is installed
if (-not (Test-Command "python")) {
    Write-Host "ERROR: Python is not installed or not in PATH" -ForegroundColor Red
    Write-Host "Please install Python 3.8+ and add it to your PATH" -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit 1
}

# Display Python version
Write-Host "Python version:" -ForegroundColor Green
python --version
Write-Host ""

# Check if virtual environment exists
if (-not (Test-Path "venv")) {
    Write-Host "Creating virtual environment..." -ForegroundColor Yellow
    python -m venv venv
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: Failed to create virtual environment" -ForegroundColor Red
        Read-Host "Press Enter to exit"
        exit 1
    }
    Write-Host "Virtual environment created successfully" -ForegroundColor Green
    Write-Host ""
}

# Activate virtual environment
Write-Host "Activating virtual environment..." -ForegroundColor Yellow
& ".\venv\Scripts\Activate.ps1"
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Failed to activate virtual environment" -ForegroundColor Red
    Write-Host "You may need to run: Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser" -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit 1
}
Write-Host "Virtual environment activated" -ForegroundColor Green
Write-Host ""

# Upgrade pip
Write-Host "Upgrading pip..." -ForegroundColor Yellow
python -m pip install --upgrade pip
Write-Host ""

# Install requirements
Write-Host "Installing/updating requirements..." -ForegroundColor Yellow
if (Test-Path "requirements.txt") {
    pip install -r requirements.txt
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: Failed to install requirements" -ForegroundColor Red
        Read-Host "Press Enter to exit"
        exit 1
    }
    Write-Host "Requirements installed successfully" -ForegroundColor Green
} else {
    Write-Host "WARNING: requirements.txt not found" -ForegroundColor Yellow
    Write-Host "Installing Flask manually..." -ForegroundColor Yellow
    pip install Flask Flask-SQLAlchemy
}
Write-Host ""

# Initialize database if it doesn't exist
if (-not (Test-Path "lite.db")) {
    Write-Host "Database not found. Initializing..." -ForegroundColor Yellow
    python init_db.py
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: Failed to initialize database" -ForegroundColor Red
        Read-Host "Press Enter to exit"
        exit 1
    }
    Write-Host "Database initialized successfully" -ForegroundColor Green
    Write-Host ""
}

# Set environment variables
$env:FLASK_APP = "app.py"
$env:FLASK_ENV = "development"
$env:FLASK_DEBUG = "1"

# Display startup information
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "LITE Application Starting..." -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Flask App: $($env:FLASK_APP)" -ForegroundColor White
Write-Host "Environment: $($env:FLASK_ENV)" -ForegroundColor White
Write-Host "Debug Mode: $($env:FLASK_DEBUG)" -ForegroundColor White
Write-Host ""
Write-Host "The application will be available at:" -ForegroundColor Green
Write-Host "  http://localhost:5000" -ForegroundColor Cyan
Write-Host "  http://127.0.0.1:5000" -ForegroundColor Cyan
Write-Host ""
Write-Host "Press Ctrl+C to stop the application" -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Start the Flask application
try {
    python app.py
} catch {
    Write-Host "" 
    Write-Host "Application exited with error: $($_.Exception.Message)" -ForegroundColor Red
    Read-Host "Press Enter to exit"
}