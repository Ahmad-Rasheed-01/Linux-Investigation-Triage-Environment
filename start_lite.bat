@echo off
REM LITE Application Startup Script for Windows
REM This script sets up the virtual environment and starts the Flask application

echo ========================================
echo Linux Investigation ^& Triage Environment
echo ========================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.8+ and add it to your PATH
    pause
    exit /b 1
)

REM Display Python version
echo Python version:
python --version
echo.

REM Check if virtual environment exists
if not exist "venv" (
    echo Creating virtual environment...
    python -m venv venv
    if errorlevel 1 (
        echo ERROR: Failed to create virtual environment
        pause
        exit /b 1
    )
    echo Virtual environment created successfully
echo.
)

REM Activate virtual environment
echo Activating virtual environment...
call venv\Scripts\activate.bat
if errorlevel 1 (
    echo ERROR: Failed to activate virtual environment
    pause
    exit /b 1
)
echo Virtual environment activated
echo.

REM Upgrade pip
echo Upgrading pip...
python -m pip install --upgrade pip
echo.

REM Install requirements
echo Installing/updating requirements...
if exist "requirements.txt" (
    pip install -r requirements.txt
    if errorlevel 1 (
        echo ERROR: Failed to install requirements
        pause
        exit /b 1
    )
    echo Requirements installed successfully
) else (
    echo WARNING: requirements.txt not found
    echo Installing Flask manually...
    pip install Flask Flask-SQLAlchemy
)
echo.

REM Initialize database if it doesn't exist
if not exist "lite.db" (
    echo Database not found. Initializing...
    python init_db.py
    if errorlevel 1 (
        echo ERROR: Failed to initialize database
        pause
        exit /b 1
    )
    echo Database initialized successfully
echo.
)

REM Set environment variables
set FLASK_APP=app.py
set FLASK_ENV=development
set FLASK_DEBUG=1

REM Display startup information
echo ========================================
echo LITE Application Starting...
echo ========================================
echo Flask App: %FLASK_APP%
echo Environment: %FLASK_ENV%
echo Debug Mode: %FLASK_DEBUG%
echo.
echo The application will be available at:
echo   http://localhost:5000
echo   http://127.0.0.1:5000
echo.
echo Press Ctrl+C to stop the application
echo ========================================
echo.

REM Start the Flask application
python app.py

REM Pause on exit to see any error messages
if errorlevel 1 (
    echo.
    echo Application exited with error
    pause
)