# Linux Investigation & Triage Environment (LITE)

A Python Flask-based web application for ingesting, managing, and visualizing JSON artifacts collected from Linux systems. LITE provides digital forensic examiners with an intuitive, multi-case management platform that supports advanced data visualization and smooth workflow organization.

## Features

### 🔍 Case Management
- **Multi-case Support**: Create and manage multiple investigation cases
- **Case Lifecycle**: Track cases through active, inactive, and closed states
- **Metadata Management**: Store examiner details, incident dates, tags, and notes
- **Dedicated Storage**: Automatic folder creation for each case

### 📊 Data Visualization
- **Modern UI**: Professional interface with smooth animations
- **Interactive Dashboards**: Main dashboard with system overview
- **Case Analytics**: Individual case statistics and artifact summaries
- **Advanced Filtering**: Sort, search, and filter artifacts efficiently

### 📁 Artifact Processing
- **JSON Ingestion**: Support for large JSON files (200-300MB each)
- **Non-blocking Processing**: Asynchronous file processing for smooth UI
- **Batch Upload**: Handle 80-100 JSON files per case
- **Status Tracking**: Monitor processing status in real-time

### 🔎 Analysis Tools
- **Expandable Navigation**: Organized analysis sections
- **Content Search**: Search within artifacts and metadata
- **Data Exploration**: Interactive artifact content viewing
- **Export Capabilities**: Download and export case data

## Quick Start

### Prerequisites
- Python 3.8 or higher
- Windows 10/11 (PowerShell support recommended)
- At least 4GB RAM (recommended 8GB for large datasets)
- 10GB+ free disk space for artifacts

### Installation

1. **Clone or Download** the project to your local machine

2. **Run the Startup Script**:
   
   **Option A: Batch Script (Command Prompt)**
   ```cmd
   start_lite.bat
   ```
   
   **Option B: PowerShell Script**
   ```powershell
   .\start_lite.ps1
   ```
   
   The startup script will automatically:
   - Create a Python virtual environment
   - Install required dependencies
   - Initialize the SQLite database
   - Start the Flask application

3. **Access the Application**:
   Open your web browser and navigate to:
   - http://localhost:5000
   - http://127.0.0.1:5000

### Manual Setup (Alternative)

If you prefer manual setup:

```cmd
# Create virtual environment
python -m venv venv

# Activate virtual environment
venv\Scripts\activate.bat  # Windows CMD
# OR
venv\Scripts\Activate.ps1  # PowerShell

# Install dependencies
pip install -r requirements.txt

# Initialize database
python init_db.py

# Start application
python app.py
```

## Project Structure

```
LITE/
├── app.py                 # Main Flask application
├── init_db.py            # Database initialization script
├── requirements.txt      # Python dependencies
├── start_lite.bat       # Windows batch startup script
├── start_lite.ps1       # PowerShell startup script
├── README.md            # This file
├── lite.db              # SQLite database (created automatically)
├── lite/                # Main application package
│   ├── __init__.py
│   ├── models/          # Database models
│   │   ├── __init__.py
│   │   ├── case_model.py
│   │   └── artifact_model.py
│   ├── routes/          # Flask routes
│   │   ├── __init__.py
│   │   ├── main_routes.py
│   │   ├── case_routes.py
│   │   └── analysis_routes.py
│   ├── services/        # Business logic
│   │   ├── __init__.py
│   │   ├── file_service.py
│   │   └── json_parser.py
│   ├── templates/       # HTML templates
│   │   ├── base.html
│   │   ├── dashboard.html
│   │   ├── cases/
│   │   │   ├── list.html
│   │   │   ├── create.html
│   │   │   ├── detail.html
│   │   │   └── upload.html
│   │   └── analysis/
│   │       └── analysis.html
│   └── static/          # Static assets
│       ├── css/
│       │   └── style.css
│       └── js/
│           └── app.js
└── uploads/             # File storage (created automatically)
    └── cases/           # Case-specific folders
```

## Usage Guide

### Creating a New Case

1. Navigate to **Cases** → **Create New Case**
2. Fill in the required information:
   - **Case Name**: Descriptive name for the investigation
   - **Examiner**: Your name or ID
   - **Incident Date**: When the incident occurred
   - **Operating System**: Target system OS
   - **Tags**: Comma-separated keywords
   - **Description**: Case overview
   - **Notes**: Additional details

3. Optionally upload initial JSON artifacts
4. Click **Create Case**

### Uploading Artifacts

1. Go to a specific case detail page
2. Click **Upload Artifacts**
3. Drag and drop JSON files or click to browse
4. Files are validated and processed automatically
5. Monitor processing status in real-time

### Analyzing Data

1. From a case detail page, click **Analyze**
2. Use the expandable sidebar to navigate sections:
   - **Overview**: Case summary and artifact statistics
   - **System Information**: System details from artifacts
   - **Users**: User account information
   - **Processes**: Running processes data
   - **Network**: Network connections and traffic
   - **Logs**: System and application logs
   - **File System**: File system artifacts

3. Use the search functionality to find specific data
4. Click on individual artifacts to view detailed content

### Dashboard Overview

- **Statistics Cards**: Quick overview of cases and artifacts
- **Charts**: Visual representation of case status and trends
- **Recent Activity**: Latest case updates
- **System Health**: Application performance metrics



## Configuration

### Environment Variables
- `FLASK_ENV`: Set to `development` or `production`
- `FLASK_DEBUG`: Enable/disable debug mode
- `SECRET_KEY`: Flask secret key (auto-generated)

### Database
- **Type**: SQLite
- **Location**: `lite.db` in project root
- **Backup**: Recommended to backup regularly

### File Storage
- **Location**: `uploads/cases/` directory
- **Structure**: Each case gets its own subdirectory
- **Naming**: Original filenames are preserved

## Troubleshooting

### Common Issues

**Python not found**
- Ensure Python 3.8+ is installed
- Add Python to your system PATH
- Restart command prompt/PowerShell

**Virtual environment activation fails**
- For PowerShell: Run `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser`
- Use Command Prompt as alternative

**Database errors**
- Delete `lite.db` and run `python init_db.py`
- Check file permissions in project directory

**Port 5000 already in use**
- Stop other applications using port 5000
- Modify `app.py` to use a different port

**Large file upload issues**
- Check available disk space
- Ensure files are valid JSON format
- Monitor system memory usage

### Performance Optimization

- **Memory**: Increase system RAM for large datasets
- **Storage**: Use SSD for better I/O performance
- **Processing**: Close unnecessary applications during analysis

## Security Considerations

- **Local Use**: Application designed for local/trusted network use
- **File Validation**: Only JSON files are accepted
- **Data Isolation**: Each case stored in separate directories
- **Access Control**: No built-in authentication (add if needed)

## Development

### Adding New Features

1. **Models**: Add new database models in `lite/models/`
2. **Routes**: Create new routes in `lite/routes/`
3. **Services**: Add business logic in `lite/services/`
4. **Templates**: Create HTML templates in `lite/templates/`
5. **Static Assets**: Add CSS/JS in `lite/static/`

### Database Migrations

```python
# Reset database (WARNING: Deletes all data)
python init_db.py

# Manual migration
from app import app, db
with app.app_context():
    db.create_all()
```

## Support

For issues, questions, or contributions:

1. Check the troubleshooting section above
2. Review the application logs in the console
3. Ensure all dependencies are properly installed
4. Verify the sample dataset path is correct

## License

This project is developed for educational and professional forensic analysis purposes. Please ensure compliance with your organization's policies and applicable laws when analyzing system artifacts.

---

**LITE - Linux Investigation & Triage Environment**  
*Empowering Digital Forensic Examiners with Modern Tools*