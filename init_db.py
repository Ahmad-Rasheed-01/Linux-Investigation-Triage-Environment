#!/usr/bin/env python3
"""
Database Initialization Script for LITE Application

This script creates the SQLite database and initializes all required tables
for the Linux Investigation & Triage Environment (LITE) application.
"""

import os
import sys
from datetime import datetime
from pathlib import Path

# Add the project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from lite.app import app, db
from lite.models.case_model import Case
from lite.models.artifact_model import Artifact

def create_database():
    """
    Create the database and all tables.
    """
    try:
        with app.app_context():
            # Create all tables
            db.create_all()
            
            # Create upload directory if it doesn't exist
            upload_dir = Path(app.config['UPLOAD_FOLDER'])
            upload_dir.mkdir(parents=True, exist_ok=True)
            
            print("✓ Database tables created successfully")
            print(f"✓ Upload directory created: {upload_dir}")
            
            # Check if tables were created
            inspector = db.inspect(db.engine)
            tables = inspector.get_table_names()
            
            print(f"\nCreated tables: {', '.join(tables)}")
            
            return True
            
    except Exception as e:
        print(f"✗ Error creating database: {str(e)}")
        return False

def create_sample_data():
    """
    Create sample data for testing purposes.
    """
    try:
        with app.app_context():
            # Check if sample data already exists
            if Case.query.first():
                print("Sample data already exists, skipping creation")
                return True
            
            # Create sample cases
            sample_cases = [
                {
                    'case_name': 'Sample Investigation 001',
                    'examiner': 'John Doe',
                    'incident_date': datetime(2024, 1, 15),
                    'tags': 'malware,network-intrusion',
                    'operating_system': 'Ubuntu 22.04 LTS',
                    'description': 'Investigation of suspected malware infection on web server',
                    'notes': 'Initial analysis shows suspicious network connections',
                    'status': 'active',
                    'priority': 'high'
                },
                {
                    'case_name': 'Data Breach Analysis',
                    'examiner': 'Jane Smith',
                    'incident_date': datetime(2024, 1, 20),
                    'tags': 'data-breach,unauthorized-access',
                    'operating_system': 'CentOS 8',
                    'description': 'Analysis of potential data breach incident',
                    'notes': 'Investigating unauthorized database access',
                    'status': 'active',
                    'priority': 'critical'
                },
                {
                    'case_name': 'System Compromise Investigation',
                    'examiner': 'Mike Johnson',
                    'incident_date': datetime(2024, 1, 10),
                    'tags': 'system-compromise,privilege-escalation',
                    'operating_system': 'Debian 11',
                    'description': 'Investigation of system compromise with privilege escalation',
                    'notes': 'Analysis completed, case ready for closure',
                    'status': 'closed',
                    'priority': 'medium'
                }
            ]
            
            created_cases = []
            for case_data in sample_cases:
                case = Case(**case_data)
                db.session.add(case)
                created_cases.append(case)
            
            # Commit the cases first to get their IDs
            db.session.commit()
            
            print(f"✓ Created {len(created_cases)} sample cases")
            
            # Create sample artifacts for the first case
            if created_cases:
                sample_artifacts = [
                    {
                        'case_id': created_cases[0].case_id,
                        'filename': 'system_info.json',
                        'file_path': f'cases/{created_cases[0].case_id}/system_info.json',
                        'file_size': 1024 * 50,  # 50KB
                        'status': 'processed'
                    },
                    {
                        'case_id': created_cases[0].case_id,
                        'filename': 'network_connections.json',
                        'file_path': f'cases/{created_cases[0].case_id}/network_connections.json',
                        'file_size': 1024 * 200,  # 200KB
                        'status': 'processed'
                    },
                    {
                        'case_id': created_cases[0].case_id,
                        'filename': 'process_list.json',
                        'file_path': f'cases/{created_cases[0].case_id}/process_list.json',
                        'file_size': 1024 * 150,  # 150KB
                        'status': 'processing'
                    }
                ]
                
                for artifact_data in sample_artifacts:
                    artifact = Artifact(**artifact_data)
                    db.session.add(artifact)
                
                db.session.commit()
                print(f"✓ Created {len(sample_artifacts)} sample artifacts")
            
            return True
            
    except Exception as e:
        print(f"✗ Error creating sample data: {str(e)}")
        db.session.rollback()
        return False

def verify_database():
    """
    Verify that the database was created correctly.
    """
    try:
        with app.app_context():
            # Check tables exist
            inspector = db.inspect(db.engine)
            tables = inspector.get_table_names()
            
            required_tables = ['cases', 'artifacts']
            missing_tables = [table for table in required_tables if table not in tables]
            
            if missing_tables:
                print(f"✗ Missing tables: {', '.join(missing_tables)}")
                return False
            
            # Check table structures
            for table in required_tables:
                columns = [col['name'] for col in inspector.get_columns(table)]
                print(f"✓ Table '{table}' columns: {', '.join(columns)}")
            
            # Check data counts
            case_count = Case.query.count()
            artifact_count = Artifact.query.count()
            
            print(f"\nDatabase Statistics:")
            print(f"  Cases: {case_count}")
            print(f"  Artifacts: {artifact_count}")
            
            return True
            
    except Exception as e:
        print(f"✗ Error verifying database: {str(e)}")
        return False

def reset_database():
    """
    Reset the database by dropping and recreating all tables.
    """
    try:
        with app.app_context():
            print("Resetting database...")
            
            # Drop all tables
            db.drop_all()
            print("✓ Dropped all tables")
            
            # Recreate tables
            db.create_all()
            print("✓ Recreated all tables")
            
            return True
            
    except Exception as e:
        print(f"✗ Error resetting database: {str(e)}")
        return False

def main():
    """
    Main function to initialize the database.
    """
    print("LITE Database Initialization")
    print("=" * 40)
    
    # Check if database file exists (in instance folder)
    instance_dir = Path('instance')
    instance_dir.mkdir(exist_ok=True)
    db_path = instance_dir / 'lite.db'
    if db_path.exists():
        response = input(f"Database file '{db_path}' already exists. Reset it? (y/N): ")
        if response.lower() == 'y':
            if not reset_database():
                sys.exit(1)
        else:
            print("Using existing database")
    else:
        print("Creating new database...")
        if not create_database():
            sys.exit(1)
    
    # Verify database structure
    print("\nVerifying database structure...")
    if not verify_database():
        sys.exit(1)
    
    # Ask about sample data
    response = input("\nCreate sample data for testing? (Y/n): ")
    if response.lower() != 'n':
        print("Creating sample data...")
        if not create_sample_data():
            print("Warning: Failed to create sample data")
    
    print("\n" + "=" * 40)
    print("✓ Database initialization completed successfully!")
    print(f"✓ Database file: {db_path.absolute()}")
    print("✓ Ready to start the LITE application")
    print("\nTo start the application, run:")
    print("  python app.py")

if __name__ == '__main__':
    main()