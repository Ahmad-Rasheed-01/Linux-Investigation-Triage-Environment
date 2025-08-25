import os
import json
import threading
from datetime import datetime
from werkzeug.utils import secure_filename
from models.artifact_model import Artifact
from app import db

class FileService:
    """Service for handling file uploads and processing"""
    
    def __init__(self):
        self.allowed_extensions = {'json'}
    
    def allowed_file(self, filename):
        """Check if file extension is allowed"""
        return '.' in filename and \
               filename.rsplit('.', 1)[1].lower() in self.allowed_extensions
    
    def save_artifact(self, file, case):
        """Save uploaded artifact file and create database record"""
        if not file or not self.allowed_file(file.filename):
            return False
        
        try:
            # Secure the filename
            original_filename = file.filename
            filename = secure_filename(original_filename)
            
            # Ensure unique filename
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            name, ext = os.path.splitext(filename)
            unique_filename = f"{name}_{timestamp}{ext}"
            
            # Create file path
            file_path = os.path.join(case.folder_path, unique_filename)
            
            # Save file
            file.save(file_path)
            
            # Get file size
            file_size_bytes = os.path.getsize(file_path)
            file_size_mb = file_size_bytes / (1024 * 1024)
            
            # Create artifact record
            artifact = Artifact(
                filename=unique_filename,
                original_filename=original_filename,
                file_path=file_path,
                file_type='json',
                file_size_bytes=file_size_bytes,
                file_size_mb=file_size_mb,
                case_id=case.id,
                processing_status='pending'
            )
            
            # Auto-categorize artifact
            artifact.categorize_artifact()
            
            db.session.add(artifact)
            db.session.commit()
            
            # Process file asynchronously
            threading.Thread(
                target=self._process_artifact_async,
                args=(artifact.id,),
                daemon=True
            ).start()
            
            return True
            
        except Exception as e:
            print(f"Error saving artifact: {str(e)}")
            return False
    
    def _process_artifact_async(self, artifact_id):
        """Process artifact asynchronously"""
        try:
            # Get artifact from database
            artifact = Artifact.query.get(artifact_id)
            if not artifact:
                return
            
            # Update status to processing
            artifact.processing_status = 'processing'
            db.session.commit()
            
            # Process JSON file
            self._analyze_json_file(artifact)
            
            # Update status to completed
            artifact.processing_status = 'completed'
            db.session.commit()
            
        except Exception as e:
            # Update status to error
            artifact = Artifact.query.get(artifact_id)
            if artifact:
                artifact.processing_status = 'error'
                artifact.processing_error = str(e)
                db.session.commit()
    
    def _analyze_json_file(self, artifact):
        """Analyze JSON file and extract metadata"""
        try:
            with open(artifact.file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Count records
            if isinstance(data, list):
                artifact.record_count = len(data)
            elif isinstance(data, dict):
                artifact.record_count = 1
            else:
                artifact.record_count = 0
            
            # Additional analysis could be added here
            # For example: extracting timestamps, identifying data types, etc.
            
        except json.JSONDecodeError as e:
            raise Exception(f"Invalid JSON format: {str(e)}")
        except Exception as e:
            raise Exception(f"Error analyzing file: {str(e)}")
    
    def delete_artifact(self, artifact):
        """Delete artifact file and database record"""
        try:
            # Delete file if it exists
            if os.path.exists(artifact.file_path):
                os.remove(artifact.file_path)
            
            # Delete database record
            db.session.delete(artifact)
            db.session.commit()
            
            return True
            
        except Exception as e:
            print(f"Error deleting artifact: {str(e)}")
            return False
    
    def get_file_info(self, file_path):
        """Get basic file information"""
        try:
            if not os.path.exists(file_path):
                return None
            
            stat = os.stat(file_path)
            return {
                'size_bytes': stat.st_size,
                'size_mb': stat.st_size / (1024 * 1024),
                'modified_time': datetime.fromtimestamp(stat.st_mtime),
                'created_time': datetime.fromtimestamp(stat.st_ctime)
            }
            
        except Exception as e:
            print(f"Error getting file info: {str(e)}")
            return None
    
    def validate_json_file(self, file_path):
        """Validate JSON file format"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                json.load(f)
            return True, None
            
        except json.JSONDecodeError as e:
            return False, f"Invalid JSON: {str(e)}"
        except Exception as e:
            return False, f"Error reading file: {str(e)}"