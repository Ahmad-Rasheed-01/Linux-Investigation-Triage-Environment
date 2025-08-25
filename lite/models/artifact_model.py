from datetime import datetime
from ..database import db

class Artifact(db.Model):
    __tablename__ = 'artifacts'
    
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    file_path = db.Column(db.String(500), nullable=False)
    file_type = db.Column(db.String(50), nullable=False, default='json')
    file_size_bytes = db.Column(db.BigInteger, nullable=True)
    file_size_mb = db.Column(db.Float, nullable=True)
    upload_timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    processing_status = db.Column(db.String(20), nullable=False, default='pending')  # pending, processing, completed, error
    processing_error = db.Column(db.Text, nullable=True)
    artifact_category = db.Column(db.String(100), nullable=True)  # system, network, logs, etc.
    record_count = db.Column(db.Integer, nullable=True)  # number of records in JSON
    
    # Foreign key
    case_id = db.Column(db.Integer, db.ForeignKey('cases.id'), nullable=False)
    
    def __repr__(self):
        return f'<Artifact {self.filename}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'filename': self.filename,
            'original_filename': self.original_filename,
            'file_path': self.file_path,
            'file_type': self.file_type,
            'file_size_bytes': self.file_size_bytes,
            'file_size_mb': self.file_size_mb,
            'upload_timestamp': self.upload_timestamp.isoformat() if self.upload_timestamp else None,
            'processing_status': self.processing_status,
            'processing_error': self.processing_error,
            'artifact_category': self.artifact_category,
            'record_count': self.record_count,
            'case_id': self.case_id
        }
    
    @property
    def file_size_formatted(self):
        """Return formatted file size"""
        if not self.file_size_bytes:
            return "Unknown"
        
        size = self.file_size_bytes
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} TB"
    
    def categorize_artifact(self):
        """Auto-categorize artifact based on filename"""
        filename_lower = self.filename.lower()
        
        if any(keyword in filename_lower for keyword in ['network', 'connection', 'port', 'socket', 'arp', 'dns', 'routing']):
            self.artifact_category = 'Network'
        elif any(keyword in filename_lower for keyword in ['process', 'cpu', 'memory', 'system', 'kernel', 'uptime']):
            self.artifact_category = 'System'
        elif any(keyword in filename_lower for keyword in ['user', 'account', 'group', 'password', 'auth', 'sudo']):
            self.artifact_category = 'Users'
        elif any(keyword in filename_lower for keyword in ['log', 'syslog', 'auth', 'kern', 'audit', 'btmp', 'wtmp']):
            self.artifact_category = 'Logs'
        elif any(keyword in filename_lower for keyword in ['disk', 'mount', 'filesystem', 'block', 'fdisk']):
            self.artifact_category = 'Storage'
        elif any(keyword in filename_lower for keyword in ['browser', 'history', 'download', 'search']):
            self.artifact_category = 'Browser'
        else:
            self.artifact_category = 'Other'