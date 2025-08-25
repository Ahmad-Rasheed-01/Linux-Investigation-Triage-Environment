from datetime import datetime
from ..database import db
import uuid

class Case(db.Model):
    __tablename__ = 'cases'
    
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    case_name = db.Column(db.String(200), nullable=False)
    examiner = db.Column(db.String(100), nullable=False)
    creation_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    incident_date = db.Column(db.DateTime, nullable=True)
    tags = db.Column(db.Text, nullable=True)  # JSON string of tags
    operating_system = db.Column(db.String(100), nullable=True)
    notes = db.Column(db.Text, nullable=True)
    description = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(20), nullable=False, default='active')  # active, inactive, closed
    folder_path = db.Column(db.String(500), nullable=True)
    
    # Relationships
    artifacts = db.relationship('Artifact', backref='case', lazy=True, cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<Case {self.case_name}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'case_id': self.case_id,
            'case_name': self.case_name,
            'examiner': self.examiner,
            'creation_date': self.creation_date.isoformat() if self.creation_date else None,
            'incident_date': self.incident_date.isoformat() if self.incident_date else None,
            'tags': self.tags,
            'operating_system': self.operating_system,
            'notes': self.notes,
            'description': self.description,
            'status': self.status,
            'folder_path': self.folder_path,
            'artifact_count': len(self.artifacts)
        }
    
    @property
    def total_artifacts(self):
        return len(self.artifacts)
    
    @property
    def total_size_mb(self):
        return sum(artifact.file_size_mb for artifact in self.artifacts if artifact.file_size_mb)