from flask import Blueprint, render_template, jsonify
from ..models.case_model import Case
from ..models.artifact_model import Artifact
from ..database import db
from sqlalchemy import func

bp = Blueprint('main', __name__)

@bp.route('/')
def index():
    """Main dashboard with overview of all cases"""
    # Get case statistics
    total_cases = Case.query.count()
    active_cases = Case.query.filter_by(status='active').count()
    inactive_cases = Case.query.filter_by(status='inactive').count()
    closed_cases = Case.query.filter_by(status='closed').count()
    
    # Get artifact statistics
    total_artifacts = Artifact.query.count()
    total_size_mb = db.session.query(func.sum(Artifact.file_size_mb)).scalar() or 0
    
    # Get recent cases
    recent_cases = Case.query.order_by(Case.creation_date.desc()).limit(5).all()
    
    # Get processing status counts
    processing_stats = db.session.query(
        Artifact.processing_status,
        func.count(Artifact.id)
    ).group_by(Artifact.processing_status).all()
    
    processing_counts = {status: count for status, count in processing_stats}
    
    stats = {
        'total_cases': total_cases,
        'active_cases': active_cases,
        'inactive_cases': inactive_cases,
        'closed_cases': closed_cases,
        'total_artifacts': total_artifacts,
        'total_size_gb': round(total_size_mb / 1024, 2) if total_size_mb else 0,
        'processing_counts': processing_counts
    }
    
    return render_template('dashboard.html', stats=stats, recent_cases=recent_cases)

@bp.route('/api/dashboard/stats')
def dashboard_stats_api():
    """API endpoint for dashboard statistics"""
    # Get case statistics
    total_cases = Case.query.count()
    active_cases = Case.query.filter_by(status='active').count()
    inactive_cases = Case.query.filter_by(status='inactive').count()
    closed_cases = Case.query.filter_by(status='closed').count()
    
    # Get artifact statistics
    total_artifacts = Artifact.query.count()
    total_size_mb = db.session.query(func.sum(Artifact.file_size_mb)).scalar() or 0
    
    # Get category distribution
    category_stats = db.session.query(
        Artifact.artifact_category,
        func.count(Artifact.id)
    ).group_by(Artifact.artifact_category).all()
    
    category_counts = {category or 'Uncategorized': count for category, count in category_stats}
    
    # Get processing status counts
    processing_stats = db.session.query(
        Artifact.processing_status,
        func.count(Artifact.id)
    ).group_by(Artifact.processing_status).all()
    
    processing_counts = {status: count for status, count in processing_stats}
    
    return jsonify({
        'cases': {
            'total': total_cases,
            'active': active_cases,
            'inactive': inactive_cases,
            'closed': closed_cases
        },
        'artifacts': {
            'total': total_artifacts,
            'total_size_gb': round(total_size_mb / 1024, 2) if total_size_mb else 0,
            'categories': category_counts,
            'processing_status': processing_counts
        }
    })

@bp.route('/health')
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'database': 'connected',
        'timestamp': datetime.utcnow().isoformat()
    })