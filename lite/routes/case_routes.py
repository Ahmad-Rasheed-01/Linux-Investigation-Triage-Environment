from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, current_app
from models.case_model import Case
from models.artifact_model import Artifact
from services.file_service import FileService
from app import db
from datetime import datetime
import os
import json

bp = Blueprint('cases', __name__, url_prefix='/cases')

@bp.route('/')
def list_cases():
    """Cases dashboard - list all cases"""
    page = request.args.get('page', 1, type=int)
    per_page = 12  # Number of cases per page
    
    cases = Case.query.order_by(Case.creation_date.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    return render_template('cases/list.html', cases=cases)

@bp.route('/create', methods=['GET', 'POST'])
def create_case():
    """Create a new case"""
    if request.method == 'POST':
        try:
            # Get form data
            case_name = request.form.get('case_name')
            examiner = request.form.get('examiner')
            incident_date_str = request.form.get('incident_date')
            tags = request.form.get('tags', '')
            operating_system = request.form.get('operating_system')
            notes = request.form.get('notes', '')
            description = request.form.get('description', '')
            
            # Validate required fields
            if not case_name or not examiner:
                flash('Case name and examiner are required.', 'error')
                return render_template('cases/create.html')
            
            # Parse incident date
            incident_date = None
            if incident_date_str:
                try:
                    incident_date = datetime.strptime(incident_date_str, '%Y-%m-%d')
                except ValueError:
                    flash('Invalid incident date format.', 'error')
                    return render_template('cases/create.html')
            
            # Create new case
            new_case = Case(
                case_name=case_name,
                examiner=examiner,
                incident_date=incident_date,
                tags=tags,
                operating_system=operating_system,
                notes=notes,
                description=description
            )
            
            db.session.add(new_case)
            db.session.commit()
            
            # Create case folder
            case_folder = os.path.join(current_app.config['UPLOAD_FOLDER'], new_case.case_id)
            os.makedirs(case_folder, exist_ok=True)
            new_case.folder_path = case_folder
            db.session.commit()
            
            flash(f'Case "{case_name}" created successfully!', 'success')
            return redirect(url_for('cases.view_case', case_id=new_case.case_id))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error creating case: {str(e)}', 'error')
            return render_template('cases/create.html')
    
    return render_template('cases/create.html')

@bp.route('/<case_id>')
def view_case(case_id):
    """View individual case details"""
    case = Case.query.filter_by(case_id=case_id).first_or_404()
    
    # Get artifacts with pagination
    page = request.args.get('page', 1, type=int)
    per_page = 20
    
    artifacts = Artifact.query.filter_by(case_id=case.id).order_by(
        Artifact.upload_timestamp.desc()
    ).paginate(page=page, per_page=per_page, error_out=False)
    
    # Get artifact statistics
    artifact_stats = {
        'total': len(case.artifacts),
        'by_category': {},
        'by_status': {},
        'total_size_mb': case.total_size_mb
    }
    
    # Calculate category and status distributions
    for artifact in case.artifacts:
        category = artifact.artifact_category or 'Uncategorized'
        status = artifact.processing_status
        
        artifact_stats['by_category'][category] = artifact_stats['by_category'].get(category, 0) + 1
        artifact_stats['by_status'][status] = artifact_stats['by_status'].get(status, 0) + 1
    
    return render_template('cases/view.html', case=case, artifacts=artifacts, stats=artifact_stats)

@bp.route('/<case_id>/upload', methods=['POST'])
def upload_artifacts(case_id):
    """Upload JSON artifacts to a case"""
    case = Case.query.filter_by(case_id=case_id).first_or_404()
    
    if 'files' not in request.files:
        flash('No files selected.', 'error')
        return redirect(url_for('cases.view_case', case_id=case_id))
    
    files = request.files.getlist('files')
    uploaded_count = 0
    
    try:
        file_service = FileService()
        
        for file in files:
            if file and file.filename:
                if file.filename.lower().endswith('.json'):
                    success = file_service.save_artifact(file, case)
                    if success:
                        uploaded_count += 1
                else:
                    flash(f'Skipped {file.filename}: Only JSON files are allowed.', 'warning')
        
        if uploaded_count > 0:
            flash(f'Successfully uploaded {uploaded_count} artifact(s).', 'success')
        else:
            flash('No files were uploaded.', 'warning')
            
    except Exception as e:
        flash(f'Error uploading files: {str(e)}', 'error')
    
    return redirect(url_for('cases.view_case', case_id=case_id))

@bp.route('/<case_id>/status', methods=['POST'])
def update_case_status(case_id):
    """Update case status"""
    case = Case.query.filter_by(case_id=case_id).first_or_404()
    
    new_status = request.json.get('status')
    if new_status not in ['active', 'inactive', 'closed']:
        return jsonify({'error': 'Invalid status'}), 400
    
    try:
        case.status = new_status
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': f'Case status updated to {new_status}',
            'status': new_status
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@bp.route('/api/cases')
def api_list_cases():
    """API endpoint to list cases"""
    cases = Case.query.order_by(Case.creation_date.desc()).all()
    return jsonify([case.to_dict() for case in cases])

@bp.route('/api/cases/<case_id>')
def api_get_case(case_id):
    """API endpoint to get case details"""
    case = Case.query.filter_by(case_id=case_id).first_or_404()
    case_data = case.to_dict()
    case_data['artifacts'] = [artifact.to_dict() for artifact in case.artifacts]
    return jsonify(case_data)