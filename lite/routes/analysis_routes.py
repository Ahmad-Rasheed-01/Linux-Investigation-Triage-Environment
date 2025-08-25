from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from ..models.case_model import Case
from ..models.artifact_model import Artifact
from ..services.json_parser import JsonParser
from ..database import db
import json
import os

bp = Blueprint('analysis', __name__, url_prefix='/analysis')

@bp.route('/<case_id>')
def analysis_page(case_id):
    """Main analysis page with expandable navigation"""
    case = Case.query.filter_by(case_id=case_id).first_or_404()
    
    # Get artifacts grouped by category
    artifacts_by_category = {}
    for artifact in case.artifacts:
        category = artifact.artifact_category or 'Other'
        if category not in artifacts_by_category:
            artifacts_by_category[category] = []
        artifacts_by_category[category].append(artifact)
    
    # Define navigation structure
    nav_structure = {
        'Overview': {
            'icon': 'fas fa-chart-pie',
            'expanded': True,
            'items': {
                'Case Summary': 'overview-summary',
                'Artifacts Overview': 'overview-artifacts',
                'File Types': 'overview-types',
                'Processing Status': 'overview-status'
            }
        },
        'System Information': {
            'icon': 'fas fa-server',
            'expanded': False,
            'items': {
                'System Details': 'system-details',
                'Hardware Info': 'system-hardware',
                'Kernel Information': 'system-kernel',
                'Environment': 'system-environment'
            }
        },
        'Users': {
            'icon': 'fas fa-users',
            'expanded': False,
            'items': {
                'User Accounts': 'users-accounts',
                'Group Information': 'users-groups',
                'Authentication': 'users-auth',
                'Sudo Configuration': 'users-sudo'
            }
        },
        'Processes': {
            'icon': 'fas fa-tasks',
            'expanded': False,
            'items': {
                'Running Processes': 'processes-running',
                'Process Tree': 'processes-tree',
                'System Services': 'processes-services',
                'Scheduled Tasks': 'processes-scheduled'
            }
        },
        'Network': {
            'icon': 'fas fa-network-wired',
            'expanded': False,
            'items': {
                'Network Interfaces': 'network-interfaces',
                'Connections': 'network-connections',
                'Open Ports': 'network-ports',
                'Routing Table': 'network-routing',
                'DNS Configuration': 'network-dns'
            }
        },
        'Storage': {
            'icon': 'fas fa-hdd',
            'expanded': False,
            'items': {
                'Disk Information': 'storage-disks',
                'Mount Points': 'storage-mounts',
                'File Systems': 'storage-filesystems',
                'Block Devices': 'storage-blocks'
            }
        },
        'Logs': {
            'icon': 'fas fa-file-alt',
            'expanded': False,
            'items': {
                'System Logs': 'logs-system',
                'Authentication Logs': 'logs-auth',
                'Kernel Logs': 'logs-kernel',
                'Audit Logs': 'logs-audit',
                'User Activity': 'logs-user'
            }
        },
        'Browser Data': {
            'icon': 'fas fa-globe',
            'expanded': False,
            'items': {
                'Browsing History': 'browser-history',
                'Downloads': 'browser-downloads',
                'Search History': 'browser-search',
                'Extensions': 'browser-extensions'
            }
        }
    }
    
    return render_template('analysis/analysis.html', 
                         case=case, 
                         artifacts_by_category=artifacts_by_category,
                         nav_structure=nav_structure)

@bp.route('/<case_id>/data/<section>')
def get_section_data(case_id, section):
    """Get data for a specific analysis section"""
    case = Case.query.filter_by(case_id=case_id).first_or_404()
    
    try:
        json_parser = JsonParser()
        
        if section == 'overview-summary':
            return jsonify({
                'case_info': case.to_dict(),
                'total_artifacts': len(case.artifacts),
                'total_size_gb': round(case.total_size_mb / 1024, 2) if case.total_size_mb else 0,
                'categories': _get_category_stats(case.artifacts),
                'status_distribution': _get_status_stats(case.artifacts)
            })
        
        elif section == 'overview-artifacts':
            artifacts_data = []
            for artifact in case.artifacts:
                artifact_dict = artifact.to_dict()
                artifact_dict['file_size_formatted'] = artifact.file_size_formatted
                artifacts_data.append(artifact_dict)
            
            return jsonify({
                'artifacts': artifacts_data,
                'total_count': len(artifacts_data)
            })
        
        elif section == 'system-details':
            system_artifacts = _get_artifacts_by_keywords(case.artifacts, 
                ['system', 'cpu', 'memory', 'uptime', 'kernel_version', 'locale'])
            system_data = {}
            
            for artifact in system_artifacts:
                data = json_parser.load_json_file(artifact.file_path)
                if data:
                    system_data[artifact.filename] = data
            
            return jsonify(system_data)
        
        elif section == 'users-accounts':
            user_artifacts = _get_artifacts_by_keywords(case.artifacts, 
                ['user', 'account', 'group', 'password'])
            user_data = {}
            
            for artifact in user_artifacts:
                data = json_parser.load_json_file(artifact.file_path)
                if data:
                    user_data[artifact.filename] = data
            
            return jsonify(user_data)
        
        elif section == 'network-connections':
            network_artifacts = _get_artifacts_by_keywords(case.artifacts, 
                ['network', 'connection', 'port', 'socket', 'interface'])
            network_data = {}
            
            for artifact in network_artifacts:
                data = json_parser.load_json_file(artifact.file_path)
                if data:
                    network_data[artifact.filename] = data
            
            return jsonify(network_data)
        
        elif section == 'processes-running':
            process_artifacts = _get_artifacts_by_keywords(case.artifacts, 
                ['process', 'service', 'systemd'])
            process_data = {}
            
            for artifact in process_artifacts:
                data = json_parser.load_json_file(artifact.file_path)
                if data:
                    process_data[artifact.filename] = data
            
            return jsonify(process_data)
        
        elif section == 'logs-system':
            log_artifacts = _get_artifacts_by_keywords(case.artifacts, 
                ['log', 'syslog', 'auth', 'kern', 'audit'])
            log_data = {}
            
            for artifact in log_artifacts:
                data = json_parser.load_json_file(artifact.file_path)
                if data:
                    # Limit log entries for performance
                    if isinstance(data, list) and len(data) > 1000:
                        data = data[:1000]  # Show first 1000 entries
                    log_data[artifact.filename] = data
            
            return jsonify(log_data)
        
        else:
            return jsonify({'error': 'Section not found'}), 404
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@bp.route('/<case_id>/artifact/<int:artifact_id>')
def view_artifact(case_id, artifact_id):
    """View individual artifact content"""
    case = Case.query.filter_by(case_id=case_id).first_or_404()
    artifact = Artifact.query.filter_by(id=artifact_id, case_id=case.id).first_or_404()
    
    try:
        json_parser = JsonParser()
        data = json_parser.load_json_file(artifact.file_path)
        
        return jsonify({
            'artifact': artifact.to_dict(),
            'data': data,
            'record_count': len(data) if isinstance(data, list) else 1
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@bp.route('/<case_id>/search')
def search_artifacts(case_id):
    """Search within artifacts"""
    case = Case.query.filter_by(case_id=case_id).first_or_404()
    query = request.args.get('q', '')
    category = request.args.get('category', '')
    
    if not query:
        return jsonify({'results': [], 'total': 0})
    
    # Filter artifacts
    artifacts = case.artifacts
    if category:
        artifacts = [a for a in artifacts if a.artifact_category == category]
    
    # Search in filenames and content
    results = []
    json_parser = JsonParser()
    
    for artifact in artifacts:
        if query.lower() in artifact.filename.lower():
            results.append({
                'artifact': artifact.to_dict(),
                'match_type': 'filename',
                'match_text': artifact.filename
            })
        else:
            # Search in content (limited for performance)
            try:
                data = json_parser.load_json_file(artifact.file_path)
                if data and json_parser.search_in_data(data, query):
                    results.append({
                        'artifact': artifact.to_dict(),
                        'match_type': 'content',
                        'match_text': f'Found in {artifact.filename}'
                    })
            except:
                continue
    
    return jsonify({
        'results': results[:50],  # Limit results
        'total': len(results),
        'query': query
    })

def _get_category_stats(artifacts):
    """Get artifact count by category"""
    stats = {}
    for artifact in artifacts:
        category = artifact.artifact_category or 'Other'
        stats[category] = stats.get(category, 0) + 1
    return stats

def _get_status_stats(artifacts):
    """Get artifact count by processing status"""
    stats = {}
    for artifact in artifacts:
        status = artifact.processing_status
        stats[status] = stats.get(status, 0) + 1
    return stats

def _get_artifacts_by_keywords(artifacts, keywords):
    """Filter artifacts by filename keywords"""
    filtered = []
    for artifact in artifacts:
        filename_lower = artifact.filename.lower()
        if any(keyword in filename_lower for keyword in keywords):
            filtered.append(artifact)
    return filtered