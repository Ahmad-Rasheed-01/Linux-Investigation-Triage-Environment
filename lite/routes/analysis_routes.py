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
                'User Accounts': 'user-accounts',
                'Login History': 'login-history',
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
            # Get comprehensive case summary data
            summary_data = _generate_case_summary(case, json_parser)
            return jsonify({
                'success': True,
                'data': summary_data
            })
        
        elif section == 'overview-artifacts':
            # Get system information from collection metadata
            system_info = _get_collection_metadata(case)
            return jsonify({
                'success': True,
                'data': system_info
            })
            
        elif section == 'artifacts':
            # Get system information from collection metadata
            system_info = _get_collection_metadata(case)
            return jsonify({
                'success': True,
                'data': system_info
            })
        
        elif section == 'hardware':
            system_artifacts = _get_artifacts_by_keywords(case.artifacts, 
                ['system', 'cpu', 'memory', 'uptime', 'kernel_version', 'locale'])
            system_data = {}
            
            for artifact in system_artifacts:
                data = json_parser.load_json_file(artifact.file_path)
                if data:
                    system_data[artifact.filename] = data
            
            # Add CPU information processing (handle case-insensitive matching)
            cpu_artifacts = _get_artifacts_by_keywords(case.artifacts, ['cpuinformation'])
            for artifact in cpu_artifacts:
                data = json_parser.load_json_file(artifact.file_path)
                if data:
                    system_data[artifact.filename] = data
            
            return jsonify({
                'success': True,
                'data': system_data
            })
        
        elif section == 'environment':
            # Get environment variables artifacts
            env_artifacts = _get_artifacts_by_keywords(case.artifacts, 
                ['environment', 'environmentvariables', 'env'])
            env_data = {}
            
            for artifact in env_artifacts:
                data = json_parser.load_json_file(artifact.file_path)
                if data:
                    env_data[artifact.filename] = data
            
            return jsonify({
                'success': True,
                'data': env_data
            })
        
        elif section == 'user-accounts':
            user_artifacts = _get_artifacts_by_keywords(case.artifacts, 
                ['user', 'account', 'group', 'password'])
            user_data = {}
            
            # Load all user-related artifacts
            for artifact in user_artifacts:
                data = json_parser.load_json_file(artifact.file_path)
                if data:
                    user_data[artifact.filename] = data
            
            # Enhance user data with password status information
            password_status_data = None
            for filename, data in user_data.items():
                if 'passwordstatus' in filename.lower():
                    password_status_data = data
                    
                    # Extract data from 'data' key if it exists
                    if isinstance(password_status_data, dict) and 'data' in password_status_data:
                        password_status_data = password_status_data['data']
                    
                    # Create password status map
                    password_status_map = {}
                    for entry in password_status_data:
                        if isinstance(entry, dict) and 'username' in entry:
                            password_status_map[entry['username']] = {
                                'rawStatusCode': entry.get('rawStatusCode', '-'),
                                'lastPasswordChange': entry.get('lastPasswordChange', '-'),
                                'minimumPasswordAge': entry.get('minimumPasswordAge', '-'),
                                'maximumPasswordAge': entry.get('maximumPasswordAge', '-'),
                                'passwordWarningPeriod': entry.get('passwordWarningPeriod', '-'),
                                'passwordInactivityPeriod': entry.get('passwordInactivityPeriod', '-'),
                                'accountExpirationDate': entry.get('accountExpirationDate', None)
                            }
                    
                    break
            
            # Enhance user data with password hash information
            password_hash_data = None
            for filename, data in user_data.items():
                if 'passwordinfo' in filename.lower():
                    password_hash_data = data
                    
                    # Extract data from 'data' key if it exists
                    if isinstance(password_hash_data, dict) and 'data' in password_hash_data:
                        password_hash_data = password_hash_data['data']
                    
                    # Create password hash map
                    password_hash_map = {}
                    for entry in password_hash_data:
                        if isinstance(entry, dict) and 'username' in entry:
                            password_hash = entry.get('passwordHash', 'N/A')
                            hash_type = _detect_hash_type(password_hash)
                            password_hash_map[entry['username']] = {
                                'passwordHash': password_hash,
                                'hashType': hash_type
                            }
                    
                    break
            
            # If we have password status data, merge it with user accounts
            if password_status_data:
                
                # Enhance user accounts data with password status
                for filename, data in user_data.items():
                    # Handle nested structure - extract data array if it exists
                    user_entries = data
                    if isinstance(data, dict) and 'data' in data:
                        user_entries = data['data']
                    
                    if isinstance(user_entries, list) and any('username' in item for item in user_entries if isinstance(item, dict)):
                        for user_entry in user_entries:
                            if isinstance(user_entry, dict) and 'username' in user_entry:
                                username = user_entry['username']
                                if username in password_status_map:
                                    user_entry['passwordStatus'] = password_status_map[username]
            
            # If we have password hash data, merge it with user accounts
            if password_hash_data:
                
                # Enhance user accounts data with password hash
                for filename, data in user_data.items():
                    # Handle nested structure - extract data array if it exists
                    user_entries = data
                    if isinstance(data, dict) and 'data' in data:
                        user_entries = data['data']
                    
                    if isinstance(user_entries, list) and any('username' in item for item in user_entries if isinstance(item, dict)):
                        for user_entry in user_entries:
                            if isinstance(user_entry, dict) and 'username' in user_entry:
                                username = user_entry['username']
                                if username in password_hash_map:
                                    user_entry['passwordHash'] = password_hash_map[username]['passwordHash']
                                    user_entry['hashType'] = password_hash_map[username]['hashType']
            
            return jsonify({
                'success': True,
                'data': user_data
            })
        
        elif section == 'network-connections':
            network_artifacts = _get_artifacts_by_keywords(case.artifacts, 
                ['network', 'connection', 'port', 'socket', 'interface'])
            network_data = {}
            
            for artifact in network_artifacts:
                data = json_parser.load_json_file(artifact.file_path)
                if data:
                    network_data[artifact.filename] = data
            
            return jsonify({
                'success': True,
                'data': network_data
            })
        
        elif section == 'processes-running':
            process_artifacts = _get_artifacts_by_keywords(case.artifacts, 
                ['process', 'processes', 'service', 'systemd'])
            process_data = {}
            
            for artifact in process_artifacts:
                data = json_parser.load_json_file(artifact.file_path)
                if data:
                    process_data[artifact.filename] = data
            
            return jsonify({
                'success': True,
                'data': process_data
            })
        
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
            
            return jsonify({
                'success': True,
                'data': log_data
            })
        
        elif section == 'collection-logs':
            # Parse collection log file
            collection_log_data = _parse_collection_logs(case)
            if not collection_log_data.get('success', True):
                return jsonify({
                    'success': False,
                    'message': collection_log_data.get('message', 'Failed to load collection log data'),
                    'data': None
                })
            else:
                return jsonify({
                    'success': True,
                    'data': collection_log_data
                })
        
        elif section == 'login-history':
            # Get login history artifacts
            login_artifacts = _get_artifacts_by_keywords(case.artifacts, 
                ['wtmp', 'utmp', 'lastlog', 'auth'])
            login_data = {}
            
            for artifact in login_artifacts:
                data = json_parser.load_json_file(artifact.file_path)
                if data:
                    # Process different log types
                    if 'wtmp' in artifact.filename.lower():
                        login_data['wtmp_logs'] = data
                    elif 'utmp' in artifact.filename.lower():
                        login_data['utmp_logs'] = data
                    elif 'lastlog' in artifact.filename.lower():
                        login_data['lastlog_logs'] = data
                    elif 'auth' in artifact.filename.lower():
                        # Limit auth logs for performance (they can be very large)
                        if isinstance(data, list) and len(data) > 2000:
                            data = data[:2000]  # Show first 2000 entries
                        login_data['auth_logs'] = data
            
            return jsonify({
                'success': True,
                'data': login_data
            })
        
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

def _generate_case_summary(case, json_parser):
    """Generate comprehensive case summary with key insights"""
    artifacts = case.artifacts
    
    # Basic statistics
    total_artifacts = len(artifacts)
    total_size_gb = round(case.total_size_mb / 1024, 2) if case.total_size_mb else 0
    categories = _get_category_stats(artifacts)
    status_distribution = _get_status_stats(artifacts)
    
    # Key insights and findings
    insights = _analyze_case_insights(artifacts, json_parser)
    
    # Security indicators
    security_findings = _analyze_security_indicators(artifacts, json_parser)
    
    # System overview
    system_overview = _get_system_overview(artifacts, json_parser)
    
    # Investigation timeline
    timeline_data = _generate_investigation_timeline(case, artifacts)
    
    return {
        'case_info': case.to_dict(),
        'statistics': {
            'total_artifacts': total_artifacts,
            'total_size_gb': total_size_gb,
            'categories': categories,
            'status_distribution': status_distribution,
            'processed_count': status_distribution.get('completed', 0),
            'processing_count': status_distribution.get('processing', 0),
            'pending_count': status_distribution.get('pending', 0)
        },
        'key_insights': insights,
        'security_findings': security_findings,
        'system_overview': system_overview,
        'timeline': timeline_data
    }

def _analyze_case_insights(artifacts, json_parser):
    """Analyze artifacts to extract key investigation insights"""
    insights = {
        'critical_findings': [],
        'user_activity': {},
        'network_activity': {},
        'process_analysis': {},
        'file_system_changes': []
    }
    
    # Analyze user artifacts
    user_artifacts = _get_artifacts_by_keywords(artifacts, ['user', 'account', 'passwd', 'shadow'])
    if user_artifacts:
        insights['user_activity']['total_users'] = len(user_artifacts)
        insights['user_activity']['privileged_users'] = _count_privileged_users(user_artifacts, json_parser)
    
    # Analyze network artifacts
    network_artifacts = _get_artifacts_by_keywords(artifacts, ['network', 'netstat', 'ss', 'connection'])
    if network_artifacts:
        insights['network_activity']['active_connections'] = len(network_artifacts)
        insights['network_activity']['suspicious_ports'] = _find_suspicious_ports(network_artifacts, json_parser)
    
    # Analyze process artifacts
    process_artifacts = _get_artifacts_by_keywords(artifacts, ['process', 'ps', 'systemd', 'service'])
    if process_artifacts:
        insights['process_analysis']['running_processes'] = len(process_artifacts)
        insights['process_analysis']['suspicious_processes'] = _find_suspicious_processes(process_artifacts, json_parser)
    
    return insights

def _analyze_security_indicators(artifacts, json_parser):
    """Analyze artifacts for security indicators and threats"""
    findings = {
        'threat_level': 'low',
        'indicators': [],
        'recommendations': []
    }
    
    # Check for authentication logs
    auth_artifacts = _get_artifacts_by_keywords(artifacts, ['auth', 'secure', 'wtmp', 'btmp'])
    if auth_artifacts:
        findings['indicators'].append({
            'type': 'authentication',
            'description': f'Found {len(auth_artifacts)} authentication-related artifacts',
            'severity': 'info'
        })
    
    # Check for system logs
    log_artifacts = _get_artifacts_by_keywords(artifacts, ['syslog', 'messages', 'kern', 'dmesg'])
    if log_artifacts:
        findings['indicators'].append({
            'type': 'system_logs',
            'description': f'Found {len(log_artifacts)} system log artifacts',
            'severity': 'info'
        })
    
    # Check for network configuration
    network_config = _get_artifacts_by_keywords(artifacts, ['interfaces', 'resolv', 'hosts', 'iptables'])
    if network_config:
        findings['indicators'].append({
            'type': 'network_config',
            'description': f'Found {len(network_config)} network configuration artifacts',
            'severity': 'info'
        })
    
    # Add general recommendations
    findings['recommendations'] = [
        'Review authentication logs for suspicious login attempts',
        'Analyze network connections for unauthorized access',
        'Check running processes for malicious activity',
        'Examine file system changes for unauthorized modifications'
    ]
    
    return findings

def _get_system_overview(artifacts, json_parser):
    """Extract system overview information"""
    overview = {
        'hostname': 'Unknown',
        'os_version': 'Unknown',
        'kernel_version': 'Unknown',
        'architecture': 'Unknown',
        'uptime': 'Unknown',
        'last_boot': 'Unknown'
    }
    
    # Try to extract system information from artifacts
    system_artifacts = _get_artifacts_by_keywords(artifacts, ['hostname', 'uname', 'version', 'uptime'])
    
    for artifact in system_artifacts:
        try:
            data = json_parser.load_json_file(artifact.file_path)
            if data and isinstance(data, dict):
                # Extract hostname
                if 'hostname' in artifact.filename.lower() and 'output' in data:
                    overview['hostname'] = data['output'].strip()
                
                # Extract OS version
                elif 'version' in artifact.filename.lower() and 'output' in data:
                    overview['os_version'] = data['output'].strip()
                
                # Extract kernel version
                elif 'uname' in artifact.filename.lower() and 'output' in data:
                    overview['kernel_version'] = data['output'].strip()
                
                # Extract uptime
                elif 'uptime' in artifact.filename.lower() and 'output' in data:
                    overview['uptime'] = data['output'].strip()
        except Exception:
            continue
    
    return overview

def _generate_investigation_timeline(case, artifacts):
    """Generate investigation timeline based on case and artifact data"""
    timeline = []
    
    # Add case creation event
    timeline.append({
        'timestamp': case.creation_date.isoformat(),
        'event': 'Case Created',
        'description': f'Investigation case "{case.case_name}" was created',
        'type': 'case_event'
    })
    
    # Add artifact upload events
    for artifact in artifacts:
        if artifact.upload_timestamp:
            timeline.append({
                'timestamp': artifact.upload_timestamp.isoformat(),
                'event': 'Artifact Uploaded',
                'description': f'Artifact "{artifact.filename}" was uploaded',
                'type': 'artifact_event'
            })
    
    # Sort timeline by timestamp
    timeline.sort(key=lambda x: x['timestamp'])
    
    return timeline

def _count_privileged_users(user_artifacts, json_parser):
    """Count privileged users from user artifacts"""
    privileged_count = 0
    # This is a placeholder - implement based on actual data structure
    return privileged_count

def _find_suspicious_ports(network_artifacts, json_parser):
    """Find suspicious network ports"""
    suspicious_ports = []
    # This is a placeholder - implement based on actual data structure
    return suspicious_ports

def _find_suspicious_processes(process_artifacts, json_parser):
    """Find suspicious processes"""
    suspicious_processes = []
    # This is a placeholder - implement based on actual data structure
    return suspicious_processes

def _get_collection_metadata(case):
    """Extract system information from collection metadata JSON file and include artifact information"""
    import glob
    
    # Look for collection metadata file in the case directory
    case_dir = os.path.join('cases', case.case_id)
    metadata_pattern = os.path.join(case_dir, 'collection_metadata_*.json')
    metadata_files = glob.glob(metadata_pattern)
    
    # Get artifact statistics and individual files
    artifacts = case.artifacts
    artifact_stats = {
        'total_count': len(artifacts),
        'total_size_mb': sum(artifact.file_size_mb for artifact in artifacts if artifact.file_size_mb),
        'by_category': _get_category_stats(artifacts),
        'by_status': _get_status_stats(artifacts),
        'latest_upload': max([artifact.upload_timestamp for artifact in artifacts], default=None),
        'file_types': {},
        'files': [artifact.to_dict() for artifact in artifacts]  # Include individual files
    }
    
    # Calculate file type distribution
    for artifact in artifacts:
        file_ext = os.path.splitext(artifact.filename)[1].lower() or 'no extension'
        artifact_stats['file_types'][file_ext] = artifact_stats['file_types'].get(file_ext, 0) + 1
    
    if not metadata_files:
        return {
            'error': 'Collection metadata file not found',
            'system_info': {},
            'artifact_info': artifact_stats
        }
    
    try:
        # Read the first metadata file found
        metadata_file = metadata_files[0]
        with open(metadata_file, 'r', encoding='utf-8') as f:
            metadata = json.load(f)
        
        # Extract system information
        system_info = {
            'collection_info': {
                'timestamp': metadata.get('timestamp', 'Unknown'),
                'hostname': metadata.get('hostname', 'Unknown'),
                'version': metadata.get('version', 'Unknown'),
                'versionSEA': metadata.get('versionSEA', 'Unknown'),
                'collection_directory': metadata.get('collection_directory', 'Unknown'),
                'output_format': metadata.get('output_format', 'Unknown')
            },
            'platform_info': metadata.get('platform', {}),
            'timezone_info': metadata.get('timezone', {}),
            'locale_info': metadata.get('locale', {})
        }
        
        return {
            'success': True,
            'system_info': system_info,
            'artifact_info': artifact_stats,
            'metadata_file': os.path.basename(metadata_file)
        }
        
    except Exception as e:
        return {
            'error': f'Failed to read collection metadata: {str(e)}',
            'system_info': {},
            'artifact_info': artifact_stats
        }

def _parse_collection_logs(case):
    """Parse collection log file and return structured data"""
    import glob
    import re
    from datetime import datetime
    
    # Look for collection log file in the case directory
    case_dir = os.path.join('cases', case.case_id)
    log_pattern = os.path.join(case_dir, '*_*.log')
    log_files = glob.glob(log_pattern)
    
    if not log_files:
        return {
            'error': 'Collection log file not found',
            'logs': [],
            'statistics': {}
        }
    
    try:
        # Read the first log file found
        log_file = log_files[0]
        logs = []
        statistics = {
            'total_entries': 0,
            'info_count': 0,
            'debug_count': 0,
            'warning_count': 0,
            'error_count': 0,
            'other_count': 0,
            'components': set()
        }
        
        # Regular expression to parse log entries
        # Format: YYYY-MM-DD HH:MM:SS,mmm - component - level - message
        log_pattern = re.compile(r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}) - (\w+) - (\w+) - (.*)$')
        
        with open(log_file, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                    
                match = log_pattern.match(line)
                if match:
                    timestamp_str, component, level, message = match.groups()
                    
                    # Parse timestamp
                    try:
                        timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S,%f')
                        formatted_timestamp = timestamp.strftime('%Y-%m-%d %H:%M:%S')
                    except ValueError:
                        formatted_timestamp = timestamp_str
                    
                    log_entry = {
                        'id': line_num,
                        'timestamp': formatted_timestamp,
                        'level': level,
                        'component': component,
                        'message': message,
                        'raw_line': line
                    }
                    
                    logs.append(log_entry)
                    
                    # Update statistics
                    statistics['total_entries'] += 1
                    
                    # Safely update level counts
                    level_key = f'{level.lower()}_count'
                    if level_key in statistics:
                        statistics[level_key] += 1
                    else:
                        # Handle unknown log levels
                        if 'other_count' not in statistics:
                            statistics['other_count'] = 0
                        statistics['other_count'] += 1
                    
                    statistics['components'].add(component)
                else:
                    # Handle lines that don't match the pattern
                    log_entry = {
                        'id': line_num,
                        'timestamp': 'Unknown',
                        'level': 'UNKNOWN',
                        'component': 'Unknown',
                        'message': line,
                        'raw_line': line
                    }
                    logs.append(log_entry)
                    statistics['total_entries'] += 1
        
        # Convert set to list for JSON serialization
        statistics['components'] = list(statistics['components'])
        
        return {
            'success': True,
            'logs': logs,
            'statistics': statistics,
            'log_file': os.path.basename(log_file)
        }
        
    except Exception as e:
        return {
            'success': False,
            'message': f'Failed to parse collection logs: {str(e)}',
            'logs': [],
            'statistics': {}
        }

def _detect_hash_type(password_hash):
    """Detect the type of password hash based on its format"""
    if not password_hash or password_hash == 'N/A' or password_hash == '*' or password_hash == '!':
        return 'No Password/Locked'
    
    # Common hash type patterns
    if password_hash.startswith('$1$'):
        return 'MD5'
    elif password_hash.startswith('$2a$') or password_hash.startswith('$2b$') or password_hash.startswith('$2x$') or password_hash.startswith('$2y$'):
        return 'Blowfish/bcrypt'
    elif password_hash.startswith('$5$'):
        return 'SHA-256'
    elif password_hash.startswith('$6$'):
        return 'SHA-512'
    elif password_hash.startswith('$y$'):
        return 'yescrypt'
    elif password_hash.startswith('$7$'):
        return 'scrypt'
    elif password_hash.startswith('$argon2'):
        return 'Argon2'
    elif password_hash.startswith('$pbkdf2'):
        return 'PBKDF2'
    elif len(password_hash) == 13 and not password_hash.startswith('$'):
        return 'DES (Traditional)'
    elif len(password_hash) == 34 and password_hash.startswith('$'):
        return 'Extended DES'
    elif password_hash.startswith('{'):
        return 'LDAP Format'
    else:
        return 'Unknown/Other'