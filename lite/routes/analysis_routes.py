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
                'Process Hunting': 'process-hunting',
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
                'Sockets': 'network-sockets',
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
        
        elif section == 'network-interfaces':
            # Load specific network interfaces JSON file
            if case.folder_path:
                # Construct absolute path from relative folder_path
                base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                network_interfaces_file = os.path.join(
                    base_dir, 
                    case.folder_path, 
                    'networkInterfaces.json'
                )
            else:
                network_interfaces_file = None
            
            network_data = {}
            file_found = False
            
            if network_interfaces_file and os.path.exists(network_interfaces_file):
                data = json_parser.load_json_file(network_interfaces_file)
                if data:
                    network_data['networkInterfaces.json'] = data
                    file_found = True
            
            # Also check for other network interface artifacts as fallback
            interface_artifacts = _get_artifacts_by_keywords(case.artifacts, 
                ['interface', 'networkinterface', 'ifconfig', 'ip_addr', 'ip_link'])
            
            for artifact in interface_artifacts:
                data = json_parser.load_json_file(artifact.file_path)
                if data:
                    network_data[artifact.filename] = data
                    file_found = True
            
            # If no network interface data found, provide a helpful message
            if not file_found:
                return jsonify({
                    'success': False,
                    'message': 'No network interface data found. The networkInterfaces.json file was not found in the case directory. Please ensure network interface artifacts have been collected and are available in the case folder.',
                    'data': None
                })
            
            return jsonify({
                'success': True,
                'data': network_data
            })
        
        elif section == 'network-routing':
            # Load specific routing table JSON file
            if case.folder_path:
                # Use absolute folder_path directly (it's already absolute from case creation)
                routing_table_file = os.path.join(
                    case.folder_path, 
                    'routingTableRaw.json'
                )
            else:
                routing_table_file = None
            
            network_data = {}
            file_found = False
            
            # Load routing table data
            if routing_table_file and os.path.exists(routing_table_file):
                data = json_parser.load_json_file(routing_table_file)
                if data:
                    network_data['routingTableRaw.json'] = data
                    file_found = True
            
            # Also check for other routing table artifacts as fallback
            routing_artifacts = _get_artifacts_by_keywords(case.artifacts, 
                ['route', 'routing', 'ip_route'])
            
            for artifact in routing_artifacts:
                data = json_parser.load_json_file(artifact.file_path)
                if data:
                    network_data[artifact.filename] = data
                    file_found = True
            
            # If no routing data found, provide a helpful message
            if not file_found:
                return jsonify({
                    'success': False,
                    'message': 'No routing table data found. The routingTableRaw.json file was not found in the case directory. Please ensure routing table artifacts have been collected and are available in the case folder.',
                    'data': None
                })
            
            # Parse routing table data for frontend
            routing_table = []
            try:
                for filename, data in network_data.items():
                    if 'stdout' in data and data['stdout']:
                        # Parse the stdout content which contains the routing table
                        lines = data['stdout'].strip().split('\n')
                        # Skip the header lines
                        for line in lines[2:]:  # Skip 'Kernel IP routing table' and header row
                            if line.strip():
                                parts = line.split()
                                if len(parts) >= 8:
                                    routing_table.append({
                                        'destination': parts[0],
                                        'gateway': parts[1],
                                        'genmask': parts[2],
                                        'flags': parts[3],
                                        'metric': parts[4],
                                        'ref': parts[5],
                                        'use': parts[6],
                                        'iface': parts[7]
                                    })
            except Exception as e:
                print(f"Error parsing routing table data: {str(e)}")
                return jsonify({
                    'success': False,
                    'message': f'Error parsing routing table data: {str(e)}',
                    'data': None
                })
            
            return jsonify({
                'success': True,
                'data': {
                    'routing_table': routing_table,
                    'raw_data': network_data
                }
            })
        
        elif section == 'network-connections':
            # Load specific network connections JSON file
            if case.folder_path:
                # Construct absolute path from relative folder_path
                base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                network_connections_file = os.path.join(
                    base_dir, 
                    case.folder_path, 
                    'networkConnections.json'
                )
                # Also load connection tracking data
                connection_tracking_file = os.path.join(
                    base_dir, 
                    case.folder_path, 
                    'connectionTracking.json'
                )
            else:
                network_connections_file = None
                connection_tracking_file = None
            
            network_data = {}
            file_found = False
            
            if network_connections_file and os.path.exists(network_connections_file):
                data = json_parser.load_json_file(network_connections_file)
                if data:
                    network_data['networkConnections.json'] = data
                    file_found = True
            
            # Load connection tracking data
            if connection_tracking_file and os.path.exists(connection_tracking_file):
                data = json_parser.load_json_file(connection_tracking_file)
                if data:
                    network_data['connectionTracking.json'] = data
                    file_found = True
            
            # Also check for other network artifacts as fallback
            network_artifacts = _get_artifacts_by_keywords(case.artifacts, 
                ['network', 'connection', 'port', 'socket', 'interface'])
            
            for artifact in network_artifacts:
                data = json_parser.load_json_file(artifact.file_path)
                if data:
                    network_data[artifact.filename] = data
                    file_found = True
            
            # If no network data found, provide a helpful message
            if not file_found:
                return jsonify({
                    'success': False,
                    'message': 'No network connection data found. The networkConnections.json file was not found in the case directory. Please ensure network connection artifacts have been collected and are available in the case folder.',
                    'data': None
                })
            
            return jsonify({
                'success': True,
                'data': network_data
            })
        
        elif section == 'network-ports':
            # Load specific open ports JSON file
            if case.folder_path:
                # Construct absolute path from relative folder_path
                # Go up two levels from lite/routes/ to get to project root
                base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
                open_ports_file = os.path.join(
                    base_dir, 
                    case.folder_path, 
                    'openPorts.json'
                )
            else:
                open_ports_file = None
            
            ports_data = {}
            file_found = False
            
            if open_ports_file and os.path.exists(open_ports_file):
                data = json_parser.load_json_file(open_ports_file)
                if data:
                    ports_data['openPorts.json'] = data
                    file_found = True
            
            # Also check for other port-related artifacts as fallback
            port_artifacts = _get_artifacts_by_keywords(case.artifacts, 
                ['port', 'openports', 'netstat', 'ss', 'lsof'])
            
            for artifact in port_artifacts:
                data = json_parser.load_json_file(artifact.file_path)
                if data:
                    ports_data[artifact.filename] = data
                    file_found = True
            
            # If no open ports data found, provide a helpful message
            if not file_found:
                return jsonify({
                    'success': False,
                    'message': 'No open ports data found. The openPorts.json file was not found in the case directory. Please ensure open ports artifacts have been collected and are available in the case folder.',
                    'data': None
                })
            
            return jsonify({
                'success': True,
                'data': ports_data
            })
        
        elif section == 'network-sockets':
            # Load specific socket statistics JSON file
            if case.folder_path:
                # Construct absolute path from relative folder_path
                # Go up two levels from lite/routes/ to get to project root
                base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
                socket_stats_file = os.path.join(
                    base_dir, 
                    case.folder_path, 
                    'socketStatistics.json'
                )
            else:
                socket_stats_file = None
            
            sockets_data = {}
            file_found = False
            
            if socket_stats_file and os.path.exists(socket_stats_file):
                data = json_parser.load_json_file(socket_stats_file)
                if data:
                    sockets_data['socketStatistics.json'] = data
                    file_found = True
            
            # Also check for other socket-related artifacts as fallback
            socket_artifacts = _get_artifacts_by_keywords(case.artifacts, 
                ['socket', 'socketstatistics', 'ss', 'netstat'])
            
            for artifact in socket_artifacts:
                data = json_parser.load_json_file(artifact.file_path)
                if data:
                    sockets_data[artifact.filename] = data
                    file_found = True
            
            # If no socket data found, provide a helpful message
            if not file_found:
                return jsonify({
                    'success': False,
                    'message': 'No socket statistics data found. The socketStatistics.json file was not found in the case directory. Please ensure socket artifacts have been collected and are available in the case folder.',
                    'data': None
                })
            
            return jsonify({
                'success': True,
                'data': sockets_data
            })
        
        elif section == 'processes-running':
            # Load process data directly from case directory
            case_dir = os.path.join('cases', case.case_id)
            print(f"DEBUG: Looking for processes in case directory: {case_dir}")
            
            process_data = {}
            file_found = False
            
            # Check for processes.json file directly in case directory
            processes_file = os.path.join(case_dir, 'processes.json')
            print(f"DEBUG: Checking for processes file: {processes_file}")
            print(f"DEBUG: File exists: {os.path.exists(processes_file)}")
            
            if os.path.exists(processes_file):
                try:
                    print(f"DEBUG: Attempting to load processes.json")
                    data = json_parser.load_json_file(processes_file)
                    print(f"DEBUG: Loaded data type: {type(data)}, length: {len(data) if isinstance(data, (list, dict)) else 'N/A'}")
                    if data:
                        process_data['processes.json'] = data
                        file_found = True
                        print(f"DEBUG: Successfully loaded processes.json with {len(data) if isinstance(data, list) else 'dict'} items")
                except Exception as e:
                    print(f"ERROR loading processes.json: {e}")
            
            # Also check for other process-related files
            try:
                for filename in os.listdir(case_dir):
                    if any(keyword in filename.lower() for keyword in ['process', 'ps_', 'top_', 'htop']):
                        file_path = os.path.join(case_dir, filename)
                        if os.path.isfile(file_path) and filename.endswith('.json'):
                            try:
                                data = json_parser.load_json_file(file_path)
                                if data:
                                    process_data[filename] = data
                                    file_found = True
                            except Exception as e:
                                print(f"Error loading {filename}: {e}")
            except Exception as e:
                print(f"Error listing case directory: {e}")
            
            # Fallback to artifacts database if no files found directly
            if not file_found:
                process_artifacts = _get_artifacts_by_keywords(case.artifacts, 
                    ['process', 'processes', 'service', 'systemd'])
                
                for artifact in process_artifacts:
                    data = json_parser.load_json_file(artifact.file_path)
                    if data:
                        process_data[artifact.filename] = data
                        file_found = True
            
            # If no process data found, provide a helpful message
            if not file_found:
                return jsonify({
                    'success': False,
                    'message': 'No Process Data Available',
                    'description': 'No running processes data found in the uploaded artifacts.',
                    'expected': 'Expected Data: Upload artifacts containing process information (ps, top, htop output) to view running processes.',
                    'data': None
                })
            
            return jsonify({
                'success': True,
                'data': process_data
            })
        
        elif section == 'process-hunting':
            # Get process hunting artifacts
            hunting_artifacts = _get_artifacts_by_keywords(case.artifacts, 
                ['process_hunting_data', 'hunting', 'process_hunting'])
            hunting_data = {}
            
            for artifact in hunting_artifacts:
                data = json_parser.load_json_file(artifact.file_path)
                if data:
                    hunting_data[artifact.filename] = data
            
            return jsonify({
                'success': True,
                'data': hunting_data
            })
        

        elif section == 'services' or section == 'processes-services':
            # Get systemd services artifacts
            service_artifacts = _get_artifacts_by_keywords(case.artifacts, 
                ['systemdservices', 'services', 'systemd'])
            service_data = {}
            
            for artifact in service_artifacts:
                data = json_parser.load_json_file(artifact.file_path)
                if data:
                    service_data[artifact.filename] = data
            
            return jsonify({
                'success': True,
                'data': service_data
            })
        
        elif section == 'logs-system':
            try:
                log_artifacts = _get_artifacts_by_keywords(case.artifacts, 
                    ['syslog'])
                log_data = {}
                
                for artifact in log_artifacts:
                    try:
                        data = json_parser.load_json_file(artifact.file_path)
                        if data:
                            # Process logs from JSON structure
                            if isinstance(data, dict) and 'entries' in data:
                                # Limit log entries for performance
                                if len(data['entries']) > 1000:
                                    data['entries'] = data['entries'][:1000]  # Show first 1000 entries
                                log_data[artifact.filename] = data
                            # Handle list format (backward compatibility)
                            elif isinstance(data, list):
                                # Limit log entries for performance
                                if len(data) > 1000:
                                    data = data[:1000]  # Show first 1000 entries
                                log_data[artifact.filename] = data
                            # Handle other dict formats
                            elif isinstance(data, dict):
                                log_data[artifact.filename] = data
                    except Exception as file_error:
                        print(f"Error processing log file {artifact.filename}: {str(file_error)}")
                        continue
                
                return jsonify({
                    'success': True,
                    'data': log_data
                })
            except Exception as logs_error:
                print(f"Error in logs-system section: {str(logs_error)}")
                return jsonify({
                    'success': False,
                    'error': f'Error loading system logs: {str(logs_error)}'
                }), 500
            
        elif section == 'auth-logs':
            # Get authentication log artifacts
            auth_artifacts = _get_artifacts_by_keywords(case.artifacts, ['auth'])
            login_data = {'auth_logs': {'entries': []}}
            
            for artifact in auth_artifacts:
                data = json_parser.load_json_file(artifact.file_path)
                if data:
                    # Process auth logs from JSON structure
                    if isinstance(data, dict) and 'entries' in data:
                        # Limit auth logs for performance (they can be very large)
                        if len(data['entries']) > 2000:
                            data['entries'] = data['entries'][:2000]  # Show first 2000 entries
                        login_data['auth_logs'] = data
                        break  # Use the first valid auth log file found
                    # Handle list format (backward compatibility)
                    elif isinstance(data, list) and len(data) > 0:
                        # Limit auth logs for performance (they can be very large)
                        if len(data) > 2000:
                            data = data[:2000]  # Show first 2000 entries
                        login_data['auth_logs'] = {'entries': data}
                        break  # Use the first valid auth log file found
            
            return jsonify({
                'success': True,
                'data': login_data
            })
        
        elif section == 'logs-audit':
            # Get audit log artifacts
            audit_artifacts = _get_artifacts_by_keywords(case.artifacts, ['audit'])
            audit_data = {}
            
            for artifact in audit_artifacts:
                try:
                    data = json_parser.load_json_file(artifact.file_path)
                    if data:
                        # Process audit logs from JSON structure
                        if isinstance(data, dict) and 'entries' in data:
                            # Limit audit logs for performance
                            if len(data['entries']) > 1000:
                                data['entries'] = data['entries'][:1000]  # Show first 1000 entries
                            audit_data[artifact.filename] = data
                        # Handle list format (backward compatibility)
                        elif isinstance(data, list):
                            # Limit audit logs for performance
                            if len(data) > 1000:
                                data = data[:1000]  # Show first 1000 entries
                            audit_data[artifact.filename] = data
                        # Handle other dict formats
                        elif isinstance(data, dict):
                            audit_data[artifact.filename] = data
                except Exception as file_error:
                    print(f"Error processing audit file {artifact.filename}: {str(file_error)}")
                    continue
            
            return jsonify({
                'success': True,
                'data': audit_data
            })
        
        elif section == 'collection-logs':
            # Parse collection log file
            collection_log_data = _parse_collection_logs(case)
            if 'error' in collection_log_data:
                return jsonify({
                    'success': False,
                    'message': collection_log_data.get('error', 'Failed to load collection log data'),
                    'data': None
                })
            else:
                return jsonify({
                    'success': True,
                    'data': collection_log_data
                })
        
        elif section == 'logs-kernel':
            try:
                # First try to load the specific kernel log file
                case_dir = os.path.join('cases', case.case_id)
                kernel_file_path = os.path.join(case_dir, 'kern.json')
                
                kernel_data = {}
                
                if os.path.exists(kernel_file_path):
                    try:
                        data = json_parser.load_json_file(kernel_file_path)
                        if data:
                            # Process kernel logs from JSON structure
                            if isinstance(data, dict) and 'entries' in data:
                                # Limit kernel log entries for performance
                                if len(data['entries']) > 1500:
                                    data['entries'] = data['entries'][:1500]  # Show first 1500 entries
                                kernel_data['kern.json'] = data
                            elif isinstance(data, list):
                                # Limit kernel log entries for performance
                                if len(data) > 1500:
                                    data = data[:1500]  # Show first 1500 entries
                                kernel_data['kern.json'] = {'entries': data}
                            elif isinstance(data, dict):
                                kernel_data['kern.json'] = data
                    except Exception as file_error:
                        print(f"Error processing kernel file kern.json: {str(file_error)}")
                
                # If no specific file found, search for other kernel log artifacts
                if not kernel_data:
                    kernel_artifacts = _get_artifacts_by_keywords(case.artifacts, ['kern', 'kernel'])
                    
                    for artifact in kernel_artifacts:
                        try:
                            data = json_parser.load_json_file(artifact.file_path)
                            if data:
                                # Process kernel logs from JSON structure
                                if isinstance(data, dict) and 'entries' in data:
                                    # Limit kernel log entries for performance
                                    if len(data['entries']) > 1500:
                                        data['entries'] = data['entries'][:1500]  # Show first 1500 entries
                                    kernel_data[artifact.filename] = data
                                elif isinstance(data, list):
                                    # Limit kernel log entries for performance
                                    if len(data) > 1500:
                                        data = data[:1500]  # Show first 1500 entries
                                    kernel_data[artifact.filename] = {'entries': data}
                                elif isinstance(data, dict):
                                    kernel_data[artifact.filename] = data
                        except Exception as file_error:
                            print(f"Error processing kernel file {artifact.filename}: {str(file_error)}")
                            continue
                
                return jsonify({
                    'success': True,
                    'data': kernel_data
                })
            except Exception as kernel_error:
                print(f"Error in logs-kernel section: {str(kernel_error)}")
                return jsonify({
                    'success': False,
                    'error': f'Error loading kernel logs: {str(kernel_error)}'
                }), 500
            
        elif section == 'application-logs':
            try:
                # Load application log files
                case_dir = os.path.join('cases', case.case_id)
                app_data = {}
                
                # Look for common application log files
                app_log_files = ['application.json', 'app.json', 'applications.json', 'app_logs.json', 'syslog.json']
                
                for log_file in app_log_files:
                    app_file_path = os.path.join(case_dir, log_file)
                    if os.path.exists(app_file_path):
                        try:
                            data = json_parser.load_json_file(app_file_path)
                            if data:
                                # Process application logs from JSON structure
                                if isinstance(data, dict) and 'entries' in data:
                                    # Limit application log entries for performance
                                    if len(data['entries']) > 1000:
                                        data['entries'] = data['entries'][:1000]  # Show first 1000 entries
                                    app_data[log_file] = data
                                elif isinstance(data, list):
                                    # Limit application log entries for performance
                                    if len(data) > 1000:
                                        data = data[:1000]  # Show first 1000 entries
                                    app_data[log_file] = {'entries': data}
                                elif isinstance(data, dict):
                                    app_data[log_file] = data
                        except Exception as file_error:
                            print(f"Error processing application log file {log_file}: {str(file_error)}")
                            continue
                
                # If no specific files found, search for application-related artifacts
                if not app_data:
                    app_artifacts = _get_artifacts_by_keywords(case.artifacts, ['application', 'app', 'service', 'syslog'])
                    
                    for artifact in app_artifacts:
                        try:
                            data = json_parser.load_json_file(artifact.file_path)
                            if data:
                                # Process application logs from JSON structure
                                if isinstance(data, dict) and 'entries' in data:
                                    # Limit application log entries for performance
                                    if len(data['entries']) > 1000:
                                        data['entries'] = data['entries'][:1000]  # Show first 1000 entries
                                    app_data[artifact.filename] = data
                                elif isinstance(data, list):
                                    # Limit application log entries for performance
                                    if len(data) > 1000:
                                        data = data[:1000]  # Show first 1000 entries
                                    app_data[artifact.filename] = {'entries': data}
                                elif isinstance(data, dict):
                                    app_data[artifact.filename] = data
                        except Exception as file_error:
                            print(f"Error processing application file {artifact.filename}: {str(file_error)}")
                            continue
                
                return jsonify({
                    'success': True,
                    'data': app_data
                })
            except Exception as app_error:
                print(f"Error in application-logs section: {str(app_error)}")
                return jsonify({
                    'success': False,
                    'error': f'Error loading application logs: {str(app_error)}'
                }), 500
            
        elif section == 'collection-logs':
            # Parse collection log file
            collection_log_data = _parse_collection_logs(case)
            if 'error' in collection_log_data:
                return jsonify({
                    'success': False,
                    'message': collection_log_data.get('error', 'Failed to load collection log data'),
                    'data': None
                })
            else:
                return jsonify({
                    'success': True,
                    'data': collection_log_data
                })
        
        elif section == 'ufw-logs':
            try:
                # Load the specific UFW log file
                case_dir = os.path.join('cases', case.case_id)
                ufw_file_path = os.path.join(case_dir, 'ufw.json')
                
                ufw_data = {}
                
                if os.path.exists(ufw_file_path):
                    try:
                        data = json_parser.load_json_file(ufw_file_path)
                        if data:
                            # Process UFW logs from JSON structure
                            if isinstance(data, dict) and 'entries' in data:
                                # Limit UFW log entries for performance
                                if len(data['entries']) > 1000:
                                    data['entries'] = data['entries'][:1000]  # Show first 1000 entries
                                ufw_data['ufw.json'] = data
                            elif isinstance(data, list):
                                # Limit UFW log entries for performance
                                if len(data) > 1000:
                                    data = data[:1000]  # Show first 1000 entries
                                ufw_data['ufw.json'] = {'entries': data}
                            elif isinstance(data, dict):
                                ufw_data['ufw.json'] = data
                    except Exception as file_error:
                        print(f"Error processing UFW file ufw.json: {str(file_error)}")
                        return jsonify({
                            'success': False,
                            'error': f'Error loading UFW log file: {str(file_error)}'
                        }), 500
                else:
                    # If specific file not found, search for other UFW artifacts
                    ufw_artifacts = _get_artifacts_by_keywords(case.artifacts, ['ufw'])
                    
                    for artifact in ufw_artifacts:
                        try:
                            data = json_parser.load_json_file(artifact.file_path)
                            if data:
                                # Process UFW logs from JSON structure
                                if isinstance(data, dict) and 'entries' in data:
                                    # Limit UFW log entries for performance
                                    if len(data['entries']) > 1000:
                                        data['entries'] = data['entries'][:1000]  # Show first 1000 entries
                                    ufw_data[artifact.filename] = data
                                elif isinstance(data, list):
                                    # Limit UFW log entries for performance
                                    if len(data) > 1000:
                                        data = data[:1000]  # Show first 1000 entries
                                    ufw_data[artifact.filename] = {'entries': data}
                                elif isinstance(data, dict):
                                    ufw_data[artifact.filename] = data
                        except Exception as file_error:
                            print(f"Error processing UFW file {artifact.filename}: {str(file_error)}")
                            continue
                
                return jsonify({
                    'success': True,
                    'data': ufw_data
                })
            except Exception as ufw_error:
                print(f"Error in ufw-logs section: {str(ufw_error)}")
                return jsonify({
                    'success': False,
                    'error': f'Error loading UFW logs: {str(ufw_error)}'
                }), 500
        
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
                        # Process auth logs from JSON structure
                        if isinstance(data, dict) and 'entries' in data:
                            # Limit auth logs for performance (they can be very large)
                            if len(data['entries']) > 2000:
                                data['entries'] = data['entries'][:2000]  # Show first 2000 entries
                            login_data['auth_logs'] = data
                        # Handle list format (backward compatibility)
                        elif isinstance(data, list) and len(data) > 0:
                            # Limit auth logs for performance (they can be very large)
                            if len(data) > 2000:
                                data = data[:2000]  # Show first 2000 entries
                            login_data['auth_logs'] = {'entries': data}
                        else:
                            # Empty or invalid format
                            login_data['auth_logs'] = {'entries': []}
            
            return jsonify({
                'success': True,
                'data': login_data
            })
        
        elif section == 'triggered-tasks':
            # Load triggered tasks data
            import glob
            case_dir = os.path.join('cases', case.case_id)
            triggered_tasks_files = glob.glob(os.path.join(case_dir, 'triggered_tasks_data.json'))
            
            if triggered_tasks_files:
                # Get the most recent file
                latest_file = max(triggered_tasks_files, key=os.path.getctime)
                
                try:
                    with open(latest_file, 'r') as f:
                        triggered_tasks_data = json.load(f)
                    
                    return jsonify({
                        'success': True,
                        'data': triggered_tasks_data,
                        'total': len(triggered_tasks_data) if isinstance(triggered_tasks_data, list) else 0,
                        'file': os.path.basename(latest_file)
                    })
                except Exception as e:
                    return jsonify({'error': f'Error reading triggered tasks data: {str(e)}'}), 500
            else:
                return jsonify({'error': 'Triggered tasks data not found'}), 404
        
        elif section == 'software-installed':
            # Load installed packages data
            import glob
            case_dir = os.path.join('cases', case.case_id)
            
            # Look for dpkg packages file
            dpkg_files = glob.glob(os.path.join(case_dir, 'dpkgPackages.json'))
            
            if dpkg_files:
                # Get the most recent file
                latest_file = max(dpkg_files, key=os.path.getctime)
                
                try:
                    with open(latest_file, 'r', encoding='utf-8') as f:
                        packages_data = json.load(f)
                    
                    # Process the packages data
                    packages_list = []
                    if isinstance(packages_data, dict) and 'packages' in packages_data:
                        packages_list = packages_data['packages']
                    elif isinstance(packages_data, list):
                        packages_list = packages_data
                    
                    if packages_list:
                        processed_packages = []
                        for pkg in packages_list:
                            if isinstance(pkg, dict):
                                # Handle nested status object
                                status_info = pkg.get('status', {})
                                if isinstance(status_info, dict):
                                    status = status_info.get('package_status', 'N/A')
                                    priority = 'normal'  # Default priority since it's not in the status object
                                else:
                                    status = str(status_info) if status_info else 'N/A'
                                    priority = 'normal'
                                
                                processed_packages.append({
                                    'name': pkg.get('name', 'N/A'),
                                    'version': pkg.get('version', 'N/A'),
                                    'architecture': pkg.get('architecture', 'N/A'),
                                    'status': status,
                                    'priority': priority,
                                    'description': pkg.get('description', 'No description available')
                                })
                        
                        return jsonify({
                            'success': True,
                            'data': {
                                'packages': processed_packages,
                                'total': len(processed_packages),
                                'file': os.path.basename(latest_file)
                            }
                        })
                    else:
                        return jsonify({
                            'success': False,
                            'error': 'Invalid packages data format'
                        }), 500
                        
                except Exception as e:
                    return jsonify({
                        'success': False,
                        'error': f'Error reading packages data: {str(e)}'
                    }), 500
            else:
                return jsonify({
                    'success': False,
                    'error': 'Installed packages data not found'
                }), 404
        
        elif section == 'software-installations':
            # Load installation records data
            import glob
            case_dir = os.path.join('cases', case.case_id)
            
            # Look for installRecords files
            install_files = glob.glob(os.path.join(case_dir, 'installRecords.json'))
            
            if install_files:
                # Get the most recent file
                latest_file = max(install_files, key=os.path.getctime)
                
                try:
                    with open(latest_file, 'r', encoding='utf-8') as f:
                        install_data = json.load(f)
                    
                    # Process the installation data
                    if isinstance(install_data, list):
                        processed_installs = []
                        for install in install_data:
                            if isinstance(install, dict):
                                processed_installs.append({
                                    'timestamp': install.get('timestamp', 0),
                                    'action': install.get('action', 'unknown'),
                                    'package': install.get('package', 'unknown'),
                                    'package_name': install.get('package_name', 'unknown'),
                                    'architecture': install.get('architecture', 'unknown'),
                                    'version': install.get('version', 'unknown'),
                                    'source_file': install.get('source_file', 'unknown')
                                })
                        
                        return jsonify({
                            'success': True,
                            'data': {
                                'installations': processed_installs,
                                'total': len(processed_installs),
                                'file': os.path.basename(latest_file)
                            }
                        })
                    else:
                        return jsonify({
                            'success': False,
                            'error': 'Invalid installation data format'
                        }), 500
                        
                except Exception as e:
                    return jsonify({
                        'success': False,
                        'error': f'Error reading installation data: {str(e)}'
                    }), 500
            else:
                return jsonify({
                    'success': False,
                    'error': 'Installation records data not found'
                }), 404
        
        elif section == 'software-upgradations':
            # Load upgrade records data
            case_dir = os.path.join('cases', case.case_id)
            upgrade_files = [f for f in os.listdir(case_dir) if f.startswith('upgradeRecords') and f.endswith('.json')]
            
            if upgrade_files:
                # Get the most recent upgrade records file
                latest_file = os.path.join(case_dir, sorted(upgrade_files)[-1])
                
                try:
                    with open(latest_file, 'r', encoding='utf-8') as f:
                        upgrade_data = json.load(f)
                    
                    # Process the upgrade data
                    if isinstance(upgrade_data, list):
                        processed_upgrades = []
                        for upgrade in upgrade_data:
                            if isinstance(upgrade, dict):
                                processed_upgrades.append({
                                    'timestamp': upgrade.get('timestamp', 0),
                                    'action': upgrade.get('action', 'unknown'),
                                    'package': upgrade.get('package', 'unknown'),
                                    'package_name': upgrade.get('package_name', 'unknown'),
                                    'architecture': upgrade.get('architecture', 'unknown'),
                                    'old_version': upgrade.get('old_version', 'unknown'),
                                    'new_version': upgrade.get('new_version', 'unknown'),
                                    'source_file': upgrade.get('source_file', 'unknown')
                                })
                        
                        return jsonify({
                            'success': True,
                            'data': {
                                'upgradations': processed_upgrades,
                                'total': len(processed_upgrades),
                                'file': os.path.basename(latest_file)
                            }
                        })
                    else:
                        return jsonify({
                            'success': False,
                            'error': 'Invalid upgrade data format'
                        }), 500
                        
                except Exception as e:
                    return jsonify({
                        'success': False,
                        'error': f'Error reading upgrade data: {str(e)}'
                    }), 500
            else:
                return jsonify({
                    'success': False,
                    'error': 'Upgrade records data not found'
                }), 404
        
        elif section == 'software-removal':
            # Load removal records data
            case_dir = os.path.join('cases', case.case_id)
            removal_files = [f for f in os.listdir(case_dir) if f.startswith('removeRecords') and f.endswith('.json')]
            
            if removal_files:
                # Get the most recent removal records file
                latest_file = os.path.join(case_dir, sorted(removal_files)[-1])
                
                try:
                    with open(latest_file, 'r', encoding='utf-8') as f:
                        removal_data = json.load(f)
                    
                    # Process the removal data
                    if isinstance(removal_data, list):
                        processed_removals = []
                        for removal in removal_data:
                            if isinstance(removal, dict):
                                processed_removals.append({
                                    'timestamp': removal.get('timestamp', 0),
                                    'action': removal.get('action', 'unknown'),
                                    'package': removal.get('package', 'unknown'),
                                    'package_name': removal.get('package_name', 'unknown'),
                                    'architecture': removal.get('architecture', 'unknown'),
                                    'version': removal.get('version', 'unknown'),
                                    'source_file': removal.get('source_file', 'unknown')
                                })
                        
                        return jsonify({
                            'success': True,
                            'data': {
                                'removals': processed_removals,
                                'total': len(processed_removals),
                                'file': os.path.basename(latest_file)
                            }
                        })
                    else:
                        return jsonify({
                            'success': False,
                            'error': 'Invalid removal data format'
                        }), 500
                        
                except Exception as e:
                    return jsonify({
                        'success': False,
                        'error': f'Error reading removal data: {str(e)}'
                    }), 500
            else:
                return jsonify({
                    'success': False,
                    'error': 'Removal records data not found'
                }), 404
        
        elif section == 'firewall-config':
            # Load firewall rules data
            case_dir = os.path.join('cases', case.case_id)
            firewall_files = [f for f in os.listdir(case_dir) if f.startswith('firewallRules') and f.endswith('.json')]
            
            if firewall_files:
                # Get the most recent firewall rules file
                latest_file = os.path.join(case_dir, sorted(firewall_files)[-1])
                
                try:
                    with open(latest_file, 'r', encoding='utf-8') as f:
                        firewall_data = json.load(f)
                    
                    # Process the firewall data
                    if isinstance(firewall_data, dict):
                        return jsonify({
                            'success': True,
                            'data': {
                                'firewall_rules': firewall_data,
                                'file': os.path.basename(latest_file)
                            }
                        })
                    else:
                        return jsonify({
                            'success': False,
                            'error': 'Invalid firewall data format'
                        }), 500
                        
                except Exception as e:
                    return jsonify({
                        'success': False,
                        'error': f'Error reading firewall data: {str(e)}'
                    }), 500
            else:
                return jsonify({
                    'success': False,
                    'error': 'Firewall rules data not found'
                }), 404
        
        elif section == 'nfs':
            # Load NFS exports and mounts data
            case_dir = os.path.join('cases', case.case_id)
            
            # Find NFS exports file
            exports_files = [f for f in os.listdir(case_dir) if f.startswith('nfsExports') and f.endswith('.json')]
            # Find NFS mounts file
            mounts_files = [f for f in os.listdir(case_dir) if f.startswith('nfsMounts') and f.endswith('.json')]
            
            nfs_exports = {}
            nfs_mounts = {}
            exports_file = None
            mounts_file = None
            
            # Load exports data
            if exports_files:
                latest_exports_file = os.path.join(case_dir, sorted(exports_files)[-1])
                try:
                    with open(latest_exports_file, 'r', encoding='utf-8') as f:
                        exports_data = json.load(f)
                        exports_file = os.path.basename(latest_exports_file)
                        
                        # Extract exports array from the JSON structure
                        if 'exports' in exports_data and isinstance(exports_data['exports'], list):
                            # Convert list of exports to dictionary format expected by frontend
                            for i, export in enumerate(exports_data['exports']):
                                if isinstance(export, dict) and 'path' in export:
                                    nfs_exports[export['path']] = {
                                        'clients': export.get('clients', []),
                                        'options': export.get('options', [])
                                    }
                                elif isinstance(export, str):
                                    # Handle simple string exports
                                    nfs_exports[export] = {
                                        'clients': [],
                                        'options': []
                                    }
                except Exception as e:
                    print(f"Error reading NFS exports: {e}")
            
            # Load mounts data
            if mounts_files:
                latest_mounts_file = os.path.join(case_dir, sorted(mounts_files)[-1])
                try:
                    with open(latest_mounts_file, 'r', encoding='utf-8') as f:
                        mounts_data = json.load(f)
                        mounts_file = os.path.basename(latest_mounts_file)
                        
                        # Extract mounts array from the JSON structure
                        if 'mounts' in mounts_data and isinstance(mounts_data['mounts'], list):
                            # Convert list of mounts to dictionary format expected by frontend
                            for i, mount in enumerate(mounts_data['mounts']):
                                if isinstance(mount, dict):
                                    mount_point = mount.get('mount_point', f'mount_{i}')
                                    nfs_mounts[mount_point] = {
                                        'server': mount.get('server', 'Unknown'),
                                        'remote_path': mount.get('remote_path', 'Unknown'),
                                        'options': mount.get('options', []),
                                        'status': mount.get('status', 'Unknown')
                                    }
                except Exception as e:
                    print(f"Error reading NFS mounts: {e}")
            
            return jsonify({
                'success': True,
                'data': {
                    'nfs_exports': nfs_exports,
                    'nfs_mounts': nfs_mounts,
                    'file': f"Exports: {exports_file or 'Not found'}, Mounts: {mounts_file or 'Not found'}"
                }
            })
        
        elif section == 'samba':
            # Load CIFS mounts and Samba shares data
            case_dir = os.path.join('cases', case.case_id)
            
            # Find CIFS mounts file
            cifs_files = [f for f in os.listdir(case_dir) if f.startswith('cifsMounts') and f.endswith('.json')]
            # Find Samba shares file
            samba_files = [f for f in os.listdir(case_dir) if f.startswith('sambaShares') and f.endswith('.json')]
            
            cifs_mounts = {}
            samba_shares = {}
            cifs_file = None
            samba_file = None
            
            # Load CIFS mounts data
            if cifs_files:
                latest_cifs_file = os.path.join(case_dir, sorted(cifs_files)[-1])
                try:
                    with open(latest_cifs_file, 'r', encoding='utf-8') as f:
                        cifs_data = json.load(f)
                        cifs_file = os.path.basename(latest_cifs_file)
                        
                        # Extract mounts array from the JSON structure
                        if 'mounts' in cifs_data and isinstance(cifs_data['mounts'], list):
                            # Convert list of mounts to dictionary format expected by frontend
                            for i, mount in enumerate(cifs_data['mounts']):
                                if isinstance(mount, dict):
                                    mount_point = mount.get('mount_point', f'mount_{i}')
                                    cifs_mounts[mount_point] = {
                                        'server': mount.get('server', 'Unknown'),
                                        'share': mount.get('share', 'Unknown'),
                                        'options': mount.get('options', []),
                                        'status': mount.get('status', 'Unknown')
                                    }
                except Exception as e:
                    print(f"Error reading CIFS mounts: {e}")
            
            # Load Samba shares data
            if samba_files:
                latest_samba_file = os.path.join(case_dir, sorted(samba_files)[-1])
                try:
                    with open(latest_samba_file, 'r', encoding='utf-8') as f:
                        samba_data = json.load(f)
                        samba_file = os.path.basename(latest_samba_file)
                        
                        # Extract shares array from the JSON structure
                        if 'shares' in samba_data and isinstance(samba_data['shares'], list):
                            # Convert list of shares to dictionary format expected by frontend
                            for i, share in enumerate(samba_data['shares']):
                                if isinstance(share, dict) and 'name' in share:
                                    samba_shares[share['name']] = {
                                        'path': share.get('path', 'Unknown'),
                                        'comment': share.get('comment', ''),
                                        'users': share.get('users', []),
                                        'permissions': share.get('permissions', 'Unknown')
                                    }
                                elif isinstance(share, str):
                                    # Handle simple string shares
                                    samba_shares[share] = {
                                        'path': 'Unknown',
                                        'comment': '',
                                        'users': [],
                                        'permissions': 'Unknown'
                                    }
                except Exception as e:
                    print(f"Error reading Samba shares: {e}")
            
            return jsonify({
                'success': True,
                'data': {
                    'cifs_mounts': cifs_mounts,
                    'samba_shares': samba_shares,
                    'file': f"CIFS: {cifs_file or 'Not found'}, Shares: {samba_file or 'Not found'}"
                }
            })
        
        elif section == 'browsing-history':
            # Load browsing history data
            case_dir = os.path.join('cases', case.case_id)
            
            # Find browsing history file
            history_files = [f for f in os.listdir(case_dir) if f.startswith('browsingHistory') and f.endswith('.json')]
            
            browsing_history = []
            history_file = None
            
            # Load browsing history data
            if history_files:
                latest_history_file = os.path.join(case_dir, sorted(history_files)[-1])
                try:
                    with open(latest_history_file, 'r', encoding='utf-8') as f:
                        history_data = json.load(f)
                        history_file = os.path.basename(latest_history_file)
                        
                        # Process browsing history data
                        if isinstance(history_data, list):
                            for entry in history_data:
                                if isinstance(entry, dict):
                                    # Convert timestamp to readable format
                                    visit_date = 'Unknown'
                                    if 'visitDate' in entry:
                                        try:
                                            # Convert Unix timestamp to readable date
                                            import datetime
                                            timestamp = float(entry['visitDate'])
                                            visit_date = datetime.datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
                                        except (ValueError, TypeError):
                                            visit_date = str(entry['visitDate'])
                                    
                                    last_visit = 'Unknown'
                                    if 'lastVisit' in entry:
                                        try:
                                            timestamp = float(entry['lastVisit'])
                                            last_visit = datetime.datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
                                        except (ValueError, TypeError):
                                            last_visit = str(entry['lastVisit'])
                                    
                                    browsing_history.append({
                                        'url': entry.get('url', '').strip(),
                                        'title': entry.get('title', 'No Title'),
                                        'visitDate': visit_date,
                                        'lastVisit': last_visit,
                                        'visitCount': entry.get('visitCount', 0),
                                        'typed': entry.get('typed', False),
                                        'hidden': entry.get('hidden', False),
                                        'frecency': entry.get('frecency', 0),
                                        'visitType': entry.get('visitType', 0),
                                        'sourceProfile': entry.get('sourceProfile', 'Unknown')
                                    })
                except Exception as e:
                    print(f"Error reading browsing history: {e}")
            
            return jsonify({
                'success': True,
                'data': {
                    'browsing_history': browsing_history,
                    'file': history_file or 'Not found',
                    'total_entries': len(browsing_history)
                }
            })
        
        elif section == 'search-history':
            # Load search history data
            case_dir = os.path.join('cases', case.case_id)
            
            # Find search history file
            search_files = [f for f in os.listdir(case_dir) if f.startswith('searchHistory') and f.endswith('.json')]
            
            search_history = []
            search_file = None
            
            # Load search history data
            if search_files:
                latest_search_file = os.path.join(case_dir, sorted(search_files)[-1])
                try:
                    with open(latest_search_file, 'r', encoding='utf-8') as f:
                        search_data = json.load(f)
                        search_file = os.path.basename(latest_search_file)
                        
                        # Process search history data
                        if isinstance(search_data, list):
                            for entry in search_data:
                                if isinstance(entry, dict):
                                    # Convert timestamps to readable format
                                    first_used = 'Unknown'
                                    last_used = 'Unknown'
                                    
                                    if 'firstUsed' in entry:
                                        try:
                                            import datetime
                                            timestamp = float(entry['firstUsed'])
                                            first_used = datetime.datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
                                        except (ValueError, TypeError):
                                            first_used = str(entry['firstUsed'])
                                    
                                    if 'lastUsed' in entry:
                                        try:
                                            timestamp = float(entry['lastUsed'])
                                            last_used = datetime.datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
                                        except (ValueError, TypeError):
                                            last_used = str(entry['lastUsed'])
                                    
                                    search_history.append({
                                        'fieldName': entry.get('fieldName', 'Unknown'),
                                        'value': entry.get('value', ''),
                                        'url': entry.get('url', ''),
                                        'title': entry.get('title', ''),
                                        'timesUsed': entry.get('timesUsed', 0),
                                        'firstUsed': first_used,
                                        'lastUsed': last_used,
                                        'visitCount': entry.get('visitCount', 0),
                                        'source': entry.get('source', 'Unknown'),
                                        'sourceProfile': entry.get('sourceProfile', 'Unknown')
                                    })
                except Exception as e:
                    print(f"Error reading search history: {e}")
            
            return jsonify({
                'success': True,
                'data': {
                    'search_history': search_history,
                    'file': search_file or 'Not found',
                    'total_entries': len(search_history)
                }
            })
        
        elif section == 'downloads':
            # Load downloads data
            case_dir = os.path.join('cases', case.case_id)
            
            # Find downloads file
            downloads_files = [f for f in os.listdir(case_dir) if f.startswith('downloads_data') and f.endswith('.json')]
            
            downloads = []
            downloads_file = None
            
            # Load downloads data
            if downloads_files:
                latest_downloads_file = os.path.join(case_dir, sorted(downloads_files)[-1])
                try:
                    with open(latest_downloads_file, 'r', encoding='utf-8') as f:
                        downloads_data = json.load(f)
                        downloads_file = os.path.basename(latest_downloads_file)
                        
                        # Process downloads data
                        if isinstance(downloads_data, list):
                            for entry in downloads_data:
                                if isinstance(entry, dict) and entry.get('annotationType') == 'downloads/destinationFileURI':
                                    # Convert timestamp to readable format
                                    download_date = 'Unknown'
                                    
                                    if 'downloadDate' in entry:
                                        try:
                                            import datetime
                                            timestamp = float(entry['downloadDate'])
                                            download_date = datetime.datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
                                        except (ValueError, TypeError):
                                            download_date = str(entry['downloadDate'])
                                    
                                    downloads.append({
                                        'title': entry.get('title', 'Unknown'),
                                        'sourceUrl': entry.get('sourceUrl', ''),
                                        'filePath': entry.get('filePath', ''),
                                        'downloadDate': download_date,
                                        'sourceProfile': entry.get('sourceProfile', 'Unknown')
                                    })
                except Exception as e:
                    print(f"Error reading downloads: {e}")
            
            return jsonify({
                'success': True,
                'data': {
                    'downloads': downloads,
                    'file': downloads_file or 'Not found',
                    'total_entries': len(downloads)
                }
            })
        
        elif section == 'extensions':
            # Load extensions data
            case_dir = os.path.join('cases', case.case_id)
            
            # Find extensions file
            extensions_files = [f for f in os.listdir(case_dir) if f.startswith('extensions_data_') and f.endswith('.json')]
            
            extensions = []
            extensions_file = None
            
            # Load extensions data
            if extensions_files:
                latest_extensions_file = os.path.join(case_dir, sorted(extensions_files)[-1])
                try:
                    with open(latest_extensions_file, 'r', encoding='utf-8') as f:
                        extensions_data = json.load(f)
                        extensions_file = os.path.basename(latest_extensions_file)
                        
                        # Process extensions data
                        if isinstance(extensions_data, list):
                            for entry in extensions_data:
                                if isinstance(entry, dict):
                                    # Convert timestamps to readable format
                                    install_date = 'Unknown'
                                    update_date = 'Unknown'
                                    
                                    if 'installDate' in entry and entry['installDate']:
                                        try:
                                            import datetime
                                            timestamp = float(entry['installDate']) / 1000  # Convert from milliseconds
                                            install_date = datetime.datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
                                        except (ValueError, TypeError):
                                            install_date = str(entry['installDate'])
                                    
                                    if 'updateDate' in entry and entry['updateDate']:
                                        try:
                                            import datetime
                                            timestamp = float(entry['updateDate']) / 1000  # Convert from milliseconds
                                            update_date = datetime.datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
                                        except (ValueError, TypeError):
                                            update_date = str(entry['updateDate'])
                                    
                                    extensions.append({
                                        'id': entry.get('id', 'Unknown'),
                                        'name': entry.get('name', 'Unknown'),
                                        'version': entry.get('version', 'Unknown'),
                                        'type': entry.get('type', 'Unknown'),
                                        'enabled': entry.get('enabled', False),
                                        'installDate': install_date,
                                        'updateDate': update_date,
                                        'description': entry.get('description', ''),
                                        'permissions': entry.get('permissions', []),
                                        'origins': entry.get('origins', []),
                                        'source': entry.get('source', 'Unknown'),
                                        'sourceProfile': entry.get('sourceProfile', 'Unknown')
                                    })
                except Exception as e:
                    print(f"Error reading extensions: {e}")
            
            return jsonify({
                'success': True,
                'data': {
                    'extensions': extensions,
                    'file': extensions_file or 'Not found',
                    'total_entries': len(extensions)
                }
            })
        
        elif section == 'file-listing':
            # Load file listing data
            case_dir = os.path.join('cases', case.case_id)
            file_data = {}
            
            # Look for file listing related files
            file_listing_files = ['criticalFiles.json', 'homeDirectories.json', 'user_home_directories.json']
            
            for file_name in file_listing_files:
                file_path = os.path.join(case_dir, file_name)
                if os.path.exists(file_path):
                    try:
                        data = json_parser.load_json_file(file_path)
                        if data:
                            # Limit entries for performance
                            if isinstance(data, list) and len(data) > 1000:
                                data = data[:1000]  # Show first 1000 entries
                            file_data[file_name] = data
                    except Exception as file_error:
                        print(f"Error processing file listing file {file_name}: {str(file_error)}")
                        continue
            
            # If no specific files found, search for file-related artifacts
            if not file_data:
                file_artifacts = _get_artifacts_by_keywords(case.artifacts, ['file', 'directory', 'critical', 'home'])
                
                for artifact in file_artifacts:
                    try:
                        data = json_parser.load_json_file(artifact.file_path)
                        if data:
                            # Limit entries for performance
                            if isinstance(data, list) and len(data) > 1000:
                                data = data[:1000]  # Show first 1000 entries
                            file_data[artifact.filename] = data
                    except Exception as file_error:
                        print(f"Error processing file artifact {artifact.filename}: {str(file_error)}")
                        continue
            
            return jsonify({
                'success': True,
                'data': file_data
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
    log_pattern = os.path.join(case_dir, 'sea_*.log')
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