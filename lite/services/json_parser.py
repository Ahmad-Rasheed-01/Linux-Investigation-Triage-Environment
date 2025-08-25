import json
import os
from typing import Any, Dict, List, Union

class JsonParser:
    """Service for parsing and searching JSON artifacts"""
    
    def __init__(self):
        self.max_file_size_mb = 500  # Maximum file size to process
        self.max_records_display = 1000  # Maximum records to display at once
    
    def load_json_file(self, file_path: str) -> Union[Dict, List, None]:
        """Load JSON file with size and safety checks"""
        try:
            # Check file size
            file_size_mb = os.path.getsize(file_path) / (1024 * 1024)
            if file_size_mb > self.max_file_size_mb:
                raise Exception(f"File too large: {file_size_mb:.1f}MB (max: {self.max_file_size_mb}MB)")
            
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Limit records for display performance
            if isinstance(data, list) and len(data) > self.max_records_display:
                return data[:self.max_records_display]
            
            return data
            
        except json.JSONDecodeError as e:
            raise Exception(f"Invalid JSON format: {str(e)}")
        except FileNotFoundError:
            raise Exception("File not found")
        except Exception as e:
            raise Exception(f"Error loading file: {str(e)}")
    
    def get_json_summary(self, file_path: str) -> Dict[str, Any]:
        """Get summary information about JSON file"""
        try:
            data = self.load_json_file(file_path)
            
            summary = {
                'type': type(data).__name__,
                'size_mb': os.path.getsize(file_path) / (1024 * 1024),
                'record_count': 0,
                'structure': {},
                'sample_keys': []
            }
            
            if isinstance(data, list):
                summary['record_count'] = len(data)
                if data:
                    # Analyze first record structure
                    first_record = data[0]
                    if isinstance(first_record, dict):
                        summary['sample_keys'] = list(first_record.keys())[:10]
                        summary['structure'] = self._analyze_structure(first_record)
            
            elif isinstance(data, dict):
                summary['record_count'] = 1
                summary['sample_keys'] = list(data.keys())[:10]
                summary['structure'] = self._analyze_structure(data)
            
            return summary
            
        except Exception as e:
            return {'error': str(e)}
    
    def search_in_data(self, data: Union[Dict, List], query: str) -> bool:
        """Search for query string in JSON data"""
        query_lower = query.lower()
        
        try:
            if isinstance(data, dict):
                return self._search_in_dict(data, query_lower)
            elif isinstance(data, list):
                return self._search_in_list(data, query_lower)
            else:
                return query_lower in str(data).lower()
                
        except Exception:
            return False
    
    def _search_in_dict(self, data: Dict, query: str) -> bool:
        """Search in dictionary"""
        for key, value in data.items():
            # Search in key
            if query in key.lower():
                return True
            
            # Search in value
            if isinstance(value, (dict, list)):
                if self.search_in_data(value, query):
                    return True
            else:
                if query in str(value).lower():
                    return True
        
        return False
    
    def _search_in_list(self, data: List, query: str) -> bool:
        """Search in list (limit search for performance)"""
        # Limit search to first 100 items for performance
        search_limit = min(len(data), 100)
        
        for item in data[:search_limit]:
            if self.search_in_data(item, query):
                return True
        
        return False
    
    def _analyze_structure(self, data: Dict) -> Dict[str, str]:
        """Analyze the structure of a dictionary"""
        structure = {}
        
        for key, value in data.items():
            if isinstance(value, dict):
                structure[key] = 'object'
            elif isinstance(value, list):
                if value and isinstance(value[0], dict):
                    structure[key] = 'array[object]'
                else:
                    structure[key] = 'array'
            elif isinstance(value, str):
                structure[key] = 'string'
            elif isinstance(value, (int, float)):
                structure[key] = 'number'
            elif isinstance(value, bool):
                structure[key] = 'boolean'
            else:
                structure[key] = 'unknown'
        
        return structure
    
    def extract_fields(self, data: Union[Dict, List], fields: List[str]) -> List[Dict]:
        """Extract specific fields from JSON data"""
        results = []
        
        try:
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, dict):
                        extracted = {}
                        for field in fields:
                            if field in item:
                                extracted[field] = item[field]
                        if extracted:
                            results.append(extracted)
            
            elif isinstance(data, dict):
                extracted = {}
                for field in fields:
                    if field in data:
                        extracted[field] = data[field]
                if extracted:
                    results.append(extracted)
            
            return results
            
        except Exception as e:
            raise Exception(f"Error extracting fields: {str(e)}")
    
    def filter_data(self, data: Union[Dict, List], filters: Dict[str, Any]) -> Union[Dict, List]:
        """Filter JSON data based on criteria"""
        try:
            if isinstance(data, list):
                filtered = []
                for item in data:
                    if isinstance(item, dict) and self._matches_filters(item, filters):
                        filtered.append(item)
                return filtered
            
            elif isinstance(data, dict):
                if self._matches_filters(data, filters):
                    return data
                else:
                    return {}
            
            return data
            
        except Exception as e:
            raise Exception(f"Error filtering data: {str(e)}")
    
    def _matches_filters(self, item: Dict, filters: Dict[str, Any]) -> bool:
        """Check if item matches filter criteria"""
        for field, value in filters.items():
            if field not in item:
                return False
            
            item_value = item[field]
            
            # String contains check
            if isinstance(value, str) and isinstance(item_value, str):
                if value.lower() not in item_value.lower():
                    return False
            # Exact match for other types
            elif item_value != value:
                return False
        
        return True
    
    def get_unique_values(self, data: Union[Dict, List], field: str) -> List[Any]:
        """Get unique values for a specific field"""
        unique_values = set()
        
        try:
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, dict) and field in item:
                        unique_values.add(item[field])
            
            elif isinstance(data, dict) and field in data:
                unique_values.add(data[field])
            
            return sorted(list(unique_values))
            
        except Exception:
            return []
    
    def paginate_data(self, data: List, page: int = 1, per_page: int = 50) -> Dict[str, Any]:
        """Paginate list data"""
        if not isinstance(data, list):
            return {'items': data, 'total': 1, 'page': 1, 'pages': 1}
        
        total = len(data)
        pages = (total + per_page - 1) // per_page
        start = (page - 1) * per_page
        end = start + per_page
        
        return {
            'items': data[start:end],
            'total': total,
            'page': page,
            'pages': pages,
            'per_page': per_page,
            'has_prev': page > 1,
            'has_next': page < pages
        }