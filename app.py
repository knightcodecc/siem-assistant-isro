"""
Conversational SIEM Assistant API
ISRO Problem Statement #25173
Backend service for NLP-powered SIEM interaction
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime, timedelta
import json
import re
from typing import Dict, List, Any
import logging

app = Flask(__name__)
CORS(app)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class NLPParser:
    """Natural Language Parser for SIEM queries"""
    
    def __init__(self):
        self.entity_mappings = {
            'failed login': 'event.outcome:failure AND event.category:authentication',
            'malware': 'event.category:malware',
            'ransomware': 'malware.name:ransomware',
            'network': 'event.category:network',
            'vpn': 'service.name:vpn',
            'ssh': 'service.name:ssh',
            'rdp': 'service.name:rdp',
            'unusual': 'event.risk_score:[70 TO *]',
            'critical': 'event.severity:critical',
            'high': 'event.severity:high',
            'alert': 'event.kind:alert',
            'privileged': 'user.roles:admin OR user.roles:root',
        }
        
        self.time_mappings = {
            'today': '@timestamp:[now/d TO now]',
            'yesterday': '@timestamp:[now-1d/d TO now-1d]',
            'last week': '@timestamp:[now-7d TO now]',
            'last month': '@timestamp:[now-30d TO now]',
            'last hour': '@timestamp:[now-1h TO now]',
            'last 24 hours': '@timestamp:[now-24h TO now]',
        }
    
    def parse(self, query: str) -> Dict[str, Any]:
        """Parse natural language query into structured format"""
        query_lower = query.lower()
        
        # Detect intent
        intent = self._detect_intent(query_lower)
        
        # Extract entities
        entities = self._extract_entities(query_lower)
        
        # Extract time range
        time_range = self._extract_time_range(query_lower)
        
        # Build KQL query
        kql_query = self._build_kql_query(entities, time_range)
        
        return {
            'intent': intent,
            'entities': entities,
            'time_range': time_range,
            'kql_query': kql_query,
            'original_query': query
        }
    
    def _detect_intent(self, query: str) -> str:
        """Detect user intent from query"""
        if any(word in query for word in ['show', 'list', 'get', 'find']):
            return 'search'
        elif any(word in query for word in ['generate', 'create', 'make']):
            return 'report'
        elif any(word in query for word in ['analyze', 'investigate']):
            return 'analyze'
        elif any(word in query for word in ['alert', 'notify']):
            return 'alert'
        else:
            return 'search'
    
    def _extract_entities(self, query: str) -> List[str]:
        """Extract relevant entities from query"""
        entities = []
        for entity, kql in self.entity_mappings.items():
            if entity in query:
                entities.append(kql)
        return entities
    
    def _extract_time_range(self, query: str) -> str:
        """Extract time range from query"""
        for time_phrase, kql in self.time_mappings.items():
            if time_phrase in query:
                return kql
        return '@timestamp:[now-24h TO now]'  # Default to last 24 hours
    
    def _build_kql_query(self, entities: List[str], time_range: str) -> str:
        """Build KQL query from entities and time range"""
        if entities:
            entity_query = ' AND '.join(entities)
            return f"{entity_query} AND {time_range}"
        else:
            return time_range

class QueryGenerator:
    """Generate optimized Elasticsearch/KQL queries"""
    
    def __init__(self):
        self.query_templates = {
            'search': {
                'query': {
                    'bool': {
                        'must': [],
                        'filter': []
                    }
                },
                'size': 100,
                'sort': [{'@timestamp': {'order': 'desc'}}]
            },
            'aggregate': {
                'query': {
                    'bool': {
                        'must': [],
                        'filter': []
                    }
                },
                'aggs': {},
                'size': 0
            }
        }
    
    def generate_elasticsearch_query(self, parsed_data: Dict) -> Dict:
        """Generate Elasticsearch DSL query from parsed data"""
        template = self.query_templates['search'].copy()
        
        # Add query conditions
        if parsed_data['entities']:
            for entity in parsed_data['entities']:
                template['query']['bool']['must'].append({
                    'query_string': {
                        'query': entity
                    }
                })
        
        # Add time filter
        if parsed_data['time_range']:
            template['query']['bool']['filter'].append({
                'range': {
                    '@timestamp': {
                        'gte': 'now-24h',
                        'lte': 'now'
                    }
                }
            })
        
        return template

class ContextManager:
    """Manage conversation context for multi-turn queries"""
    
    def __init__(self):
        self.sessions = {}
    
    def create_session(self, session_id: str) -> Dict:
        """Create new conversation session"""
        self.sessions[session_id] = {
            'id': session_id,
            'created_at': datetime.now().isoformat(),
            'messages': [],
            'context': {},
            'query_history': []
        }
        return self.sessions[session_id]
    
    def add_message(self, session_id: str, message: Dict) -> None:
        """Add message to session history"""
        if session_id not in self.sessions:
            self.create_session(session_id)
        
        self.sessions[session_id]['messages'].append({
            'timestamp': datetime.now().isoformat(),
            'message': message
        })
        
        # Update context
        if 'entities' in message:
            self.sessions[session_id]['context'].update({
                'last_entities': message['entities'],
                'last_time_range': message.get('time_range')
            })
    
    def get_context(self, session_id: str) -> Dict:
        """Get conversation context"""
        if session_id in self.sessions:
            return self.sessions[session_id]['context']
        return {}

class ResponseFormatter:
    """Format SIEM responses for user consumption"""
    
    def format_search_results(self, results: List[Dict]) -> Dict:
        """Format search results into readable response"""
        if not results:
            return {
                'text': 'No results found for your query.',
                'data': []
            }
        
        # Analyze results
        total = len(results)
        
        # Group by relevant fields
        summary = self._generate_summary(results)
        
        return {
            'text': summary,
            'data': results[:10],  # Limit to top 10
            'total': total,
            'visualization': self._suggest_visualization(results)
        }
    
    def _generate_summary(self, results: List[Dict]) -> str:
        """Generate text summary of results"""
        total = len(results)
        
        if total == 0:
            return "No events found matching your criteria."
        elif total == 1:
            return "Found 1 event matching your criteria."
        else:
            return f"Found {total} events matching your criteria."
    
    def _suggest_visualization(self, results: List[Dict]) -> str:
        """Suggest appropriate visualization type"""
        if len(results) > 50:
            return 'timeline'
        elif len(results) > 10:
            return 'bar_chart'
        else:
            return 'table'

# Initialize components
nlp_parser = NLPParser()
query_generator = QueryGenerator()
context_manager = ContextManager()
response_formatter = ResponseFormatter()

# Mock SIEM connector (replace with actual Elastic/Wazuh connection)
class MockSIEMConnector:
    """Mock SIEM connector for demonstration"""
    
    def execute_query(self, query: Dict) -> List[Dict]:
        """Execute query against SIEM (mock implementation)"""
        # Return mock data for demonstration
        return [
            {
                '@timestamp': '2024-01-15T10:30:00Z',
                'event.category': 'authentication',
                'event.outcome': 'failure',
                'source.ip': '192.168.1.100',
                'user.name': 'admin',
                'service.name': 'ssh'
            },
            {
                '@timestamp': '2024-01-15T10:35:00Z',
                'event.category': 'authentication',
                'event.outcome': 'failure',
                'source.ip': '10.0.0.50',
                'user.name': 'root',
                'service.name': 'rdp'
            }
        ]

siem_connector = MockSIEMConnector()

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'service': 'SIEM Assistant API'
    })

@app.route('/api/query', methods=['POST'])
def process_query():
    """Process natural language query"""
    try:
        data = request.json
        query = data.get('query', '')
        session_id = data.get('session_id', 'default')
        
        # Parse natural language
        parsed = nlp_parser.parse(query)
        
        # Generate Elasticsearch query
        es_query = query_generator.generate_elasticsearch_query(parsed)
        
        # Execute query (mock)
        results = siem_connector.execute_query(es_query)
        
        # Format response
        formatted_response = response_formatter.format_search_results(results)
        
        # Update context
        context_manager.add_message(session_id, {
            'query': query,
            'parsed': parsed,
            'results_count': len(results)
        })
        
        return jsonify({
            'success': True,
            'query': query,
            'kql': parsed['kql_query'],
            'elasticsearch_query': es_query,
            'response': formatted_response,
            'session_id': session_id
        })
    
    except Exception as e:
        logger.error(f"Error processing query: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/report', methods=['POST'])
def generate_report():
    """Generate automated report"""
    try:
        data = request.json
        report_type = data.get('type', 'summary')
        time_range = data.get('time_range', 'last_24_hours')
        
        # Generate report data (mock)
        report_data = {
            'title': f'Security Report - {datetime.now().strftime("%Y-%m-%d")}',
            'summary': {
                'total_events': 3847,
                'critical_alerts': 7,
                'high_alerts': 23,
                'medium_alerts': 45
            },
            'top_threats': [
                {'name': 'Failed Authentication', 'count': 847},
                {'name': 'Malware Detection', 'count': 156},
                {'name': 'Network Anomaly', 'count': 89}
            ],
            'recommendations': [
                'Investigate failed authentication attempts from IP 192.168.1.100',
                'Update malware signatures to latest version',
                'Review network segmentation policies'
            ]
        }
        
        return jsonify({
            'success': True,
            'report': report_data,
            'format': 'json',
            'generated_at': datetime.now().isoformat()
        })
    
    except Exception as e:
        logger.error(f"Error generating report: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/context', methods=['GET'])
def get_context():
    """Get conversation context"""
    session_id = request.args.get('session_id', 'default')
    context = context_manager.get_context(session_id)
    
    return jsonify({
        'session_id': session_id,
        'context': context
    })

@app.route('/api/clarify', methods=['POST'])
def clarify_query():
    """Handle ambiguous queries by asking for clarification"""
    try:
        data = request.json
        query = data.get('query', '')
        
        # Analyze ambiguity
        clarifications = []
        
        if 'unusual' in query.lower() and 'activity' in query.lower():
            clarifications = [
                'Unusual bandwidth patterns',
                'Anomalous connection attempts',
                'Suspicious data transfers',
                'All unusual activities'
            ]
        elif 'report' in query.lower():
            clarifications = [
                'Executive summary report',
                'Technical detailed report',
                'Compliance audit report',
                'Custom report'
            ]
        
        return jsonify({
            'needs_clarification': len(clarifications) > 0,
            'options': clarifications,
            'original_query': query
        })
    
    except Exception as e:
        logger.error(f"Error in clarification: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)