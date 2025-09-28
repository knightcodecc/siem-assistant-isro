"""
Enhanced Conversational SIEM Assistant API
ISRO Problem Statement #25173
Advanced NLP-powered SIEM interaction with ISRO mission context
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime, timedelta
import json
import re
import uuid
import logging
from typing import Dict, List, Any, Optional
import time
import random

app = Flask(__name__)
CORS(app)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ISRONLPProcessor:
    """Advanced Natural Language Processor for ISRO SIEM queries"""
    
    def __init__(self):
        # Enhanced entity mappings with ISRO context
        self.entity_mappings = {
            # Authentication & Access Control
            'failed login': {
                'kql': 'event.outcome:failure AND event.category:authentication',
                'category': 'authentication',
                'priority': 'HIGH',
                'description': 'Failed authentication attempts'
            },
            'privileged access': {
                'kql': 'user.roles:(admin OR root OR mission_controller OR satellite_operator)',
                'category': 'privilege_escalation',
                'priority': 'CRITICAL',
                'description': 'Privileged account activities'
            },
            'suspicious login': {
                'kql': 'event.action:login AND event.risk_score:[70 TO *]',
                'category': 'suspicious_activity',
                'priority': 'HIGH',
                'description': 'Suspicious authentication patterns'
            },
            
            # Network & Communication Security
            'network anomaly': {
                'kql': 'event.category:network AND event.risk_score:[80 TO *]',
                'category': 'network_security',
                'priority': 'HIGH',
                'description': 'Network traffic anomalies'
            },
            'satellite communication': {
                'kql': 'service.name:satellite_comm OR tags:satellite_comms',
                'category': 'space_communications',
                'priority': 'CRITICAL',
                'description': 'Satellite communication systems'
            },
            'ground station': {
                'kql': 'tags:ground_station OR host.name:*-station-* OR location.facility:(VSSC OR SHAR OR ISTRAC OR NRSC)',
                'category': 'infrastructure',
                'priority': 'HIGH',
                'description': 'Ground station infrastructure'
            },
            
            # Threat Detection
            'malware': {
                'kql': 'event.category:malware OR threat.indicator.type:malware',
                'category': 'malware',
                'priority': 'CRITICAL',
                'description': 'Malware detection events'
            },
            'ransomware': {
                'kql': 'malware.name:ransomware OR threat.tactic:impact',
                'category': 'ransomware',
                'priority': 'CRITICAL',
                'description': 'Ransomware activity detection'
            },
            'apt': {
                'kql': 'threat.group.name:* AND threat.tactic:* AND tags:advanced_persistent_threat',
                'category': 'advanced_threats',
                'priority': 'CRITICAL',
                'description': 'Advanced Persistent Threat indicators'
            },
            
            # ISRO Mission-Specific
            'chandrayaan': {
                'kql': 'tags:chandrayaan OR mission.name:chandrayaan* OR project.lunar_mission:*',
                'category': 'lunar_mission',
                'priority': 'CRITICAL',
                'description': 'Chandrayaan lunar mission systems'
            },
            'aditya': {
                'kql': 'tags:aditya OR mission.name:aditya* OR project.solar_mission:*',
                'category': 'solar_mission',
                'priority': 'CRITICAL',
                'description': 'Aditya-L1 solar observatory mission'
            },
            'gaganyaan': {
                'kql': 'tags:gaganyaan OR mission.name:gaganyaan* OR project.human_spaceflight:*',
                'category': 'human_spaceflight',
                'priority': 'CRITICAL',
                'description': 'Gaganyaan human spaceflight program'
            },
            'mission control': {
                'kql': 'host.name:*mission-control* OR tags:mission_control OR facility:mission_operations',
                'category': 'mission_operations',
                'priority': 'CRITICAL',
                'description': 'Mission control systems'
            },
            'launch': {
                'kql': 'event.category:launch_operations OR tags:launch OR phase:launch_window',
                'category': 'launch_operations',
                'priority': 'CRITICAL',
                'description': 'Launch operations and systems'
            }
        }
        
        # Enhanced time mappings with mission-specific contexts
        self.time_mappings = {
            'today': '@timestamp:[now/d TO now]',
            'yesterday': '@timestamp:[now-1d/d TO now-1d/d+1d]',
            'last week': '@timestamp:[now-7d TO now]',
            'last month': '@timestamp:[now-30d TO now]',
            'last hour': '@timestamp:[now-1h TO now]',
            'last 24 hours': '@timestamp:[now-24h TO now]',
            'during launch': '@timestamp:[now-4h TO now+2h] AND tags:launch_window',
            'mission phase': '@timestamp:[now-12h TO now] AND mission.phase:*',
            'orbit insertion': '@timestamp:[now-6h TO now+2h] AND mission.phase:orbit_insertion',
            'critical phase': '@timestamp:[now-2h TO now] AND mission.criticality:high'
        }
        
        # Mission-specific contexts
        self.mission_contexts = {
            'chandrayaan': {
                'filters': 'mission.name:chandrayaan* OR tags:lunar_mission',
                'priority_systems': ['lunar_orbiter', 'ground_station_byalalu', 'mission_control_bangalore', 'deep_space_network'],
                'critical_phases': ['trans_lunar_injection', 'lunar_orbit_insertion', 'powered_descent', 'landing'],
                'ground_stations': ['IDSN_Byalalu', 'IDSN_Bangalore', 'DSN_Madrid', 'DSN_Goldstone']
            },
            'aditya': {
                'filters': 'mission.name:aditya* OR tags:solar_mission',
                'priority_systems': ['l1_spacecraft', 'deep_space_network', 'mission_control_bangalore', 'payload_operations'],
                'critical_phases': ['l1_transfer', 'halo_orbit_insertion', 'payload_commissioning'],
                'ground_stations': ['IDSN_Byalalu', 'IDSN_Bangalore', 'Goldstone_DSN', 'Madrid_DSN']
            },
            'gaganyaan': {
                'filters': 'mission.name:gaganyaan* OR tags:human_spaceflight',
                'priority_systems': ['crew_module', 'life_support_system', 'mission_control_shar', 'recovery_systems'],
                'critical_phases': ['launch', 'orbital_insertion', 'docking', 'reentry', 'recovery'],
                'ground_stations': ['SHAR_Sriharikota', 'Mission_Control_SHAR', 'Recovery_Control_Center']
            },
            'navigation': {
                'filters': 'mission.name:navic* OR tags:navigation_system',
                'priority_systems': ['navigation_satellites', 'ground_control_segment', 'user_segment'],
                'critical_phases': ['constellation_maintenance', 'time_synchronization', 'signal_monitoring'],
                'ground_stations': ['MCF_Hassan', 'MCF_Bhopal', 'TTC_Stations']
            }
        }
        
        # Intent classification patterns
        self.intent_patterns = {
            'search': ['show', 'list', 'find', 'get', 'display', 'what', 'which'],
            'analyze': ['analyze', 'investigate', 'examine', 'study', 'review'],
            'report': ['generate', 'create', 'make', 'produce', 'compile', 'report'],
            'monitor': ['monitor', 'watch', 'track', 'observe', 'check'],
            'alert': ['alert', 'notify', 'warn', 'inform', 'escalate']
        }

    def parse_query(self, query: str, context: Dict = None) -> Dict[str, Any]:
        """Parse natural language query with enhanced ISRO context"""
        start_time = time.time()
        
        analysis = {
            'original_query': query,
            'intent': self._detect_intent(query),
            'entities': self._extract_entities(query),
            'time_range': self._extract_time_range(query),
            'mission_context': self._extract_mission_context(query, context),
            'priority': self._assess_priority(query),
            'confidence': self._calculate_confidence(query),
            'processing_time': 0,
            'suggestions': []
        }
        
        # Build KQL query
        analysis['kql_query'] = self._build_advanced_kql(analysis)
        analysis['elasticsearch_dsl'] = self._build_elasticsearch_dsl(analysis)
        analysis['explanation'] = self._generate_explanation(analysis)
        analysis['follow_up_suggestions'] = self._generate_follow_ups(analysis, context)
        
        analysis['processing_time'] = round(time.time() - start_time, 3)
        
        return analysis

    def _detect_intent(self, query: str) -> str:
        """Enhanced intent detection with confidence scoring"""
        query_lower = query.lower()
        intent_scores = {}
        
        for intent, patterns in self.intent_patterns.items():
            score = sum(1 for pattern in patterns if pattern in query_lower)
            if score > 0:
                intent_scores[intent] = score
        
        if not intent_scores:
            return 'search'  # Default intent
        
        return max(intent_scores.items(), key=lambda x: x[1])[0]

    def _extract_entities(self, query: str) -> List[Dict]:
        """Extract entities with relevance scoring"""
        entities = []
        query_lower = query.lower()
        
        for entity_term, mapping in self.entity_mappings.items():
            if entity_term in query_lower:
                # Calculate relevance based on context
                relevance = self._calculate_entity_relevance(entity_term, query_lower)
                
                entities.append({
                    'term': entity_term,
                    'kql': mapping['kql'],
                    'category': mapping['category'],
                    'priority': mapping['priority'],
                    'description': mapping['description'],
                    'relevance': relevance
                })
        
        # Sort by relevance
        entities.sort(key=lambda x: x['relevance'], reverse=True)
        
        return entities

    def _calculate_entity_relevance(self, entity: str, query: str) -> float:
        """Calculate entity relevance score"""
        base_score = 1.0
        
        # Boost score for exact matches
        if entity in query:
            base_score += 0.5
        
        # Boost for ISRO-specific terms
        isro_terms = ['satellite', 'mission', 'launch', 'space', 'chandrayaan', 'aditya', 'gaganyaan']
        if any(term in entity for term in isro_terms):
            base_score += 0.3
        
        # Boost for security-critical terms
        critical_terms = ['failed', 'malware', 'intrusion', 'breach', 'unauthorized']
        if any(term in entity for term in critical_terms):
            base_score += 0.2
        
        return base_score

    def _extract_mission_context(self, query: str, context: Dict = None) -> Optional[Dict]:
        """Extract mission-specific context"""
        query_lower = query.lower()
        
        # Check for explicit mission mentions
        for mission, mission_data in self.mission_contexts.items():
            if mission in query_lower:
                return {'mission': mission, **mission_data}
        
        # Check current context if provided
        if context and context.get('current_mission') != 'general':
            mission = context.get('current_mission')
            if mission in self.mission_contexts:
                return {'mission': mission, **self.mission_contexts[mission]}
        
        return None

    def _assess_priority(self, query: str) -> str:
        """Assess query priority based on content"""
        query_lower = query.lower()
        
        critical_keywords = ['critical', 'emergency', 'breach', 'attack', 'compromise', 'failure', 'down', 'offline']
        high_keywords = ['suspicious', 'anomaly', 'unusual', 'unauthorized', 'escalation', 'alert']
        
        if any(keyword in query_lower for keyword in critical_keywords):
            return 'CRITICAL'
        elif any(keyword in query_lower for keyword in high_keywords):
            return 'HIGH'
        else:
            return 'MEDIUM'

    def _calculate_confidence(self, query: str) -> float:
        """Calculate parsing confidence"""
        confidence_factors = []
        
        # Length factor
        word_count = len(query.split())
        if 3 <= word_count <= 15:
            confidence_factors.append(0.8)
        else:
            confidence_factors.append(0.5)
        
        # Entity detection factor
        entities_found = sum(1 for entity in self.entity_mappings.keys() if entity in query.lower())
        confidence_factors.append(min(entities_found * 0.2, 0.9))
        
        # Time reference factor
        time_refs = sum(1 for time_ref in self.time_mappings.keys() if time_ref in query.lower())
        if time_refs > 0:
            confidence_factors.append(0.8)
        else:
            confidence_factors.append(0.6)
        
        return round(sum(confidence_factors) / len(confidence_factors), 2)

    def _build_advanced_kql(self, analysis: Dict) -> str:
        """Build advanced KQL query with optimization"""
        query_parts = []
        
        # Add entity filters with proper grouping
        if analysis['entities']:
            entity_queries = []
            for entity in analysis['entities'][:3]:  # Limit to top 3 entities
                entity_queries.append(f"({entity['kql']})")
            query_parts.append(f"({' OR '.join(entity_queries)})")
        
        # Add time range filter
        if analysis['time_range']:
            query_parts.append(analysis['time_range']['kql'])
        
        # Add mission context filter
        if analysis['mission_context']:
            query_parts.append(f"({analysis['mission_context']['filters']})")
        
        # Add priority filter for critical queries
        if analysis['priority'] == 'CRITICAL':
            query_parts.append("event.risk_score:[80 TO *]")
        
        final_query = ' AND '.join(query_parts) if query_parts else '*'
        
        # Add optimization hints
        if analysis['intent'] == 'search':
            final_query += " | sort @timestamp desc | limit 100"
        elif analysis['intent'] == 'analyze':
            final_query += " | stats count() by source.ip, user.name | sort count desc"
        
        return final_query

    def _build_elasticsearch_dsl(self, analysis: Dict) -> Dict:
        """Build Elasticsearch DSL query"""
        query_dsl = {
            "query": {
                "bool": {
                    "must": [],
                    "filter": []
                }
            },
            "sort": [{"@timestamp": {"order": "desc"}}],
            "size": 100
        }
        
        # Add entity queries
        for entity in analysis['entities'][:3]:
            query_dsl["query"]["bool"]["must"].append({
                "query_string": {"query": entity['kql']}
            })
        
        # Add time range
        if analysis['time_range']:
            time_filter = self._convert_kql_time_to_es(analysis['time_range']['kql'])
            if time_filter:
                query_dsl["query"]["bool"]["filter"].append(time_filter)
        
        # Add mission context
        if analysis['mission_context']:
            query_dsl["query"]["bool"]["filter"].append({
                "query_string": {"query": analysis['mission_context']['filters']}
            })
        
        return query_dsl

    def _convert_kql_time_to_es(self, kql_time: str) -> Optional[Dict]:
        """Convert KQL time range to Elasticsearch format"""
        # Simple conversion for demo - would need more sophisticated parsing in production
        return {
            "range": {
                "@timestamp": {
                    "gte": "now-24h",
                    "lte": "now"
                }
            }
        }

    def _generate_explanation(self, analysis: Dict) -> str:
        """Generate human-readable explanation of the query"""
        explanation = f"Analyzing "
        
        if analysis['entities']:
            entity_names = [entity['term'] for entity in analysis['entities'][:2]]
            explanation += f"{' and '.join(entity_names)} events"
        else:
            explanation += "security events"
        
        if analysis['time_range']:
            explanation += f" from {analysis['time_range']['phrase']}"
        
        if analysis['mission_context']:
            explanation += f" in the context of {analysis['mission_context']['mission']} mission"
        
        explanation += f". Query priority: {analysis['priority']}, Confidence: {analysis['confidence']*100:.0f}%"
        
        return explanation

    def _generate_follow_ups(self, analysis: Dict, context: Dict = None) -> List[str]:
        """Generate contextual follow-up suggestions"""
        suggestions = []
        
        # Intent-based suggestions
        if analysis['intent'] == 'search':
            suggestions.extend([
                "Generate detailed report from these results",
                "Show timeline visualization",
                "Filter by severity level"
            ])
        elif analysis['intent'] == 'analyze':
            suggestions.extend([
                "Create correlation analysis",
                "Generate threat assessment",
                "Export analysis results"
            ])
        
        # Entity-based suggestions
        if any(entity['category'] == 'authentication' for entity in analysis['entities']):
            suggestions.append("Analyze user behavior patterns")
            suggestions.append("Check source IP geolocation")
        
        if any(entity['category'] in ['malware', 'ransomware'] for entity in analysis['entities']):
            suggestions.append("Generate threat intelligence report")
            suggestions.append("Check for lateral movement indicators")
        
        # Mission-specific suggestions
        if analysis['mission_context']:
            mission = analysis['mission_context']['mission']
            suggestions.append(f"Show {mission} mission timeline")
            suggestions.append("Monitor critical system status")
        
        return suggestions[:4]  # Limit to 4 suggestions


class ISROSIEMConnector:
    """Enhanced SIEM connector with ISRO-specific data simulation"""
    
    def __init__(self):
        self.mock_data = self._initialize_mock_data()
        self.connection_status = {
            'elastic': True,
            'wazuh': True,
            'last_check': datetime.now()
        }

    def _initialize_mock_data(self) -> Dict:
        """Initialize comprehensive ISRO SIEM mock data"""
        return {
            'ground_station_security': [
                {
                    '@timestamp': '2025-01-15T14:23:45Z',
                    'event.category': 'authentication',
                    'event.outcome': 'failure',
                    'event.risk_score': 85,
                    'user.name': 'mission_controller_lead',
                    'source.ip': '203.192.45.123',
                    'destination.ip': '10.15.45.89',
                    'tags': ['ground_station', 'vssc_thumba'],
                    'location.facility': 'VSSC',
                    'mission.name': 'chandrayaan-3',
                    'system.name': 'ground_control_system',
                    'attempts': 15,
                    'geo.country': 'India',
                    'event.severity': 'high'
                },
                {
                    '@timestamp': '2025-01-15T15:45:22Z',
                    'event.category': 'authentication',
                    'event.outcome': 'success',
                    'event.risk_score': 95,
                    'user.name': 'satellite_operator',
                    'source.ip': '10.0.15.89',
                    'tags': ['privilege_escalation', 'shar_sriharikota'],
                    'location.facility': 'SHAR',
                    'mission.name': 'aditya-l1',
                    'system.name': 'mission_control_system',
                    'user.roles': ['satellite_operator', 'elevated_access'],
                    'event.severity': 'critical'
                }
            ],
            
            'mission_critical_events': [
                {
                    '@timestamp': '2025-01-15T16:12:33Z',
                    'mission.name': 'chandrayaan-3',
                    'mission.phase': 'lunar_orbit_insertion',
                    'event.category': 'communication',
                    'event.type': 'anomaly',
                    'service.name': 'satellite_comm',
                    'communication.type': 'telemetry',
                    'duration': '4m 32s',
                    'impact': 'temporary_telemetry_loss',
                    'status': 'resolved',
                    'ground_station': 'IDSN_Byalalu',
                    'satellite.id': 'CH3-ORB-001',
                    'frequency': '2.2_GHz',
                    'signal_strength': 'weak',
                    'event.severity': 'high'
                },
                {
                    '@timestamp': '2025-01-15T17:30:11Z',
                    'mission.name': 'aditya-l1',
                    'mission.phase': 'l1_transit',
                    'event.category': 'network',
                    'event.type': 'intrusion_attempt',
                    'source.ip': '185.220.101.45',
                    'destination.ip': '10.45.67.23',
                    'network.protocol': 'tcp',
                    'destination.port': 22,
                    'tags': ['ssh_brute_force', 'blocked'],
                    'threat.indicator.type': 'ip',
                    'threat.tactic': 'credential_access',
                    'blocked': True,
                    'event.severity': 'critical'
                }
            ],
            
            'space_threat_intelligence': [
                {
                    '@timestamp': '2025-01-15T12:00:00Z',
                    'threat.group.name': 'APT-SpaceStorm',
                    'threat.tactic': ['initial_access', 'persistence', 'command_and_control'],
                    'threat.technique': 'spear_phishing',
                    'targets': 'satellite_communication_systems',
                    'indicators': ['185.220.101.45', 'space-ops.malicious.com'],
                    'risk_level': 'critical',
                    'last_seen': '2 days ago',
                    'attribution': 'nation_state_actor',
                    'campaigns': ['operation_orbital_breach'],
                    'affected_missions': ['earth_observation', 'navigation'],
                    'mitigation_status': 'active_monitoring'
                },
                {
                    '@timestamp': '2025-01-14T08:30:00Z',
                    'threat.group.name': 'CyberSat-Collective',
                    'threat.tactic': ['lateral_movement', 'data_exfiltration'],
                    'threat.technique': 'remote_access_tools',
                    'targets': 'ground_station_infrastructure',
                    'indicators': ['203.45.67.89', 'gscontrol.compromised.net'],
                    'risk_level': 'high',
                    'last_seen': '1 week ago',
                    'attribution': 'cybercriminal_group',
                    'campaigns': ['ransomware_space_ops'],
                    'mitigation_status': 'contained'
                }
            ],
            
            'communication_security': [
                {
                    '@timestamp': '2025-01-15T11:15:30Z',
                    'satellite.name': 'INSAT-3DR',
                    'satellite.id': 'INSAT3DR-001',
                    'frequency': '4.2_GHz',
                    'communication.type': 'weather_data',
                    'anomaly.type': 'signal_interference',
                    'location.coordinates': [68.5, 12.8],
                    'location.description': 'Arabian_Sea',
                    'duration': '15 minutes',
                    'impact': 'weather_data_delay',
                    'interference.source': 'unknown',
                    'investigation.status': 'ongoing',
                    'event.severity': 'medium'
                },
                {
                    '@timestamp': '2025-01-15T13:45:22Z',
                    'satellite.name': 'RISAT-2B',
                    'satellite.id': 'RISAT2B-001',
                    'frequency': '5.6_GHz',
                    'communication.type': 'radar_data',
                    'anomaly.type': 'unauthorized_access_attempt',
                    'source.ip': 'unknown',
                    'attack.vector': 'frequency_hijacking',
                    'blocked': True,
                    'investigation.status': 'escalated',
                    'threat.level': 'high',
                    'event.severity': 'critical'
                }
            ]
        }

    def execute_query(self, query_analysis: Dict) -> Dict:
        """Execute query and return mock results with realistic processing"""
        # Simulate processing delay
        processing_time = random.uniform(0.8, 2.5)
        time.sleep(processing_time / 10)  # Reduced for demo
        
        # Determine data type based on query analysis
        data_type = self._determine_data_type(query_analysis)
        
        # Get relevant mock data
        raw_data = self.mock_data.get(data_type, [])
        
        # Filter and process data based on query
        filtered_data = self._filter_data(raw_data, query_analysis)
        
        # Generate aggregations if needed
        aggregations = self._generate_aggregations(filtered_data, query_analysis)
        
        return {
            'total_hits': len(filtered_data),
            'took': round(processing_time * 1000),  # Convert to milliseconds
            'data': filtered_data,
            'aggregations': aggregations,
            'query_metadata': {
                'data_type': data_type,
                'processing_time': processing_time,
                'confidence': query_analysis.get('confidence', 0.8)
            }
        }

    def _determine_data_type(self, query_analysis: Dict) -> str:
        """Determine which data type to return based on query analysis"""
        query = query_analysis['original_query'].lower()
        
        if any(term in query for term in ['ground station', 'authentication', 'failed', 'login']):
            return 'ground_station_security'
        elif any(term in query for term in ['mission', 'chandrayaan', 'aditya', 'critical']):
            return 'mission_critical_events'
        elif any(term in query for term in ['threat', 'intelligence', 'apt']):
            return 'space_threat_intelligence'
        elif any(term in query for term in ['communication', 'satellite', 'signal']):
            return 'communication_security'
        else:
            return 'ground_station_security'  # Default

    def _filter_data(self, data: List[Dict], query_analysis: Dict) -> List[Dict]:
        """Filter data based on query parameters"""
        filtered = data.copy()
        
        # Filter by mission context if specified
        if query_analysis.get('mission_context'):
            mission = query_analysis['mission_context']['mission']
            filtered = [item for item in filtered 
                       if item.get('mission.name', '').startswith(mission) or 
                          mission in item.get('tags', [])]
        
        # Filter by priority/severity
        if query_analysis.get('priority') == 'CRITICAL':
            filtered = [item for item in filtered 
                       if item.get('event.severity') in ['critical', 'high'] or
                          item.get('event.risk_score', 0) >= 80]
        
        # Simulate time-based filtering (simplified for demo)
        if query_analysis.get('time_range', {}).get('phrase') == 'yesterday':
            # In a real implementation, this would filter by actual timestamps
            filtered = filtered[:2]  # Return subset for demo
        
        return filtered

    def _generate_aggregations(self, data: List[Dict], query_analysis: Dict) -> Dict:
        """Generate aggregations for analysis queries"""
        if not data or query_analysis.get('intent') != 'analyze':
            return {}
        
        aggregations = {}
        
        # Count by severity
        severity_counts = {}
        for item in data:
            severity = item.get('event.severity', 'unknown')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        aggregations['severity_distribution'] = severity_counts
        
        # Count by mission if applicable
        if any('mission.name' in item for item in data):
            mission_counts = {}
            for item in data:
                mission = item.get('mission.name', 'unknown')
                mission_counts[mission] = mission_counts.get(mission, 0) + 1
            aggregations['mission_distribution'] = mission_counts
        
        return aggregations


class EnhancedContextManager:
    """Enhanced context manager with persistent conversation state"""
    
    def __init__(self):
        self.sessions = {}
        self.global_context = {
            'active_investigations': 0,
            'total_queries': 0,
            'performance_metrics': {
                'avg_response_time': 1.2,
                'accuracy_rate': 0.94,
                'context_retention': 0.98
            }
        }

    def create_session(self, session_id: str) -> Dict:
        """Create enhanced conversation session"""
        self.sessions[session_id] = {
            'id': session_id,
            'created_at': datetime.now().isoformat(),
            'messages': [],
            'context': {
                'current_mission': 'general',
                'entity_history': [],
                'query_patterns': [],
                'investigation_thread': None
            },
            'query_history': [],
            'performance_stats': {
                'queries_count': 0,
                'avg_processing_time': 0,
                'context_switches': 0
            }
        }
        return self.sessions[session_id]

    def add_message(self, session_id: str, query_analysis: Dict, results: Dict) -> None:
        """Add message with enhanced context tracking"""
        if session_id not in self.sessions:
            self.create_session(session_id)
        
        session = self.sessions[session_id]
        
        # Add to message history
        message_entry = {
            'timestamp': datetime.now().isoformat(),
            'query': query_analysis['original_query'],
            'intent': query_analysis['intent'],
            'entities': [e['term'] for e in query_analysis['entities']],
            'results_count': results['total_hits'],
            'processing_time': query_analysis['processing_time']
        }
        
        session['messages'].append(message_entry)
        session['query_history'].append(query_analysis)
        
        # Update context
        self._update_context(session, query_analysis, results)
        
        # Update performance stats
        self._update_performance_stats(session, query_analysis)
        
        # Update global context
        self.global_context['total_queries'] += 1

    def _update_context(self, session: Dict, query_analysis: Dict, results: Dict) -> None:
        """Update session context with intelligence"""
        context = session['context']
        
        # Track entity usage patterns
        for entity in query_analysis['entities']:
            entity_term = entity['term']
            if entity_term not in context['entity_history']:
                context['entity_history'].append(entity_term)
            else:
                # Move to end (recent usage)
                context['entity_history'].remove(entity_term)
                context['entity_history'].append(entity_term)
        
        # Keep only last 10 entities
        context['entity_history'] = context['entity_history'][-10:]
        
        # Track query patterns
        pattern = {
            'intent': query_analysis['intent'],
            'entity_count': len(query_analysis['entities']),
            'priority': query_analysis['priority'],
            'has_time_context': bool(query_analysis.get('time_range')),
            'has_mission_context': bool(query_analysis.get('mission_context'))
        }
        context['query_patterns'].append(pattern)
        
        # Keep only last 5 patterns
        context['query_patterns'] = context['query_patterns'][-5:]
        
        # Update mission context if detected
        if query_analysis.get('mission_context'):
            new_mission = query_analysis['mission_context']['mission']
            if context['current_mission'] != new_mission:
                context['current_mission'] = new_mission
                session['performance_stats']['context_switches'] += 1

    def _update_performance_stats(self, session: Dict, query_analysis: Dict) -> None:
        """Update performance statistics"""
        stats = session['performance_stats']
        stats['queries_count'] += 1
        
        # Update average processing time
        current_avg = stats['avg_processing_time']
        new_time = query_analysis['processing_time']
        stats['avg_processing_time'] = (
            (current_avg * (stats['queries_count'] - 1) + new_time) / stats['queries_count']
        )

    def get_context_for_query(self, session_id: str) -> Dict:
        """Get enhanced context for query processing"""
        if session_id not in self.sessions:
            return {'current_mission': 'general'}
        
        session = self.sessions[session_id]
        context = session['context'].copy()
        
        # Add recent query insights
        if session['query_history']:
            recent_queries = session['query_history'][-3:]
            context['recent_intents'] = [q['intent'] for q in recent_queries]
            context['recent_entities'] = []
            for q in recent_queries:
                context['recent_entities'].extend([e['term'] for e in q['entities']])
        
        return context


class EnhancedResponseFormatter:
    """Enhanced response formatter with rich visualizations"""
    
    def __init__(self):
        self.visualization_templates = {
            'timeline': self._create_timeline_viz,
            'bar_chart': self._create_bar_chart_viz,
            'table': self._create_table_viz,
            'heatmap': self._create_heatmap_viz,
            'network_graph': self._create_network_viz
        }

    def format_response(self, query_analysis: Dict, results: Dict, context: Dict = None) -> Dict:
        """Format comprehensive response with visualizations"""
        formatted_response = {
            'success': True,
            'query_analysis': {
                'intent': query_analysis['intent'],
                'entities': [e['term'] for e in query_analysis['entities']],
                'confidence': query_analysis['confidence'],
                'priority': query_analysis['priority'],
                'processing_time': query_analysis['processing_time']
            },
            'results_summary': self._generate_summary(results, query_analysis),
            'data': results['data'][:10],  # Limit for UI display
            'total_results': results['total_hits'],
            'visualizations': self._suggest_visualizations(results, query_analysis),
            'insights': self._generate_insights(results, query_analysis),
            'follow_up_suggestions': query_analysis.get('follow_up_suggestions', []),
            'context_info': self._format_context_info(context),
            'performance': {
                'query_time': results.get('took', 0),
                'processing_time': query_analysis['processing_time'],
                'data_source': results.get('query_metadata', {}).get('data_type', 'unknown')
            }
        }
        
        return formatted_response

    def _generate_summary(self, results: Dict, query_analysis: Dict) -> str:
        """Generate intelligent summary of results"""
        total = results['total_hits']
        data_type = results.get('query_metadata', {}).get('data_type', 'events')
        
        if total == 0:
            return f"No {data_type.replace('_', ' ')} found matching your criteria. Consider broadening your search parameters."
        
        summary = f"Found {total} {data_type.replace('_', ' ')}"
        
        # Add context based on priority
        if query_analysis['priority'] == 'CRITICAL':
            critical_count = sum(1 for item in results['data'] 
                               if item.get('event.severity') in ['critical', 'high'])
            if critical_count > 0:
                summary += f", including {critical_count} critical incidents requiring immediate attention"
        
        # Add mission context if present
        if query_analysis.get('mission_context'):
            mission = query_analysis['mission_context']['mission']
            summary += f" related to {mission} mission operations"
        
        # Add time context
        if query_analysis.get('time_range'):
            time_phrase = query_analysis['time_range']['phrase']
            summary += f" from {time_phrase}"
        
        return summary + "."

    def _suggest_visualizations(self, results: Dict, query_analysis: Dict) -> List[Dict]:
        """Suggest appropriate visualizations"""
        suggestions = []
        total_results = results['total_hits']
        
        if total_results > 20:
            suggestions.append({
                'type': 'timeline',
                'title': 'Event Timeline',
                'description': 'Chronological view of security events'
            })
        
        if total_results > 5:
            suggestions.append({
                'type': 'bar_chart',
                'title': 'Distribution Analysis',
                'description': 'Event distribution by category/severity'
            })
        
        if query_analysis['intent'] == 'analyze':
            suggestions.append({
                'type': 'heatmap',
                'title': 'Risk Heatmap',
                'description': 'Visual risk assessment across systems'
            })
        
        # Always suggest table for detailed view
        suggestions.append({
            'type': 'table',
            'title': 'Detailed Results',
            'description': 'Comprehensive tabular view of all events'
        })
        
        return suggestions

    def _generate_insights(self, results: Dict, query_analysis: Dict) -> List[str]:
        """Generate actionable insights from results"""
        insights = []
        data = results['data']
        
        if not data:
            return ["No data available for insight generation"]
        
        # Severity analysis
        critical_events = [item for item in data if item.get('event.severity') == 'critical']
        if critical_events:
            insights.append(f"🚨 {len(critical_events)} critical security events require immediate investigation")
        
        # Source IP analysis
        source_ips = set()
        for item in data:
            if 'source.ip' in item:
                source_ips.add(item['source.ip'])
        
        if len(source_ips) > 3:
            insights.append(f"🌐 Multiple source IPs ({len(source_ips)}) detected - possible coordinated attack")
        
        # Mission impact analysis
        missions_affected = set()
        for item in data:
            if 'mission.name' in item:
                missions_affected.add(item['mission.name'])
        
        if missions_affected:
            insights.append(f"🚀 {len(missions_affected)} active missions potentially affected")
        
        # Time pattern analysis
        if len(data) > 5:
            insights.append("📊 Event clustering detected - recommend timeline analysis")
        
        return insights[:4]  # Limit to top 4 insights

    def _format_context_info(self, context: Dict) -> Dict:
        """Format context information for response"""
        if not context:
            return {}
        
        return {
            'current_mission': context.get('current_mission', 'general'),
            'entity_history': context.get('entity_history', [])[-5:],  # Last 5 entities
            'recent_intents': context.get('recent_intents', []),
            'context_switches': context.get('context_switches', 0)
        }

    def _create_timeline_viz(self, data: List[Dict]) -> Dict:
        """Create timeline visualization data"""
        # Implementation would create timeline visualization data
        pass

    def _create_bar_chart_viz(self, data: List[Dict]) -> Dict:
        """Create bar chart visualization data"""
        # Implementation would create bar chart data
        pass

    def _create_table_viz(self, data: List[Dict]) -> Dict:
        """Create table visualization data"""
        # Implementation would create formatted table data
        pass

    def _create_heatmap_viz(self, data: List[Dict]) -> Dict:
        """Create heatmap visualization data"""
        # Implementation would create heatmap data
        pass

    def _create_network_viz(self, data: List[Dict]) -> Dict:
        """Create network graph visualization data"""
        # Implementation would create network graph data
        pass


# Initialize enhanced components
nlp_processor = ISRONLPProcessor()
siem_connector = ISROSIEMConnector()
context_manager = EnhancedContextManager()
response_formatter = EnhancedResponseFormatter()

# Enhanced API endpoints
@app.route('/api/health', methods=['GET'])
def health_check():
    """Enhanced health check with system status"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'service': 'ISRO SIEM Assistant API',
        'version': '2.0.0',
        'components': {
            'nlp_processor': 'operational',
            'siem_connector': 'operational',
            'context_manager': 'operational',
            'response_formatter': 'operational'
        },
        'performance': {
            'total_queries_processed': context_manager.global_context['total_queries'],
            'avg_response_time': context_manager.global_context['performance_metrics']['avg_response_time'],
            'accuracy_rate': context_manager.global_context['performance_metrics']['accuracy_rate']
        }
    })

@app.route('/api/query', methods=['POST'])
def process_enhanced_query():
    """Process enhanced natural language query with full ISRO context"""
    try:
        data = request.json
        query = data.get('query', '')
        session_id = data.get('session_id', str(uuid.uuid4()))
        
        if not query.strip():
            return jsonify({
                'success': False,
                'error': 'Empty query provided'
            }), 400
        
        # Get session context
        session_context = context_manager.get_context_for_query(session_id)
        
        # Enhanced NLP parsing
        query_analysis = nlp_processor.parse_query(query, session_context)
        
        # Execute query against mock SIEM
        results = siem_connector.execute_query(query_analysis)
        
        # Format enhanced response
        formatted_response = response_formatter.format_response(
            query_analysis, results, session_context
        )
        
        # Update context
        context_manager.add_message(session_id, query_analysis, results)
        
        return jsonify({
            'success': True,
            'session_id': session_id,
            'query': {
                'original': query,
                'kql': query_analysis['kql_query'],
                'elasticsearch_dsl': query_analysis['elasticsearch_dsl'],
                'explanation': query_analysis['explanation']
            },
            'response': formatted_response,
            'metadata': {
                'processing_time': query_analysis['processing_time'],
                'confidence': query_analysis['confidence'],
                'data_source': 'mock_isro_siem'
            }
        })
    
    except Exception as e:
        logger.error(f"Error processing enhanced query: {str(e)}")
        return jsonify({
            'success': False,
            'error': f'Query processing failed: {str(e)}',
            'suggestions': [
                'Try simplifying your query',
                'Check for spelling errors',
                'Use specific ISRO mission names (chandrayaan, aditya, gaganyaan)'
            ]
        }), 500

@app.route('/api/context/<session_id>', methods=['GET'])
def get_enhanced_context(session_id: str):
    """Get enhanced conversation context"""
    context = context_manager.get_context_for_query(session_id)
    
    if session_id in context_manager.sessions:
        session = context_manager.sessions[session_id]
        return jsonify({
            'session_id': session_id,
            'context': context,
            'statistics': session['performance_stats'],
            'message_count': len(session['messages']),
            'created_at': session['created_at']
        })
    else:
        return jsonify({
            'session_id': session_id,
            'context': context,
            'message': 'New session - no history available'
        })

@app.route('/api/report/generate', methods=['POST'])
def generate_enhanced_report():
    """Generate enhanced security report with ISRO context"""
    try:
        data = request.json
        report_type = data.get('type', 'comprehensive')
        time_range = data.get('time_range', 'last_24_hours')
        mission_filter = data.get('mission', None)
        
        # Generate comprehensive report
        report_data = {
            'report_metadata': {
                'title': f'ISRO Security Analysis Report - {datetime.now().strftime("%Y-%m-%d")}',
                'generated_at': datetime.now().isoformat(),
                'report_type': report_type,
                'time_range': time_range,
                'mission_scope': mission_filter or 'All ISRO Operations'
            },
            'executive_summary': {
                'total_events_analyzed': 15847,
                'critical_incidents': 12,
                'high_priority_alerts': 45,
                'threats_mitigated': 156,
                'missions_monitored': ['Chandrayaan-3', 'Aditya-L1', 'PSLV-C58', 'NavIC'],
                'security_posture': 'GOOD',
                'recommendations_count': 8
            },
            'threat_landscape': {
                'top_threats': [
                    {
                        'name': 'Nation State APT Groups',
                        'incidents': 45,
                        'trend': 'increasing',
                        'target_systems': ['satellite_comm', 'ground_stations'],
                        'risk_level': 'critical'
                    },
                    {
                        'name': 'Satellite Signal Jamming',
                        'incidents': 23,
                        'trend': 'stable',
                        'target_systems': ['communication_satellites'],
                        'risk_level': 'high'
                    },
                    {
                        'name': 'Ground Station Intrusion',
                        'incidents': 18,
                        'trend': 'decreasing',
                        'target_systems': ['ground_control', 'mission_control'],
                        'risk_level': 'medium'
                    }
                ]
            },
            'mission_security_status': {
                'chandrayaan-3': {
                    'status': 'secure',
                    'events': 1247,
                    'critical_incidents': 2,
                    'last_incident': '3 days ago'
                },
                'aditya-l1': {
                    'status': 'monitoring',
                    'events': 856,
                    'critical_incidents': 1,
                    'last_incident': '1 day ago'
                },
                'gaganyaan': {
                    'status': 'secure',
                    'events': 542,
                    'critical_incidents': 0,
                    'last_incident': 'none'
                }
            },
            'recommendations': [
                {
                    'priority': 'critical',
                    'title': 'Enhance Satellite Communication Encryption',
                    'description': 'Implement quantum-resistant encryption for satellite communications',
                    'timeline': '30 days',
                    'impact': 'high'
                },
                {
                    'priority': 'high',
                    'title': 'Zero-Trust Architecture for Ground Stations',
                    'description': 'Deploy zero-trust security model across all ground stations',
                    'timeline': '60 days',
                    'impact': 'high'
                },
                {
                    'priority': 'medium',
                    'title': 'Advanced Threat Detection',
                    'description': 'Implement AI-powered threat detection for space operations',
                    'timeline': '90 days',
                    'impact': 'medium'
                }
            ],
            'compliance_status': {
                'iso_27001': 'compliant',
                'government_security_standards': 'compliant',
                'space_security_protocols': 'under_review',
                'last_audit': '2024-12-15'
            }
        }
        
        return jsonify({
            'success': True,
            'report': report_data,
            'export_formats': ['pdf', 'excel', 'json'],
            'generated_at': datetime.now().isoformat()
        })
    
    except Exception as e:
        logger.error(f"Error generating report: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/clarify', methods=['POST'])
def handle_query_clarification():
    """Handle ambiguous queries with intelligent clarification"""
    try:
        data = request.json
        query = data.get('query', '')
        context = data.get('context', {})
        
        # Analyze query for ambiguity
        ambiguity_analysis = _analyze_query_ambiguity(query)
        
        if ambiguity_analysis['needs_clarification']:
            return jsonify({
                'success': True,
                'needs_clarification': True,
                'ambiguous_terms': ambiguity_analysis['ambiguous_terms'],
                'clarification_options': ambiguity_analysis['options'],
                'suggestions': ambiguity_analysis['suggestions'],
                'original_query': query
            })
        else:
            return jsonify({
                'success': True,
                'needs_clarification': False,
                'message': 'Query is sufficiently clear for processing'
            })
    
    except Exception as e:
        logger.error(f"Error in clarification: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/performance', methods=['GET'])
def get_performance_metrics():
    """Get real-time performance metrics"""
    # Simulate realistic performance data
    performance_data = {
        'current_metrics': {
            'query_response_time': round(random.uniform(0.8, 2.5), 2),
            'translation_accuracy': random.randint(90, 96),
            'context_retention': random.randint(95, 99),
            'active_sessions': random.randint(10, 25),
            'system_load': {
                'cpu': random.randint(15, 35),
                'memory': random.randint(40, 60),
                'disk_io': random.randint(10, 25)
            }
        },
        'siem_connectivity': {
            'elastic_siem': {
                'status': 'online' if random.random() > 0.05 else 'reconnecting',
                'last_ping': datetime.now().isoformat(),
                'response_time': round(random.uniform(50, 200), 1)
            },
            'wazuh': {
                'status': 'online' if random.random() > 0.1 else 'offline',
                'last_ping': datetime.now().isoformat(),
                'response_time': round(random.uniform(75, 250), 1)
            }
        },
        'trend_data': {
            'queries_per_hour': [12, 15, 18, 22, 19, 25, 30, 28, 24, 20],
            'accuracy_trend': [92, 93, 94, 95, 94, 95, 96, 95, 94, 95],
            'response_time_trend': [1.2, 1.1, 1.3, 1.0, 1.2, 1.1, 1.4, 1.2, 1.1, 1.3]
        }
    }
    
    return jsonify({
        'success': True,
        'timestamp': datetime.now().isoformat(),
        'performance': performance_data
    })

@app.route('/api/missions', methods=['GET'])
def get_mission_contexts():
    """Get available ISRO mission contexts"""
    mission_data = {
        'active_missions': {
            'chandrayaan-3': {
                'name': 'Chandrayaan-3 Lunar Mission',
                'status': 'active',
                'phase': 'surface_operations',
                'priority_level': 'critical',
                'launch_date': '2023-07-14',
                'key_systems': ['lander', 'rover', 'ground_stations'],
                'security_classification': 'restricted'
            },
            'aditya-l1': {
                'name': 'Aditya-L1 Solar Observatory',
                'status': 'active',
                'phase': 'l1_operations',
                'priority_level': 'critical',
                'launch_date': '2023-09-02',
                'key_systems': ['spacecraft', 'instruments', 'deep_space_network'],
                'security_classification': 'restricted'
            },
            'gaganyaan': {
                'name': 'Gaganyaan Human Spaceflight',
                'status': 'development',
                'phase': 'pre_flight_testing',
                'priority_level': 'critical',
                'expected_launch': '2025',
                'key_systems': ['crew_module', 'life_support', 'abort_systems'],
                'security_classification': 'confidential'
            }
        },
        'infrastructure': {
            'ground_stations': [
                {'name': 'VSSC Thumba', 'location': 'Kerala', 'status': 'operational'},
                {'name': 'SHAR Sriharikota', 'location': 'Andhra Pradesh', 'status': 'operational'},
                {'name': 'ISTRAC Hassan', 'location': 'Karnataka', 'status': 'operational'},
                {'name': 'NRSC Hyderabad', 'location': 'Telangana', 'status': 'operational'}
            ],
            'mission_control_centers': [
                {'name': 'Mission Control Bangalore', 'facility': 'ISAC', 'status': 'operational'},
                {'name': 'Launch Control SHAR', 'facility': 'SDSC', 'status': 'operational'},
                {'name': 'Satellite Control Facility', 'facility': 'MCF Hassan', 'status': 'operational'}
            ]
        }
    }
    
    return jsonify({
        'success': True,
        'missions': mission_data,
        'last_updated': datetime.now().isoformat()
    })

def _analyze_query_ambiguity(query: str) -> Dict:
    """Analyze query for ambiguous terms and suggest clarifications"""
    ambiguous_patterns = {
        'unusual activity': {
            'options': [
                'Network traffic anomalies',
                'User behavior anomalies',
                'System performance anomalies',
                'Communication pattern anomalies'
            ],
            'suggestions': [
                'Specify the type of activity (network, user, system)',
                'Include time frame for analysis',
                'Mention specific systems or missions'
            ]
        },
        'security issues': {
            'options': [
                'Authentication failures',
                'Malware detections',
                'Network intrusions',
                'Data breach attempts',
                'Privilege escalations'
            ],
            'suggestions': [
                'Be specific about the type of security concern',
                'Include severity level if known',
                'Mention affected systems or missions'
            ]
        },
        'problems': {
            'options': [
                'Critical security alerts',
                'System failures',
                'Performance issues',
                'Communication disruptions'
            ],
            'suggestions': [
                'Describe the specific problem type',
                'Include impact assessment',
                'Specify affected systems'
            ]
        },
        'anomalies': {
            'options': [
                'Statistical anomalies in data',
                'Behavioral anomalies in users',
                'Network traffic anomalies',
                'Mission timeline anomalies'
            ],
            'suggestions': [
                'Specify the type of anomaly',
                'Include detection timeframe',
                'Mention baseline for comparison'
            ]
        }
    }
    
    query_lower = query.lower()
    detected_ambiguities = []
    
    for pattern, details in ambiguous_patterns.items():
        if pattern in query_lower:
            detected_ambiguities.append({
                'term': pattern,
                'options': details['options'],
                'suggestions': details['suggestions']
            })
    
    return {
        'needs_clarification': len(detected_ambiguities) > 0,
        'ambiguous_terms': [amb['term'] for amb in detected_ambiguities],
        'options': detected_ambiguities[0]['options'] if detected_ambiguities else [],
        'suggestions': detected_ambiguities[0]['suggestions'] if detected_ambiguities else []
    }

@app.route('/api/export/<session_id>', methods=['POST'])
def export_conversation(session_id: str):
    """Export conversation data in various formats"""
    try:
        data = request.json
        export_format = data.get('format', 'json')
        
        if session_id not in context_manager.sessions:
            return jsonify({
                'success': False,
                'error': 'Session not found'
            }), 404
        
        session = context_manager.sessions[session_id]
        
        export_data = {
            'session_metadata': {
                'session_id': session_id,
                'created_at': session['created_at'],
                'total_queries': len(session['messages']),
                'mission_context': session['context']['current_mission']
            },
            'conversation_history': session['messages'],
            'performance_statistics': session['performance_stats'],
            'context_evolution': session['context'],
            'export_metadata': {
                'exported_at': datetime.now().isoformat(),
                'format': export_format,
                'version': '2.0'
            }
        }
        
        return jsonify({
            'success': True,
            'export_data': export_data,
            'download_ready': True,
            'format': export_format
        })
    
    except Exception as e:
        logger.error(f"Error exporting conversation: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({
        'success': False,
        'error': 'Endpoint not found',
        'available_endpoints': [
            '/api/health',
            '/api/query',
            '/api/context/<session_id>',
            '/api/report/generate',
            '/api/clarify',
            '/api/performance',
            '/api/missions'
        ]
    }), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({
        'success': False,
        'error': 'Internal server error',
        'message': 'An unexpected error occurred. Please try again.'
    }), 500

# Request logging middleware
@app.before_request
def log_request():
    logger.info(f"Request: {request.method} {request.path} - {request.remote_addr}")

@app.after_request
def log_response(response):
    logger.info(f"Response: {response.status_code} - {request.path}")
    return response

if __name__ == '__main__':
    logger.info("Starting Enhanced ISRO SIEM Assistant API")
    logger.info("Features: NLP Processing, Multi-turn Conversations, ISRO Mission Context")
    app.run(debug=True, host='0.0.0.0', port=5000)