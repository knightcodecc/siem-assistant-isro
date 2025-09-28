"""
Conversational SIEM Assistant Backend API
NLP-Powered Security Investigation & Automated Threat Reporting
Direct ELK SIEM Integration with Multi-turn Context Awareness
"""

from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from flask_socketio import SocketIO, emit, join_room
from datetime import datetime, timedelta
import json
import re
import uuid
import logging
from typing import Dict, List, Any, Optional, Tuple
import time
import random
import os
import io
from functools import wraps
from dataclasses import dataclass
import asyncio
from concurrent.futures import ThreadPoolExecutor

# Enhanced NLP imports
import spacy
try:
    from transformers import pipeline, AutoTokenizer, AutoModel
except ImportError:
    print("Warning: transformers not available, using basic NLP")
    pipeline = None

import torch
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

# SIEM Integration imports
try:
    from elasticsearch import Elasticsearch, exceptions as es_exceptions
    from elasticsearch.helpers import scan
except ImportError:
    print("Warning: elasticsearch-py not available")
    Elasticsearch = None

import requests
from requests.auth import HTTPBasicAuth
import ssl
import urllib3

# Input validation
from marshmallow import Schema, fields, validate, ValidationError

# Suppress SSL warnings for demo
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'siem-assistant-secret-key')
CORS(app, origins=["*"])
socketio = SocketIO(app, cors_allowed_origins="*")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('siem_assistant.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class SIEMConfig:
    """SIEM configuration for real integration"""
    elasticsearch_hosts: List[str]
    elasticsearch_username: str
    elasticsearch_password: str
    wazuh_api_url: str
    wazuh_username: str
    wazuh_password: str
    index_patterns: Dict[str, str]
    ssl_verify: bool = False
    timeout: int = 30
    
    @classmethod
    def from_env(cls):
        return cls(
            elasticsearch_hosts=os.getenv('ELASTIC_HOSTS', 'localhost:9200').split(','),
            elasticsearch_username=os.getenv('ELASTIC_USER', 'elastic'),
            elasticsearch_password=os.getenv('ELASTIC_PASSWORD', 'changeme'),
            wazuh_api_url=os.getenv('WAZUH_API_URL', 'https://localhost:55000'),
            wazuh_username=os.getenv('WAZUH_USER', 'wazuh'),
            wazuh_password=os.getenv('WAZUH_PASSWORD', 'wazuh'),
            index_patterns={
                'security': os.getenv('SECURITY_INDEX', 'security-*'),
                'network': os.getenv('NETWORK_INDEX', 'network-*'),
                'authentication': os.getenv('AUTH_INDEX', 'auth-*'),
                'malware': os.getenv('MALWARE_INDEX', 'malware-*'),
                'endpoint': os.getenv('ENDPOINT_INDEX', 'endpoint-*'),
                'web': os.getenv('WEB_INDEX', 'web-*')
            }
        )

class AdvancedNLPProcessor:
    """Advanced Natural Language Processor for SIEM queries"""
    
    def __init__(self):
        self.initialize_models()
        self.initialize_entity_mappings()
        self.initialize_context_analyzer()
        
    def initialize_models(self):
        """Initialize NLP models for entity extraction and intent classification"""
        try:
            # Load spaCy model for NER
            self.nlp = spacy.load("en_core_web_sm")
            logger.info("spaCy model loaded successfully")
        except OSError:
            logger.warning("spaCy model not found, using basic processing")
            self.nlp = None
            
        # Initialize TF-IDF vectorizer for semantic similarity
        self.tfidf_vectorizer = TfidfVectorizer(
            max_features=2000,
            stop_words='english',
            ngram_range=(1, 2)
        )
        
        # Intent classification patterns
        self.intent_patterns = {
            'search': ['show', 'list', 'find', 'get', 'display', 'what', 'which', 'where'],
            'analyze': ['analyze', 'investigate', 'examine', 'study', 'review'],
            'report': ['generate', 'create', 'report', 'summary', 'compile'],
            'filter': ['filter', 'only', 'exclude', 'where', 'specific'],
            'count': ['how many', 'count', 'number of', 'total']
        }
        
    def initialize_entity_mappings(self):
        """Initialize security entity mappings for SIEM translation"""
        self.entity_mappings = {
            # Authentication Events
            'failed login': {
                'kql': 'event.outcome:failure AND event.category:authentication',
                'elasticsearch_dsl': {
                    'bool': {
                        'must': [
                            {'match': {'event.outcome': 'failure'}},
                            {'match': {'event.category': 'authentication'}}
                        ]
                    }
                },
                'category': 'authentication',
                'description': 'Failed authentication attempts',
                'aliases': ['login failures', 'authentication failures', 'failed logons']
            },
            
            'successful login': {
                'kql': 'event.outcome:success AND event.category:authentication',
                'elasticsearch_dsl': {
                    'bool': {
                        'must': [
                            {'match': {'event.outcome': 'success'}},
                            {'match': {'event.category': 'authentication'}}
                        ]
                    }
                },
                'category': 'authentication',
                'description': 'Successful authentication events'
            },
            
            'mfa attempts': {
                'kql': 'event.action:(mfa OR "multi-factor") AND event.category:authentication',
                'elasticsearch_dsl': {
                    'bool': {
                        'must': [
                            {'query_string': {'query': 'mfa OR "multi-factor"'}},
                            {'match': {'event.category': 'authentication'}}
                        ]
                    }
                },
                'category': 'authentication',
                'description': 'Multi-factor authentication events'
            },
            
            # Malware Events
            'malware detection': {
                'kql': 'event.category:(malware OR virus) AND event.action:detected',
                'elasticsearch_dsl': {
                    'bool': {
                        'should': [
                            {'match': {'event.category': 'malware'}},
                            {'match': {'event.category': 'virus'}}
                        ],
                        'must': [{'match': {'event.action': 'detected'}}]
                    }
                },
                'category': 'malware',
                'description': 'Malware detection events'
            },
            
            'virus activity': {
                'kql': 'threat.indicator.type:virus OR event.category:virus',
                'elasticsearch_dsl': {
                    'bool': {
                        'should': [
                            {'match': {'threat.indicator.type': 'virus'}},
                            {'match': {'event.category': 'virus'}}
                        ]
                    }
                },
                'category': 'malware',
                'description': 'Virus-related security events'
            },
            
            # Network Events
            'network anomaly': {
                'kql': 'event.category:network AND (tags:anomaly OR event.action:blocked)',
                'elasticsearch_dsl': {
                    'bool': {
                        'must': [{'match': {'event.category': 'network'}}],
                        'should': [
                            {'match': {'tags': 'anomaly'}},
                            {'match': {'event.action': 'blocked'}}
                        ],
                        'minimum_should_match': 1
                    }
                },
                'category': 'network',
                'description': 'Network anomalies and suspicious traffic'
            },
            
            'vpn connection': {
                'kql': 'service.name:vpn OR event.dataset:vpn',
                'elasticsearch_dsl': {
                    'bool': {
                        'should': [
                            {'match': {'service.name': 'vpn'}},
                            {'match': {'event.dataset': 'vpn'}}
                        ]
                    }
                },
                'category': 'network',
                'description': 'VPN connection events'
            },
            
            'firewall block': {
                'kql': 'event.action:blocked AND event.category:network',
                'elasticsearch_dsl': {
                    'bool': {
                        'must': [
                            {'match': {'event.action': 'blocked'}},
                            {'match': {'event.category': 'network'}}
                        ]
                    }
                },
                'category': 'network',
                'description': 'Firewall blocked connections'
            },
            
            # Web/HTTP Events
            'web attack': {
                'kql': 'event.category:web AND (http.response.status_code:>=400 OR tags:attack)',
                'elasticsearch_dsl': {
                    'bool': {
                        'must': [{'match': {'event.category': 'web'}}],
                        'should': [
                            {'range': {'http.response.status_code': {'gte': 400}}},
                            {'match': {'tags': 'attack'}}
                        ],
                        'minimum_should_match': 1
                    }
                },
                'category': 'web',
                'description': 'Web-based attacks and suspicious HTTP activity'
            },
            
            'sql injection': {
                'kql': 'event.category:web AND (url.query:*sql* OR message:*injection*)',
                'elasticsearch_dsl': {
                    'bool': {
                        'must': [{'match': {'event.category': 'web'}}],
                        'should': [
                            {'wildcard': {'url.query': '*sql*'}},
                            {'wildcard': {'message': '*injection*'}}
                        ]
                    }
                },
                'category': 'web',
                'description': 'SQL injection attempts'
            }
        }
        
        # Build reverse mapping for aliases
        self.alias_to_entity = {}
        for entity, data in self.entity_mappings.items():
            aliases = data.get('aliases', [])
            for alias in aliases:
                self.alias_to_entity[alias.lower()] = entity
                
    def initialize_context_analyzer(self):
        """Initialize context analysis patterns"""
        self.temporal_patterns = {
            'yesterday': {'gte': 'now-1d/d', 'lt': 'now/d'},
            'today': {'gte': 'now/d', 'lt': 'now'},
            'last 24 hours': {'gte': 'now-24h', 'lt': 'now'},
            'last hour': {'gte': 'now-1h', 'lt': 'now'},
            'last week': {'gte': 'now-7d', 'lt': 'now'},
            'this week': {'gte': 'now/w', 'lt': 'now'},
            'last month': {'gte': 'now-30d', 'lt': 'now'},
            'this month': {'gte': 'now/M', 'lt': 'now'}
        }
        
        self.continuation_markers = [
            'then', 'also', 'and', 'additionally', 'furthermore',
            'filter', 'only', 'exclude', 'where', 'that', 'those'
        ]
        
    def parse_query(self, query: str, context: Dict = None) -> Dict[str, Any]:
        """Parse natural language query and extract SIEM-relevant information"""
        start_time = time.time()
        
        # Preprocess query
        processed_query = self.preprocess_query(query)
        
        # Extract entities
        entities = self.extract_entities(processed_query)
        
        # Detect intent
        intent = self.detect_intent(processed_query)
        
        # Extract time range
        time_range = self.extract_time_range(processed_query)
        
        # Analyze context continuity
        context_analysis = self.analyze_context_continuity(processed_query, context)
        
        # Calculate confidence
        confidence = self.calculate_confidence(entities, intent, time_range)
        
        # Build queries
        kql_query = self.build_kql_query(entities, time_range, intent)
        elasticsearch_dsl = self.build_elasticsearch_dsl(entities, time_range, intent)
        
        processing_time = time.time() - start_time
        
        return {
            'original_query': query,
            'processed_query': processed_query,
            'entities': entities,
            'intent': intent,
            'time_range': time_range,
            'context_analysis': context_analysis,
            'confidence': confidence,
            'kql_query': kql_query,
            'elasticsearch_dsl': elasticsearch_dsl,
            'processing_time': round(processing_time, 3),
            'suggestions': self.generate_suggestions(entities, intent)
        }
    
    def preprocess_query(self, query: str) -> str:
        """Preprocess query for better analysis"""
        # Normalize whitespace
        query = re.sub(r'\s+', ' ', query.strip())
        
        # Convert common abbreviations
        replacements = {
            'auth': 'authentication',
            'login': 'authentication',
            'logon': 'authentication',
            'sec': 'security',
            'net': 'network',
            'conn': 'connection'
        }
        
        for abbrev, full_form in replacements.items():
            query = re.sub(r'\b' + abbrev + r'\b', full_form, query, flags=re.IGNORECASE)
        
        return query
    
    def extract_entities(self, query: str) -> List[Dict]:
        """Extract security entities from query"""
        entities = []
        query_lower = query.lower()
        
        # Direct entity matching
        for entity_term, mapping in self.entity_mappings.items():
            if entity_term.lower() in query_lower:
                entities.append({
                    'term': entity_term,
                    'category': mapping['category'],
                    'description': mapping['description'],
                    'kql': mapping['kql'],
                    'elasticsearch_dsl': mapping['elasticsearch_dsl'],
                    'confidence': 0.9
                })
        
        # Alias matching
        for alias, original_entity in self.alias_to_entity.items():
            if alias in query_lower and not any(e['term'] == original_entity for e in entities):
                mapping = self.entity_mappings[original_entity]
                entities.append({
                    'term': original_entity,
                    'matched_alias': alias,
                    'category': mapping['category'],
                    'description': mapping['description'],
                    'kql': mapping['kql'],
                    'elasticsearch_dsl': mapping['elasticsearch_dsl'],
                    'confidence': 0.8
                })
        
        # Named Entity Recognition with spaCy
        if self.nlp:
            doc = self.nlp(query)
            for ent in doc.ents:
                if ent.label_ in ['ORG', 'PRODUCT', 'GPE']:
                    entities.append({
                        'term': ent.text,
                        'category': 'named_entity',
                        'spacy_label': ent.label_,
                        'confidence': 0.7
                    })
        
        return entities
    
    def detect_intent(self, query: str) -> Dict[str, Any]:
        """Detect user intent from query"""
        query_lower = query.lower()
        intent_scores = {}
        
        for intent, patterns in self.intent_patterns.items():
            score = 0
            for pattern in patterns:
                if pattern in query_lower:
                    score += 1
            
            if score > 0:
                intent_scores[intent] = score
        
        if not intent_scores:
            return {'primary': 'search', 'confidence': 0.5}
        
        primary_intent = max(intent_scores.items(), key=lambda x: x[1])[0]
        confidence = intent_scores[primary_intent] / sum(intent_scores.values())
        
        return {
            'primary': primary_intent,
            'confidence': confidence,
            'all_scores': intent_scores
        }
    
    def extract_time_range(self, query: str) -> Optional[Dict]:
        """Extract time range from query"""
        query_lower = query.lower()
        
        for time_phrase, es_range in self.temporal_patterns.items():
            if time_phrase in query_lower:
                return {
                    'phrase': time_phrase,
                    'elasticsearch_range': es_range,
                    'confidence': 0.9
                }
        
        # Extract relative time patterns
        relative_patterns = {
            r'(\d+)\s*hours?\s*ago': lambda m: {'gte': f'now-{m.group(1)}h', 'lt': 'now'},
            r'(\d+)\s*days?\s*ago': lambda m: {'gte': f'now-{m.group(1)}d', 'lt': 'now'},
            r'past\s*(\d+)\s*hours?': lambda m: {'gte': f'now-{m.group(1)}h', 'lt': 'now'},
            r'past\s*(\d+)\s*days?': lambda m: {'gte': f'now-{m.group(1)}d', 'lt': 'now'}
        }
        
        for pattern, range_func in relative_patterns.items():
            match = re.search(pattern, query_lower)
            if match:
                return {
                    'phrase': match.group(0),
                    'elasticsearch_range': range_func(match),
                    'confidence': 0.8
                }
        
        return None
    
    def analyze_context_continuity(self, query: str, context: Dict = None) -> Dict:
        """Analyze if query continues previous context"""
        if not context:
            return {'is_continuation': False, 'continuity_score': 0}
        
        query_lower = query.lower()
        continuity_score = 0
        
        # Check for continuation markers
        for marker in self.continuation_markers:
            if marker in query_lower:
                continuity_score += 1
        
        # Check for pronouns referring to previous context
        pronouns = ['it', 'that', 'those', 'them', 'this', 'these']
        for pronoun in pronouns:
            if pronoun in query_lower:
                continuity_score += 0.5
        
        return {
            'is_continuation': continuity_score > 0,
            'continuity_score': continuity_score,
            'should_inherit_context': continuity_score > 1
        }
    
    def calculate_confidence(self, entities: List, intent: Dict, time_range: Dict = None) -> float:
        """Calculate overall confidence score"""
        confidence = 0.0
        
        # Entity confidence
        if entities:
            entity_confidences = [e.get('confidence', 0) for e in entities]
            confidence += max(entity_confidences) * 0.5
        
        # Intent confidence
        confidence += intent.get('confidence', 0) * 0.3
        
        # Time range confidence
        if time_range:
            confidence += time_range.get('confidence', 0) * 0.2
        
        return min(confidence, 1.0)
    
    def build_kql_query(self, entities: List, time_range: Dict = None, intent: Dict = None) -> str:
        """Build KQL query from extracted information"""
        query_parts = []
        
        # Add entity queries
        for entity in entities:
            if 'kql' in entity:
                query_parts.append(f"({entity['kql']})")
        
        # Add time range
        if time_range:
            es_range = time_range['elasticsearch_range']
            time_kql = f"@timestamp:[{es_range.get('gte', 'now-24h')} TO {es_range.get('lt', 'now')}]"
            query_parts.append(time_kql)
        
        # Combine with AND if multiple parts
        if len(query_parts) > 1:
            return ' AND '.join(query_parts)
        elif query_parts:
            return query_parts[0]
        else:
            return 'event.category:security AND @timestamp:[now-24h TO now]'
    
    def build_elasticsearch_dsl(self, entities: List, time_range: Dict = None, intent: Dict = None) -> Dict:
        """Build Elasticsearch DSL query"""
        query_dsl = {
            "query": {
                "bool": {
                    "must": [],
                    "should": [],
                    "filter": []
                }
            },
            "sort": [{"@timestamp": {"order": "desc"}}],
            "size": 100
        }
        
        # Add entity queries
        for entity in entities:
            if 'elasticsearch_dsl' in entity:
                query_dsl["query"]["bool"]["must"].append({"bool": entity['elasticsearch_dsl']})
        
        # Add time range filter
        if time_range:
            es_range = time_range['elasticsearch_range']
            query_dsl["query"]["bool"]["filter"].append({
                "range": {
                    "@timestamp": es_range
                }
            })
        
        # Add aggregations based on intent
        if intent and intent['primary'] in ['report', 'analyze']:
            query_dsl["aggs"] = {
                "events_over_time": {
                    "date_histogram": {
                        "field": "@timestamp",
                        "fixed_interval": "1h"
                    }
                },
                "top_sources": {
                    "terms": {
                        "field": "source.ip",
                        "size": 10
                    }
                }
            }
        
        return query_dsl
    
    def generate_suggestions(self, entities: List, intent: Dict) -> List[str]:
        """Generate follow-up suggestions"""
        suggestions = []
        
        if entities:
            entity_names = [e['term'] for e in entities]
            if 'failed login' in entity_names:
                suggestions.extend([
                    'Show successful logins after these failures',
                    'Filter by specific user accounts',
                    'Analyze source IP patterns'
                ])
            elif 'malware detection' in entity_names:
                suggestions.extend([
                    'Show affected systems',
                    'Generate malware family analysis',
                    'Check related network connections'
                ])
        
        # Time-based suggestions
        suggestions.extend([
            'Expand time range for trend analysis',
            'Filter to specific time window',
            'Generate hourly breakdown'
        ])
        
        return suggestions[:5]  # Limit to 5 suggestions

class SIEMConnector:
    """SIEM connector for Elasticsearch and Wazuh integration"""
    
    def __init__(self, config: SIEMConfig):
        self.config = config
        self.elasticsearch_client = None
        self.wazuh_session = None
        self.initialize_connections()
    
    def initialize_connections(self):
        """Initialize connections to SIEM systems"""
        # Initialize Elasticsearch
        if Elasticsearch:
            try:
                self.elasticsearch_client = Elasticsearch(
                    hosts=self.config.elasticsearch_hosts,
                    basic_auth=(self.config.elasticsearch_username, self.config.elasticsearch_password),
                    verify_certs=self.config.ssl_verify,
                    timeout=self.config.timeout
                )
                
                # Test connection
                if self.elasticsearch_client.ping():
                    logger.info("Elasticsearch connection successful")
                else:
                    logger.warning("Elasticsearch ping failed")
                    
            except Exception as e:
                logger.error(f"Elasticsearch connection failed: {e}")
                self.elasticsearch_client = None
        
        # Initialize Wazuh connection
        try:
            self.wazuh_session = requests.Session()
            self.wazuh_session.verify = self.config.ssl_verify
            
            # Test authentication
            auth_url = f"{self.config.wazuh_api_url}/security/user/authenticate"
            response = self.wazuh_session.post(
                auth_url,
                auth=HTTPBasicAuth(self.config.wazuh_username, self.config.wazuh_password)
            )
            
            if response.status_code == 200:
                token_data = response.json().get('data', {})
                token = token_data.get('token')
                if token:
                    self.wazuh_session.headers.update({'Authorization': f'Bearer {token}'})
                    logger.info("Wazuh connection successful")
            else:
                logger.warning(f"Wazuh authentication failed: {response.status_code}")
                
        except Exception as e:
            logger.error(f"Wazuh connection failed: {e}")
            self.wazuh_session = None
    
    def execute_query(self, query_analysis: Dict) -> Dict:
        """Execute query against SIEM systems"""
        if self.elasticsearch_client:
            return self.execute_elasticsearch_query(query_analysis)
        else:
            return self.execute_mock_query(query_analysis)
    
    def execute_elasticsearch_query(self, query_analysis: Dict) -> Dict:
        """Execute query against Elasticsearch"""
        try:
            dsl_query = query_analysis['elasticsearch_dsl']
            
            # Determine index pattern
            entities = query_analysis.get('entities', [])
            index_pattern = self.determine_index_pattern(entities)
            
            # Execute search
            start_time = time.time()
            response = self.elasticsearch_client.search(
                index=index_pattern,
                body=dsl_query
            )
            query_time = time.time() - start_time
            
            # Extract results
            hits = response['hits']['hits']
            total_hits = response['hits']['total']['value']
            
            # Format results
            formatted_results = []
            for hit in hits:
                result = hit['_source']
                result['_id'] = hit['_id']
                result['_index'] = hit['_index']
                formatted_results.append(result)
            
            return {
                'success': True,
                'total_hits': total_hits,
                'results': formatted_results,
                'took': response['took'],
                'query_time': round(query_time, 3),
                'aggregations': response.get('aggregations', {}),
                'index_pattern': index_pattern
            }
            
        except Exception as e:
            logger.error(f"Elasticsearch query failed: {e}")
            return {
                'success': False,
                'error': str(e),
                'fallback_results': self.execute_mock_query(query_analysis)
            }
    
    def determine_index_pattern(self, entities: List) -> str:
        """Determine appropriate index pattern based on entities"""
        if not entities:
            return self.config.index_patterns.get('security', 'security-*')
        
        # Map entity categories to index patterns
        category_to_index = {
            'authentication': 'authentication',
            'malware': 'malware',
            'network': 'network',
            'web': 'web',
            'endpoint': 'endpoint'
        }
        
        for entity in entities:
            category = entity.get('category')
            if category in category_to_index:
                index_key = category_to_index[category]
                return self.config.index_patterns.get(index_key, 'security-*')
        
        return self.config.index_patterns.get('security', 'security-*')
    
    def execute_mock_query(self, query_analysis: Dict) -> Dict:
        """Execute mock query for demonstration"""
        # Simulate processing time
        processing_time = random.uniform(0.3, 1.5)
        time.sleep(processing_time / 10)  # Reduced for demo
        
        # Generate mock results based on entities
        entities = query_analysis.get('entities', [])
        mock_results = self.generate_mock_results(entities)
        
        return {
            'success': True,
            'total_hits': len(mock_results),
            'results': mock_results,
            'took': int(processing_time * 1000),
            'query_time': processing_time,
            'data_source': 'mock_data',
            'note': 'Using mock data - configure Elasticsearch connection for real data'
        }
    
    def generate_mock_results(self, entities: List) -> List[Dict]:
        """Generate realistic mock SIEM data"""
        mock_results = []
        
        if not entities:
            return mock_results
        
        # Generate results based on entity types
        for entity in entities[:2]:  # Limit to first 2 entities
            entity_type = entity.get('term', 'unknown')
            
            if 'login' in entity_type or 'authentication' in entity_type:
                mock_results.extend(self.generate_auth_events())
            elif 'malware' in entity_type or 'virus' in entity_type:
                mock_results.extend(self.generate_malware_events())
            elif 'network' in entity_type:
                mock_results.extend(self.generate_network_events())
            elif 'vpn' in entity_type:
                mock_results.extend(self.generate_vpn_events())
        
        # Sort by timestamp
        mock_results.sort(key=lambda x: x.get('@timestamp', ''), reverse=True)
        return mock_results[:20]  # Limit to 20 results
    
    def generate_auth_events(self) -> List[Dict]:
        """Generate mock authentication events"""
        events = []
        base_time = datetime.now()
        
        for i in range(5):
            event_time = base_time - timedelta(hours=i, minutes=random.randint(0, 59))
            events.append({
                '@timestamp': event_time.isoformat() + 'Z',
                'event.category': 'authentication',
                'event.outcome': random.choice(['failure', 'failure', 'success']),
                'event.action': 'login',
                'user.name': random.choice(['admin', 'user1', 'service_account', 'analyst']),
                'source.ip': f"192.168.1.{random.randint(100, 200)}",
                'host.name': f"workstation-{random.randint(1, 10):02d}",
                'user_agent.original': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            })
        
        return events
    
    def generate_malware_events(self) -> List[Dict]:
        """Generate mock malware detection events"""
        events = []
        base_time = datetime.now()
        
        for i in range(3):
            event_time = base_time - timedelta(hours=i*2, minutes=random.randint(0, 59))
            events.append({
                '@timestamp': event_time.isoformat() + 'Z',
                'event.category': 'malware',
                'event.action': 'detected',
                'file.name': random.choice(['suspicious.exe', 'malware.dll', 'trojan.bin']),
                'file.hash.sha256': f"{'0123456789abcdef' * 4}",
                'host.name': f"endpoint-{random.randint(1, 15):02d}",
                'threat.indicator.type': 'malware',
                'process.name': 'antivirus_scanner.exe'
            })
        
        return events
    
    def generate_network_events(self) -> List[Dict]:
        """Generate mock network events"""
        events = []
        base_time = datetime.now()
        
        for i in range(4):
            event_time = base_time - timedelta(minutes=i*15 + random.randint(0, 14))
            events.append({
                '@timestamp': event_time.isoformat() + 'Z',
                'event.category': 'network',
                'event.action': random.choice(['blocked', 'allowed', 'monitored']),
                'source.ip': f"203.0.113.{random.randint(1, 254)}",
                'destination.ip': f"192.168.1.{random.randint(1, 254)}",
                'destination.port': random.choice([80, 443, 22, 3389, 1433]),
                'network.bytes': random.randint(1024, 1048576),
                'tags': random.choice([['suspicious'], ['anomaly'], ['blocked'], []])
            })
        
        return events
    
    def generate_vpn_events(self) -> List[Dict]:
        """Generate mock VPN events"""
        events = []
        base_time = datetime.now()
        
        for i in range(3):
            event_time = base_time - timedelta(hours=i, minutes=random.randint(0, 59))
            events.append({
                '@timestamp': event_time.isoformat() + 'Z',
                'event.category': 'authentication',
                'event.action': 'vpn_connection',
                'event.outcome': random.choice(['success', 'failure']),
                'service.name': 'vpn',
                'user.name': f"user{random.randint(1, 100)}",
                'source.ip': f"203.0.113.{random.randint(1, 254)}",
                'destination.ip': '192.168.100.1',
                'network.protocol': 'openvpn'
            })
        
        return events

class ContextManager:
    """Manage conversation context for multi-turn queries"""
    
    def __init__(self):
        self.sessions = {}
    
    def create_session(self, session_id: str) -> Dict:
        """Create new conversation session"""
        self.sessions[session_id] = {
            'id': session_id,
            'created_at': datetime.now().isoformat(),
            'last_activity': datetime.now().isoformat(),
            'query_history': [],
            'context': {
                'active_entities': [],
                'time_context': None,
                'investigation_focus': None,
                'user_intent_pattern': []
            },
            'statistics': {
                'total_queries': 0,
                'successful_queries': 0,
                'avg_confidence': 0.0
            }
        }
        return self.sessions[session_id]
    
    def get_session(self, session_id: str) -> Optional[Dict]:
        """Get existing session or create new one"""
        if session_id not in self.sessions:
            return self.create_session(session_id)
        return self.sessions[session_id]
    
    def update_session(self, session_id: str, query_analysis: Dict, results: Dict):
        """Update session with new query information"""
        session = self.get_session(session_id)
        session['last_activity'] = datetime.now().isoformat()
        
        # Add to query history
        session['query_history'].append({
            'query': query_analysis['original_query'],
            'entities': query_analysis['entities'],
            'intent': query_analysis['intent'],
            'confidence': query_analysis['confidence'],
            'timestamp': datetime.now().isoformat(),
            'results_count': results.get('total_hits', 0)
        })
        
        # Update context
        entities = query_analysis.get('entities', [])
        if entities:
            # Keep track of active entities
            entity_terms = [e['term'] for e in entities]
            session['context']['active_entities'] = list(set(
                session['context']['active_entities'] + entity_terms
            ))[-5:]  # Keep last 5 unique entities
        
        # Update time context if present
        if query_analysis.get('time_range'):
            session['context']['time_context'] = query_analysis['time_range']
        
        # Update statistics
        session['statistics']['total_queries'] += 1
        if results.get('success', True):
            session['statistics']['successful_queries'] += 1
        
        # Update average confidence
        total_confidence = session['statistics']['avg_confidence'] * (session['statistics']['total_queries'] - 1)
        session['statistics']['avg_confidence'] = (total_confidence + query_analysis['confidence']) / session['statistics']['total_queries']
        
        # Keep only last 10 queries to prevent memory bloat
        if len(session['query_history']) > 10:
            session['query_history'] = session['query_history'][-10:]

# Initialize components
config = SIEMConfig.from_env()
nlp_processor = AdvancedNLPProcessor()
siem_connector = SIEMConnector(config)
context_manager = ContextManager()

# Input validation schemas
class QuerySchema(Schema):
    query = fields.Str(required=True, validate=validate.Length(min=1, max=2000))
    session_id = fields.Str(validate=validate.Length(max=100))
    context = fields.Dict(missing={})

def validate_input(schema):
    """Input validation decorator"""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            try:
                data = schema.load(request.json)
                return f(data, *args, **kwargs)
            except ValidationError as err:
                return jsonify({
                    'success': False,
                    'error': 'Input validation failed',
                    'details': err.messages
                }), 400
            except Exception as e:
                return jsonify({
                    'success': False,
                    'error': 'Invalid JSON format'
                }), 400
        return decorated
    return decorator

# API Routes
@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'service': 'Conversational SIEM Assistant API',
        'version': '1.0.0',
        'components': {
            'nlp_processor': 'active',
            'elasticsearch': 'connected' if siem_connector.elasticsearch_client else 'mock_mode',
            'wazuh': 'connected' if siem_connector.wazuh_session else 'disconnected'
        }
    })

@app.route('/api/query', methods=['POST'])
@validate_input(QuerySchema())
def process_query(data):
    """Process natural language SIEM query"""
    try:
        query = data['query']
        session_id = data.get('session_id', str(uuid.uuid4()))
        
        # Get session context
        session = context_manager.get_session(session_id)
        
        # Process query with NLP
        query_analysis = nlp_processor.parse_query(query, session['context'])
        
        # Execute SIEM query
        results = siem_connector.execute_query(query_analysis)
        
        # Update session context
        context_manager.update_session(session_id, query_analysis, results)
        
        # Format response
        response = {
            'success': True,
            'session_id': session_id,
            'query_analysis': {
                'original_query': query_analysis['original_query'],
                'intent': query_analysis['intent']['primary'],
                'entities': [e['term'] for e in query_analysis['entities']],
                'confidence': query_analysis['confidence'],
                'processing_time': query_analysis['processing_time']
            },
            'siem_queries': {
                'kql': query_analysis['kql_query'],
                'elasticsearch_dsl': query_analysis['elasticsearch_dsl']
            },
            'results': {
                'total_hits': results.get('total_hits', 0),
                'sample_events': results.get('results', [])[:5],  # First 5 events
                'query_time': results.get('query_time', 0),
                'data_source': results.get('data_source', 'elasticsearch')
            },
            'insights': generate_insights(query_analysis, results),
            'suggestions': query_analysis.get('suggestions', []),
            'context': {
                'session_queries': len(session['query_history']),
                'avg_confidence': session['statistics']['avg_confidence']
            }
        }
        
        # Emit to WebSocket if available
        socketio.emit('query_result', response, room=session_id)
        
        return jsonify(response)
        
    except Exception as e:
        logger.error(f"Query processing error: {str(e)}")
        return jsonify({
            'success': False,
            'error': f'Query processing failed: {str(e)}',
            'suggestions': [
                'Try simplifying your query',
                'Use specific security terms like "failed login" or "malware detection"',
                'Include time ranges like "yesterday" or "last week"'
            ]
        }), 500

@app.route('/api/session/<session_id>', methods=['GET'])
def get_session_info(session_id: str):
    """Get session information and history"""
    session = context_manager.get_session(session_id)
    
    return jsonify({
        'success': True,
        'session': {
            'id': session['id'],
            'created_at': session['created_at'],
            'last_activity': session['last_activity'],
            'statistics': session['statistics'],
            'context': session['context'],
            'recent_queries': session['query_history'][-5:]  # Last 5 queries
        }
    })

@app.route('/api/explain', methods=['POST'])
def explain_query():
    """Explain how a query would be processed without executing it"""
    try:
        data = request.json
        query = data.get('query', '')
        
        if not query:
            return jsonify({
                'success': False,
                'error': 'Query text is required'
            }), 400
        
        # Parse query without execution
        query_analysis = nlp_processor.parse_query(query)
        
        explanation = {
            'success': True,
            'explanation': {
                'detected_entities': [
                    {
                        'term': e['term'],
                        'description': e.get('description', 'Security entity'),
                        'confidence': e.get('confidence', 0)
                    } for e in query_analysis['entities']
                ],
                'detected_intent': {
                    'primary': query_analysis['intent']['primary'],
                    'confidence': query_analysis['intent']['confidence']
                },
                'time_range': query_analysis.get('time_range'),
                'generated_kql': query_analysis['kql_query'],
                'overall_confidence': query_analysis['confidence'],
                'processing_notes': [
                    f"Processed query in {query_analysis['processing_time']}s",
                    f"Found {len(query_analysis['entities'])} security entities",
                    f"Intent classified as '{query_analysis['intent']['primary']}'"
                ]
            }
        }
        
        return jsonify(explanation)
        
    except Exception as e:
        logger.error(f"Query explanation error: {str(e)}")
        return jsonify({
            'success': False,
            'error': f'Query explanation failed: {str(e)}'
        }), 500

@app.route('/api/suggest', methods=['POST'])
def suggest_queries():
    """Suggest related queries based on current context"""
    try:
        data = request.json
        session_id = data.get('session_id')
        
        if session_id:
            session = context_manager.get_session(session_id)
            active_entities = session['context']['active_entities']
        else:
            active_entities = []
        
        # Generate contextual suggestions
        suggestions = []
        
        if 'failed login' in active_entities:
            suggestions.extend([
                'Show successful logins after failed attempts',
                'Analyze failed login source IPs',
                'Generate brute force attack report'
            ])
        
        if 'malware detection' in active_entities:
            suggestions.extend([
                'Show affected hosts and systems',
                'Generate malware family breakdown',
                'Check network connections from infected hosts'
            ])
        
        # Default suggestions if no context
        if not suggestions:
            suggestions = [
                'Show failed login attempts from yesterday',
                'Generate malware detection report for last week',
                'Analyze network anomalies from today',
                'Find VPN connection failures in last 24 hours',
                'Show web attacks blocked by firewall'
            ]
        
        return jsonify({
            'success': True,
            'suggestions': suggestions[:8],  # Limit to 8 suggestions
            'context_based': bool(active_entities)
        })
        
    except Exception as e:
        logger.error(f"Suggestion generation error: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Failed to generate suggestions'
        }), 500

# WebSocket events
@socketio.on('connect')
def handle_connect():
    """Handle WebSocket connection"""
    logger.info(f"WebSocket client connected: {request.sid}")
    emit('connection_status', {'status': 'connected', 'session_id': request.sid})

@socketio.on('join_session')
def handle_join_session(data):
    """Handle joining a session room"""
    session_id = data.get('session_id')
    if session_id:
        join_room(session_id)
        emit('session_joined', {'session_id': session_id})
        logger.info(f"Client {request.sid} joined session {session_id}")

@socketio.on('disconnect')
def handle_disconnect():
    """Handle WebSocket disconnection"""
    logger.info(f"WebSocket client disconnected: {request.sid}")

# Utility functions
def generate_insights(query_analysis: Dict, results: Dict) -> List[str]:
    """Generate insights from query results"""
    insights = []
    
    entities = query_analysis.get('entities', [])
    total_hits = results.get('total_hits', 0)
    
    # Entity-based insights
    if entities:
        entity_types = [e.get('category', 'unknown') for e in entities]
        
        if 'authentication' in entity_types and total_hits > 10:
            insights.append('High volume of authentication events detected - possible brute force activity')
        elif 'malware' in entity_types and total_hits > 0:
            insights.append('Active malware threats identified - recommend immediate investigation')
        elif 'network' in entity_types:
            insights.append('Network security events found - monitor for patterns and escalation')
    
    # Time-based insights
    time_range = query_analysis.get('time_range')
    if time_range and 'yesterday' in time_range.get('phrase', ''):
        insights.append('Analysis focused on previous day - consider expanding timeframe for trends')
    
    # Confidence insights
    confidence = query_analysis.get('confidence', 0)
    if confidence > 0.8:
        insights.append('High confidence query mapping - results should be accurate')
    elif confidence < 0.5:
        insights.append('Low confidence mapping - consider refining query terms')
    
    # Results insights
    if total_hits == 0:
        insights.append('No matching events found - try broader search terms or different time range')
    elif total_hits > 100:
        insights.append('Large result set - consider adding filters to narrow focus')
    
    return insights[:5]  # Limit to 5 insights

if __name__ == '__main__':
    logger.info("Starting Conversational SIEM Assistant API")
    logger.info("Features: NLP Processing, Multi-turn Context, Real SIEM Integration")
    
    # Run with SocketIO support
    socketio.run(
        app,
        debug=os.getenv('DEBUG', 'false').lower() == 'true',
        host='0.0.0.0',
        port=int(os.getenv('PORT', 5000))
    )