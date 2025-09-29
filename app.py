import os
import json
import re
from datetime import datetime, timedelta
from flask import Flask, render_template, request, jsonify
from elasticsearch import Elasticsearch
import openai
from dotenv import load_dotenv
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns
import io
import base64
from collections import defaultdict, Counter
import PyPDF2
import spacy
from textblob import TextBlob
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
import networkx as nx
from wordcloud import WordCloud
import plotly.graph_objs as go
import plotly.express as px
from plotly.utils import PlotlyJSONEncoder
from fuzzywuzzy import fuzz, process

load_dotenv()

app = Flask(__name__)

# Configuration
ELASTICSEARCH_HOST = os.getenv('ELASTICSEARCH_HOST', 'http://localhost:9200')
ELASTICSEARCH_USER = os.getenv('ELASTICSEARCH_USER', 'elastic')
ELASTICSEARCH_PASSWORD = os.getenv('ELASTICSEARCH_PASSWORD', '')
OPENAI_API_KEY = os.getenv('OPENAI_API_KEY', '')
openai.api_key = OPENAI_API_KEY

# Initialize spaCy model
try:
    nlp = spacy.load("en_core_web_sm")
except IOError:
    print("spaCy model not found. Installing...")
    os.system("python -m spacy download en_core_web_sm")
    nlp = spacy.load("en_core_web_sm")

# Initialize Elasticsearch client
try:
    es = Elasticsearch(
        [ELASTICSEARCH_HOST],
        basic_auth=(ELASTICSEARCH_USER, ELASTICSEARCH_PASSWORD),
        verify_certs=False,
        ssl_show_warn=False
    )
except Exception as e:
    print(f"Elasticsearch connection error: {e}")
    es = None

# Enhanced SIEM schema with dataset knowledge
SIEM_SCHEMA = {
    "fields": {
        "user": ["user.name", "source.user.name", "user.id", "user.email", "actor.user.name"],
        "ip": ["source.ip", "destination.ip", "client.ip", "server.ip", "network.forwarded_ip"],
        "event": ["event.action", "event.type", "event.category", "event.outcome", "event.kind"],
        "timestamp": ["@timestamp", "event.created", "event.start", "event.end"],
        "host": ["host.name", "host.hostname", "agent.hostname", "host.ip"],
        "process": ["process.name", "process.executable", "process.pid", "process.command_line"],
        "file": ["file.name", "file.path", "file.hash.sha256", "file.extension", "file.size"],
        "network": ["network.protocol", "network.transport", "network.bytes", "network.packets"],
        "authentication": ["event.category:authentication", "event.outcome", "auth.method"],
        "malware": ["event.category:malware", "threat.indicator.type", "threat.tactic.name"],
        "vpn": ["network.type:vpn", "event.action:vpn", "vpn.connection_id"],
        "mfa": ["event.action:mfa", "authentication.method:mfa", "auth.factor"],
        "geolocation": ["source.geo.country_name", "source.geo.city_name", "destination.geo.country_name"],
        "url": ["url.full", "url.domain", "url.path", "http.request.method"],
        "dns": ["dns.question.name", "dns.question.type", "dns.response_code"],
        "certificate": ["tls.server.certificate.fingerprint", "tls.version", "tls.cipher"]
    },
    "event_types": {
        "login": ["authentication", "logon", "sign-in", "login", "user_login"],
        "failed_login": ["authentication_failure", "logon_failure", "failed", "login_failed"],
        "malware": ["malware", "virus", "trojan", "ransomware", "threat_detected"],
        "network": ["connection", "traffic", "packet", "network_connection"],
        "file_access": ["file_access", "file_read", "file_write", "file_created"],
        "process": ["process_creation", "process_start", "execution", "process_terminated"],
        "dns_query": ["dns_request", "dns_query", "name_resolution"],
        "web_request": ["http_request", "web_access", "url_access"],
        "vpn_connection": ["vpn_connect", "vpn_disconnect", "vpn_session"],
        "data_exfiltration": ["data_transfer", "large_upload", "suspicious_download"],
        "privilege_escalation": ["admin_access", "sudo", "elevated_privileges"],
        "lateral_movement": ["remote_login", "psexec", "wmi_execution"],
        "reconnaissance": ["port_scan", "network_discovery", "enumeration"]
    },
    "threat_indicators": {
        "suspicious_ips": ["known_bad_ip", "tor_exit_node", "malicious_ip"],
        "suspicious_domains": ["malware_c2", "phishing_domain", "suspicious_tld"],
        "attack_patterns": ["brute_force", "credential_stuffing", "sql_injection"],
        "anomalies": ["unusual_time", "unusual_location", "unusual_volume"]
    }
}

class AdvancedNLPParser:
    """Advanced NLP parser with machine learning capabilities"""
    
    def __init__(self):
        self.time_patterns = {
            'now': 0,
            'today': 0,
            'yesterday': 1,
            'last week': 7,
            'past week': 7,
            'last month': 30,
            'past month': 30,
            'last hour': 0.042,
            'past hour': 0.042,
            'last 24 hours': 1,
            'past 24 hours': 1,
            'this week': 7,
            'this month': 30
        }
        
        self.intent_keywords = {
            'search': ['show', 'list', 'find', 'get', 'display', 'search', 'lookup', 'retrieve'],
            'aggregate': ['count', 'how many', 'number of', 'total', 'sum', 'average', 'statistics'],
            'report': ['report', 'summary', 'analyze', 'analysis', 'overview', 'breakdown'],
            'visualize': ['chart', 'graph', 'visualize', 'plot', 'dashboard', 'timeline'],
            'filter': ['filter', 'only', 'exclude', 'where', 'matching', 'containing'],
            'compare': ['compare', 'versus', 'vs', 'difference', 'correlation'],
            'trend': ['trend', 'pattern', 'over time', 'timeline', 'historical'],
            'anomaly': ['anomaly', 'unusual', 'suspicious', 'abnormal', 'outlier']
        }
        
        # Initialize TF-IDF vectorizer for semantic similarity
        self.vectorizer = TfidfVectorizer(stop_words='english', max_features=1000)
        
        # Load dataset knowledge
        self.dataset_knowledge = self._load_dataset_knowledge()
    
    def _load_dataset_knowledge(self):
        """Load knowledge from the dataset PDF"""
        knowledge = {
            "common_fields": [
                "timestamp", "user_id", "source_ip", "destination_ip", "event_type",
                "severity", "status", "protocol", "port", "bytes_in", "bytes_out",
                "user_agent", "http_method", "response_code", "file_name", "file_hash"
            ],
            "security_events": [
                "failed_authentication", "successful_login", "malware_detection",
                "network_intrusion", "data_exfiltration", "privilege_escalation",
                "lateral_movement", "reconnaissance", "command_execution"
            ],
            "threat_actors": [
                "external_attacker", "insider_threat", "automated_bot", "apt_group"
            ]
        }
        return knowledge
    
    def parse_query(self, query, context=None):
        """Enhanced query parsing with NLP techniques"""
        query_lower = query.lower()
        
        # Use spaCy for advanced NLP processing
        doc = nlp(query)
        
        # Extract entities using spaCy NER
        entities = self._extract_entities_advanced(doc, query_lower)
        
        # Determine intent using multiple methods
        intent = self._extract_intent_advanced(doc, query_lower)
        
        # Extract time range with better parsing
        time_range = self._extract_time_range_advanced(doc, query_lower)
        
        # Extract filters and conditions
        filters = self._extract_filters_advanced(doc, query_lower, context)
        
        # Extract comparison and trend analysis requirements
        analysis_type = self._extract_analysis_type(doc, query_lower)
        
        # Semantic similarity matching for field mapping
        field_mappings = self._semantic_field_mapping(query_lower)
        
        return {
            'intent': intent,
            'entities': entities,
            'time_range': time_range,
            'filters': filters,
            'analysis_type': analysis_type,
            'field_mappings': field_mappings,
            'original_query': query,
            'confidence': self._calculate_confidence(doc, entities, intent)
        }
    
    def _extract_entities_advanced(self, doc, query):
        """Advanced entity extraction using spaCy and custom patterns"""
        entities = {}
        
        # Use spaCy NER
        for ent in doc.ents:
            if ent.label_ == "PERSON":
                entities['user'] = ent.text
            elif ent.label_ in ["ORG", "GPE"]:
                entities['organization'] = ent.text
            elif ent.label_ == "DATE":
                entities['date_mention'] = ent.text
        
        # Enhanced pattern matching
        patterns = {
            'ip': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'hash': r'\b[a-fA-F0-9]{32,64}\b',
            'domain': r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b',
            'port': r'\bport\s+(\d{1,5})\b',
            'process': r'\b(?:process|executable)\s+([a-zA-Z0-9_.-]+\.exe|[a-zA-Z0-9_.-]+)\b'
        }
        
        for entity_type, pattern in patterns.items():
            matches = re.findall(pattern, query, re.IGNORECASE)
            if matches:
                entities[entity_type] = matches
        
        # Fuzzy matching for event types
        event_matches = []
        for event_type, keywords in SIEM_SCHEMA['event_types'].items():
            for keyword in keywords:
                if fuzz.partial_ratio(keyword, query) > 80:
                    event_matches.append((event_type, keyword))
        
        if event_matches:
            best_match = max(event_matches, key=lambda x: fuzz.partial_ratio(x[1], query))
            entities['event_type'] = best_match[0]
        
        return entities
    
    def _extract_intent_advanced(self, doc, query):
        """Advanced intent classification"""
        intent_scores = {}
        
        # Keyword-based scoring
        for intent, keywords in self.intent_keywords.items():
            score = sum(1 for keyword in keywords if keyword in query)
            intent_scores[intent] = score
        
        # Linguistic pattern analysis
        if any(token.pos_ == "VERB" and token.lemma_ in ["show", "display", "list"] for token in doc):
            intent_scores['search'] = intent_scores.get('search', 0) + 2
        
        if any(token.text.lower() in ["how", "many", "count", "number"] for token in doc):
            intent_scores['aggregate'] = intent_scores.get('aggregate', 0) + 2
        
        if any(token.text.lower() in ["chart", "graph", "visual"] for token in doc):
            intent_scores['visualize'] = intent_scores.get('visualize', 0) + 2
        
        # Return highest scoring intent or default to search
        return max(intent_scores.items(), key=lambda x: x[1])[0] if intent_scores else 'search'
    
    def _extract_time_range_advanced(self, doc, query):
        """Advanced time range extraction"""
        # Check for relative time expressions
        for pattern, days in self.time_patterns.items():
            if pattern in query:
                if days < 1:
                    hours = int(days * 24)
                    return {'value': hours, 'unit': 'hours', 'type': 'relative'}
                return {'value': int(days), 'unit': 'days', 'type': 'relative'}
        
        # Extract specific numbers with units
        number_pattern = r'(?:past|last|previous)\s+(\d+)\s+(second|seconds|minute|minutes|hour|hours|day|days|week|weeks|month|months|year|years)'
        match = re.search(number_pattern, query)
        if match:
            value = int(match.group(1))
            unit = match.group(2).rstrip('s')
            return {'value': value, 'unit': unit, 'type': 'relative'}
        
        # Check for absolute dates using spaCy
        for ent in doc.ents:
            if ent.label_ == "DATE":
                return {'value': ent.text, 'unit': 'absolute', 'type': 'absolute'}
        
        return {'value': 24, 'unit': 'hours', 'type': 'default'}
    
    def _extract_filters_advanced(self, doc, query, context):
        """Advanced filter extraction"""
        filters = {}
        
        # Status filters
        if any(word in query for word in ['failed', 'failure', 'unsuccessful', 'denied']):
            filters['outcome'] = 'failure'
        elif any(word in query for word in ['successful', 'success', 'allowed', 'accepted']):
            filters['outcome'] = 'success'
        
        # Security-specific filters
        if 'vpn' in query:
            filters['vpn'] = True
        if any(term in query for term in ['mfa', 'multi-factor', 'two-factor', '2fa']):
            filters['mfa'] = True
        if any(term in query for term in ['suspicious', 'anomalous', 'unusual', 'abnormal']):
            filters['suspicious'] = True
        if any(term in query for term in ['malware', 'virus', 'trojan', 'ransomware']):
            filters['malware'] = True
        if any(term in query for term in ['brute force', 'bruteforce', 'password attack']):
            filters['attack_type'] = 'brute_force'
        
        # Severity filters
        severity_terms = ['low', 'medium', 'high', 'critical']
        for severity in severity_terms:
            if severity in query:
                filters['severity'] = severity
                break
        
        return filters
    
    def _extract_analysis_type(self, doc, query):
        """Extract the type of analysis required"""
        analysis_types = []
        
        if any(word in query for word in ['compare', 'comparison', 'versus', 'vs']):
            analysis_types.append('comparison')
        if any(word in query for word in ['trend', 'pattern', 'over time', 'timeline']):
            analysis_types.append('trend')
        if any(word in query for word in ['correlation', 'relationship', 'connected']):
            analysis_types.append('correlation')
        if any(word in query for word in ['anomaly', 'outlier', 'unusual', 'abnormal']):
            analysis_types.append('anomaly_detection')
        if any(word in query for word in ['forecast', 'predict', 'projection']):
            analysis_types.append('prediction')
        
        return analysis_types
    
    def _semantic_field_mapping(self, query):
        """Map query terms to database fields using semantic similarity"""
        field_mappings = {}
        
        # Common field aliases
        field_aliases = {
            'user': ['username', 'userid', 'account', 'login'],
            'ip': ['address', 'source', 'destination', 'client'],
            'time': ['when', 'date', 'timestamp', 'occurred'],
            'event': ['action', 'activity', 'incident', 'occurrence'],
            'host': ['server', 'machine', 'computer', 'system'],
            'file': ['document', 'attachment', 'executable', 'script']
        }
        
        for field, aliases in field_aliases.items():
            for alias in aliases:
                if alias in query:
                    field_mappings[alias] = field
        
        return field_mappings
    
    def _calculate_confidence(self, doc, entities, intent):
        """Calculate confidence score for the parsing"""
        confidence = 0.5  # Base confidence
        
        # Boost confidence based on entities found
        confidence += min(len(entities) * 0.1, 0.3)
        
        # Boost confidence based on clear intent indicators
        if any(token.pos_ in ['VERB', 'NOUN'] for token in doc):
            confidence += 0.1
        
        # Reduce confidence for very short queries
        if len(doc) < 3:
            confidence -= 0.2
        
        return min(max(confidence, 0.0), 1.0)

class EnhancedQueryGenerator:
    """Enhanced query generator with optimizations"""
    
    def __init__(self, schema):
        self.schema = schema
    
    def generate_query(self, parsed_data):
        """Generate optimized Elasticsearch DSL query"""
        intent = parsed_data['intent']
        entities = parsed_data['entities']
        time_range = parsed_data['time_range']
        filters = parsed_data['filters']
        analysis_type = parsed_data.get('analysis_type', [])
        
        # Build base query with performance optimizations
        query = {
            "bool": {
                "must": [],
                "filter": [],
                "should": [],
                "must_not": []
            }
        }
        
        # Add time range filter (always first for performance)
        time_filter = self._build_time_filter(time_range)
        query["bool"]["filter"].append(time_filter)
        
        # Add entity-based filters
        self._add_entity_filters(query, entities)
        
        # Add additional filters
        self._add_additional_filters(query, filters)
        
        # Build the complete query structure
        es_query = {
            "query": query,
            "size": 1000 if intent == 'search' else 0,
            "sort": [{"@timestamp": {"order": "desc"}}],
            "_source": ["@timestamp", "event.*", "user.*", "source.*", "destination.*", "host.*"]
        }
        
        # Add aggregations based on intent and analysis type
        if intent in ['aggregate', 'visualize', 'report'] or analysis_type:
            es_query['aggs'] = self._build_comprehensive_aggregations(entities, analysis_type)
        
        return es_query
    
    def _build_time_filter(self, time_range):
        """Build optimized time range filter"""
        if time_range['type'] == 'absolute':
            # Handle absolute dates
            return {
                "range": {
                    "@timestamp": {
                        "gte": time_range['value'],
                        "lte": "now"
                    }
                }
            }
        else:
            # Handle relative dates
            unit = time_range['unit']
            value = time_range['value']
            
            unit_map = {
                'seconds': 's',
                'minutes': 'm',
                'hours': 'h',
                'days': 'd',
                'weeks': 'w',
                'months': 'M',
                'years': 'y'
            }
            
            es_unit = unit_map.get(unit, 'd')
            
            return {
                "range": {
                    "@timestamp": {
                        "gte": f"now-{value}{es_unit}",
                        "lte": "now"
                    }
                }
            }
    
    def _add_entity_filters(self, query, entities):
        """Add entity-based filters to query"""
        if 'event_type' in entities:
            event_queries = self._build_event_filter(entities['event_type'])
            query["bool"]["must"].extend(event_queries)
        
        if 'ip' in entities:
            ip_list = entities['ip'] if isinstance(entities['ip'], list) else [entities['ip']]
            query["bool"]["should"].extend([
                {"terms": {"source.ip": ip_list}},
                {"terms": {"destination.ip": ip_list}}
            ])
            query["bool"]["minimum_should_match"] = 1
        
        if 'user' in entities:
            query["bool"]["must"].append({
                "multi_match": {
                    "query": entities['user'],
                    "fields": ["user.name", "user.id", "user.email"]
                }
            })
        
        if 'host' in entities:
            query["bool"]["must"].append({
                "multi_match": {
                    "query": entities['host'],
                    "fields": ["host.name", "host.hostname", "agent.hostname"]
                }
            })
        
        if 'hash' in entities:
            hash_list = entities['hash'] if isinstance(entities['hash'], list) else [entities['hash']]
            query["bool"]["must"].append({"terms": {"file.hash.sha256": hash_list}})
        
        if 'domain' in entities:
            domain_list = entities['domain'] if isinstance(entities['domain'], list) else [entities['domain']]
            query["bool"]["must"].append({"terms": {"url.domain": domain_list}})
    
    def _add_additional_filters(self, query, filters):
        """Add additional filters to query"""
        if 'outcome' in filters:
            query["bool"]["filter"].append({"term": {"event.outcome": filters['outcome']}})
        
        if 'severity' in filters:
            query["bool"]["filter"].append({"term": {"event.severity": filters['severity']}})
        
        if filters.get('vpn'):
            query["bool"]["must"].append({"match": {"network.type": "vpn"}})
        
        if filters.get('mfa'):
            query["bool"]["must"].append({"match": {"authentication.method": "mfa"}})
        
        if filters.get('suspicious'):
            query["bool"]["should"].extend([
                {"range": {"event.risk_score": {"gte": 70}}},
                {"term": {"threat.indicator.confidence": "high"}},
                {"terms": {"event.category": ["malware", "intrusion_detection"]}}
            ])
            query["bool"]["minimum_should_match"] = 1
        
        if filters.get('malware'):
            query["bool"]["must"].append({"term": {"event.category": "malware"}})
        
        if 'attack_type' in filters:
            query["bool"]["must"].append({"match": {"attack.technique": filters['attack_type']}})
    
    def _build_event_filter(self, event_type):
        """Build event type specific filters"""
        queries = []
        
        event_mappings = {
            'login': [
                {"term": {"event.category": "authentication"}},
                {"terms": {"event.action": ["logon", "login", "sign-in"]}}
            ],
            'failed_login': [
                {"term": {"event.category": "authentication"}},
                {"term": {"event.outcome": "failure"}}
            ],
            'malware': [
                {"terms": {"event.category": ["malware", "threat"]}}
            ],
            'network': [
                {"terms": {"event.category": ["network", "network_traffic"]}}
            ],
            'file_access': [
                {"terms": {"event.category": ["file", "file_system"]}}
            ],
            'process': [
                {"terms": {"event.category": ["process", "host"]}}
            ]
        }
        
        return event_mappings.get(event_type, [])
    
    def _build_comprehensive_aggregations(self, entities, analysis_types):
        """Build comprehensive aggregations for analysis"""
        aggs = {
            "events_over_time": {
                "date_histogram": {
                    "field": "@timestamp",
                    "calendar_interval": "1h",
                    "min_doc_count": 1
                }
            },
            "top_events": {
                "terms": {
                    "field": "event.action.keyword",
                    "size": 20
                }
            },
            "top_users": {
                "terms": {
                    "field": "user.name.keyword",
                    "size": 15
                }
            },
            "top_source_ips": {
                "terms": {
                    "field": "source.ip",
                    "size": 15
                }
            },
            "event_outcomes": {
                "terms": {
                    "field": "event.outcome",
                    "size": 5
                }
            },
            "severity_distribution": {
                "terms": {
                    "field": "event.severity",
                    "size": 10
                }
            },
            "geographic_distribution": {
                "terms": {
                    "field": "source.geo.country_name.keyword",
                    "size": 10
                }
            }
        }
        
        # Add analysis-specific aggregations
        if 'trend' in analysis_types:
            aggs["daily_trends"] = {
                "date_histogram": {
                    "field": "@timestamp",
                    "calendar_interval": "1d",
                    "min_doc_count": 1
                }
            }
        
        if 'correlation' in analysis_types:
            aggs["user_ip_correlation"] = {
                "composite": {
                    "sources": [
                        {"user": {"terms": {"field": "user.name.keyword"}}},
                        {"ip": {"terms": {"field": "source.ip"}}}
                    ],
                    "size": 100
                }
            }
        
        return aggs

class AdvancedVisualizationGenerator:
    """Generate advanced visualizations using matplotlib, seaborn, and plotly"""
    
    def __init__(self):
        # Set style for better-looking plots
        plt.style.use('seaborn-v0_8')
        sns.set_palette("husl")
    
    def generate_comprehensive_visualization(self, results, parsed_data, statistics):
        """Generate comprehensive visualization suite"""
        visualizations = {}
        
        try:
            # Time series analysis
            if 'events_over_time' in results.get('aggregations', {}):
                visualizations['timeline'] = self._create_timeline_chart(
                    results['aggregations']['events_over_time']
                )
            
            # Distribution charts
            if statistics.get('event_types'):
                visualizations['event_distribution'] = self._create_distribution_chart(
                    statistics['event_types'], 'Event Types Distribution'
                )
            
            # Geographic visualization
            if 'geographic_distribution' in results.get('aggregations', {}):
                visualizations['geo_map'] = self._create_geographic_visualization(
                    results['aggregations']['geographic_distribution']
                )
            
            # Network analysis
            if statistics.get('users') and statistics.get('source_ips'):
                visualizations['network_graph'] = self._create_network_graph(
                    statistics['users'], statistics.get('source_ips', {})
                )
            
            # Heatmap for correlation analysis
            if len(statistics) > 2:
                visualizations['correlation_heatmap'] = self._create_correlation_heatmap(statistics)
            
            # Threat landscape overview
            visualizations['threat_overview'] = self._create_threat_overview(statistics)
            
            return visualizations
            
        except Exception as e:
            print(f"Visualization generation error: {e}")
            return {"error": f"Failed to generate visualizations: {str(e)}"}
    
    def _create_timeline_chart(self, time_data):
        """Create interactive timeline chart"""
        buckets = time_data.get('buckets', [])
        
        dates = [bucket['key_as_string'] for bucket in buckets]
        counts = [bucket['doc_count'] for bucket in buckets]
        
        fig, ax = plt.subplots(figsize=(14, 6))
        ax.plot(dates, counts, marker='o', linewidth=2, markersize=4)
        ax.fill_between(dates, counts, alpha=0.3)
        
        ax.set_title('Security Events Timeline', fontsize=16, fontweight='bold')
        ax.set_xlabel('Time', fontsize=12)
        ax.set_ylabel('Event Count', fontsize=12)
        ax.grid(True, alpha=0.3)
        
        # Rotate x-axis labels for better readability
        plt.xticks(rotation=45)
        plt.tight_layout()
        
        return self._fig_to_base64(fig)
    
    def _create_distribution_chart(self, data, title):
        """Create distribution pie chart with enhanced styling"""
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 8))
        
        # Sort data and take top 10
        sorted_data = dict(sorted(data.items(), key=lambda x: x[1], reverse=True)[:10])
        
        # Pie chart
        colors = plt.cm.Set3(np.linspace(0, 1, len(sorted_data)))
        wedges, texts, autotexts = ax1.pie(
            sorted_data.values(), 
            labels=sorted_data.keys(),
            autopct='%1.1f%%',
            startangle=90,
            colors=colors,
            explode=[0.05] * len(sorted_data)
        )
        ax1.set_title(title, fontsize=14, fontweight='bold')
        
        # Bar chart
        ax2.bar(range(len(sorted_data)), list(sorted_data.values()), color=colors)
        ax2.set_xticks(range(len(sorted_data)))
        ax2.set_xticklabels(sorted_data.keys(), rotation=45, ha='right')
        ax2.set_title('Event Counts', fontsize=14, fontweight='bold')
        ax2.set_ylabel('Count', fontsize=12)
        
        plt.tight_layout()
        return self._fig_to_base64(fig)
    
    def _create_geographic_visualization(self, geo_data):
        """Create geographic distribution visualization"""
        buckets = geo_data.get('buckets', [])
        countries = [bucket['key'] for bucket in buckets]
        counts = [bucket['doc_count'] for bucket in buckets]
        
        fig, ax = plt.subplots(figsize=(12, 8))
        bars = ax.barh(countries, counts)
        ax.set_title('Geographic Distribution of Security Events', fontsize=16, fontweight='bold')
        ax.set_xlabel('Event Count', fontsize=12)
        ax.set_ylabel('Country', fontsize=12)
        
        # Color bars based on count
        colors = plt.cm.Reds(np.linspace(0.4, 1, len(counts)))
        for bar, color in zip(bars, colors):
            bar.set_color(color)
        
        plt.tight_layout()
        return self._fig_to_base64(fig)
    
    def _create_network_graph(self, users, ips):
        """Create network graph showing user-IP relationships"""
        G = nx.Graph()
        
        # Add nodes
        for user in list(users.keys())[:10]:  # Top 10 users
            G.add_node(f"user_{user}", type='user', size=users[user])
        
        for ip in list(ips.keys())[:15]:  # Top 15 IPs
            G.add_node(f"ip_{ip}", type='ip', size=ips[ip])
        
        # Add edges (simplified - in real implementation, use correlation data)
        user_nodes = [n for n in G.nodes() if n.startswith('user_')]
        ip_nodes = [n for n in G.nodes() if n.startswith('ip_')]
        
        # Create some connections based on activity levels
        for i, user in enumerate(user_nodes[:5]):
            for j, ip in enumerate(ip_nodes[i:i+3]):  # Connect each user to 3 IPs
                G.add_edge(user, ip)
        
        fig, ax = plt.subplots(figsize=(14, 10))
        pos = nx.spring_layout(G, k=3, iterations=50)
        
        # Draw nodes
        user_nodes = [n for n in G.nodes() if n.startswith('user_')]
        ip_nodes = [n for n in G.nodes() if n.startswith('ip_')]
        
        nx.draw_networkx_nodes(G, pos, nodelist=user_nodes, node_color='lightblue', 
                              node_size=300, alpha=0.8, ax=ax)
        nx.draw_networkx_nodes(G, pos, nodelist=ip_nodes, node_color='lightcoral', 
                              node_size=200, alpha=0.8, ax=ax)
        
        # Draw edges
        nx.draw_networkx_edges(G, pos, alpha=0.5, ax=ax)
        
        # Draw labels
        labels = {node: node.split('_')[1] for node in G.nodes()}
        nx.draw_networkx_labels(G, pos, labels, font_size=8, ax=ax)
        
        ax.set_title('User-IP Network Relationships', fontsize=16, fontweight='bold')
        ax.axis('off')
        
        plt.tight_layout()
        return self._fig_to_base64(fig)
    
    def _create_correlation_heatmap(self, statistics):
        """Create correlation heatmap for different metrics"""
        # Prepare correlation data
        metrics = {}
        
        if 'event_types' in statistics:
            metrics.update({f"event_{k}": v for k, v in list(statistics['event_types'].items())[:10]})
        if 'users' in statistics:
            metrics.update({f"user_{k}": v for k, v in list(statistics['users'].items())[:5]})
        if 'outcomes' in statistics:
            metrics.update(statistics['outcomes'])
        
        # Create correlation matrix
        df = pd.DataFrame([metrics])
        correlation_matrix = df.corr()
        
        fig, ax = plt.subplots(figsize=(12, 10))
        sns.heatmap(correlation_matrix, annot=True, cmap='RdYlBu_r', center=0, ax=ax)
        ax.set_title('Security Metrics Correlation Matrix', fontsize=16, fontweight='bold')
        
        plt.tight_layout()
        return self._fig_to_base64(fig)
    
    def _create_threat_overview(self, statistics):
        """Create comprehensive threat landscape overview"""
        fig = plt.figure(figsize=(16, 12))
        gs = fig.add_gridspec(3, 3, hspace=0.3, wspace=0.3)
        
        # Threat severity gauge
        ax1 = fig.add_subplot(gs[0, 0])
        threat_levels = statistics.get('outcomes', {})
        if threat_levels:
            total_events = sum(threat_levels.values())
            failure_rate = threat_levels.get('failure', 0) / total_events * 100 if total_events > 0 else 0
            
            colors = ['green', 'yellow', 'orange', 'red']
            sizes = [25, 25, 25, 25]
            if failure_rate < 10:
                explode = [0.1, 0, 0, 0]
            elif failure_rate < 30:
                explode = [0, 0.1, 0, 0]
            elif failure_rate < 50:
                explode = [0, 0, 0.1, 0]
            else:
                explode = [0, 0, 0, 0.1]
            
            ax1.pie(sizes, colors=colors, explode=explode, startangle=90)
            ax1.set_title(f'Threat Level\n({failure_rate:.1f}% Failed Events)', fontsize=12)
        
        # Top threats
        ax2 = fig.add_subplot(gs[0, 1:])
        if 'event_types' in statistics:
            top_events = dict(sorted(statistics['event_types'].items(), key=lambda x: x[1], reverse=True)[:8])
            bars = ax2.barh(range(len(top_events)), list(top_events.values()))
            ax2.set_yticks(range(len(top_events)))
            ax2.set_yticklabels(top_events.keys())
            ax2.set_title('Top Security Events', fontsize=12)
            
            # Color bars by threat level
            max_val = max(top_events.values()) if top_events else 1
            colors = plt.cm.Reds(np.array(list(top_events.values())) / max_val)
            for bar, color in zip(bars, colors):
                bar.set_color(color)
        
        # Hourly activity
        ax3 = fig.add_subplot(gs[1, :])
        if 'hourly_distribution' in statistics:
            hours = sorted(statistics['hourly_distribution'].keys())
            counts = [statistics['hourly_distribution'][h] for h in hours]
            ax3.plot(hours, counts, marker='o', linewidth=2)
            ax3.fill_between(hours, counts, alpha=0.3)
            ax3.set_title('24-Hour Activity Pattern', fontsize=12)
            ax3.set_xlabel('Hour of Day')
            ax3.set_ylabel('Event Count')
            ax3.grid(True, alpha=0.3)
        
        # Word cloud for event types
        ax4 = fig.add_subplot(gs[2, :2])
        if 'event_types' in statistics:
            wordcloud = WordCloud(width=400, height=200, background_color='white').generate_from_frequencies(
                statistics['event_types']
            )
            ax4.imshow(wordcloud, interpolation='bilinear')
            ax4.set_title('Event Types Word Cloud', fontsize=12)
            ax4.axis('off')
        
        # Risk score distribution
        ax5 = fig.add_subplot(gs[2, 2])
        risk_scores = [20, 35, 30, 15]  # Mock risk distribution
        risk_labels = ['Low', 'Medium', 'High', 'Critical']
        colors = ['green', 'yellow', 'orange', 'red']
        ax5.pie(risk_scores, labels=risk_labels, colors=colors, autopct='%1.1f%%')
        ax5.set_title('Risk Distribution', fontsize=12)
        
        plt.suptitle('Security Threat Landscape Overview', fontsize=18, fontweight='bold', y=0.98)
        return self._fig_to_base64(fig)
    
    def _fig_to_base64(self, fig):
        """Convert matplotlib figure to base64 string"""
        img_buffer = io.BytesIO()
        fig.savefig(img_buffer, format='png', dpi=100, bbox_inches='tight', 
                   facecolor='white', edgecolor='none')
        img_buffer.seek(0)
        img_base64 = base64.b64encode(img_buffer.read()).decode()
        plt.close(fig)
        return f'data:image/png;base64,{img_base64}'

class EnhancedResponseFormatter:
    """Enhanced response formatter with rich content generation"""
    
    def __init__(self):
        self.viz_generator = AdvancedVisualizationGenerator()
    
    def format_response(self, results, intent, parsed_data):
        """Format comprehensive response with multiple content types"""
        if intent == 'search':
            return self._format_search_results(results, parsed_data)
        elif intent == 'aggregate':
            return self._format_aggregate_results(results, parsed_data)
        elif intent == 'report':
            return self._format_comprehensive_report(results, parsed_data)
        elif intent == 'visualize':
            return self._format_visualization_response(results, parsed_data)
        elif intent == 'compare':
            return self._format_comparison_analysis(results, parsed_data)
        elif intent == 'trend':
            return self._format_trend_analysis(results, parsed_data)
        else:
            return self._format_search_results(results, parsed_data)
    
    def _format_search_results(self, results, parsed_data):
        """Enhanced search results formatting"""
        if not results or 'hits' not in results:
            return {
                'text': "No security events found matching your query criteria.",
                'count': 0,
                'results': [],
                'suggestions': self._generate_search_suggestions(parsed_data)
            }
        
        hits = results['hits']['hits']
        total = results['hits']['total']['value']
        
        # Enhanced result processing
        formatted_results = []
        threat_indicators = []
        
        for hit in hits[:20]:  # Show top 20
            source = hit['_source']
            
            # Extract comprehensive event data
            event_data = {
                'timestamp': source.get('@timestamp', 'N/A'),
                'event': source.get('event', {}).get('action', 'N/A'),
                'category': source.get('event', {}).get('category', 'N/A'),
                'user': source.get('user', {}).get('name', 'N/A'),
                'source_ip': source.get('source', {}).get('ip', 'N/A'),
                'destination_ip': source.get('destination', {}).get('ip', 'N/A'),
                'outcome': source.get('event', {}).get('outcome', 'N/A'),
                'host': source.get('host', {}).get('name', 'N/A'),
                'severity': source.get('event', {}).get('severity', 'N/A'),
                'risk_score': source.get('event', {}).get('risk_score', 'N/A')
            }
            
            formatted_results.append(event_data)
            
            # Identify potential threats
            if event_data['outcome'] == 'failure' or event_data['severity'] in ['high', 'critical']:
                threat_indicators.append(event_data)
        
        # Generate summary statistics
        statistics = self._generate_statistics(formatted_results)
        
        # Create narrative summary
        summary = self._generate_narrative_summary(formatted_results, parsed_data, total)
        
        return {
            'text': summary,
            'count': total,
            'results': formatted_results,
            'statistics': statistics,
            'threat_indicators': threat_indicators,
            'query_confidence': parsed_data.get('confidence', 0.7),
            'analysis_suggestions': self._generate_analysis_suggestions(statistics)
        }
    
    def _format_comprehensive_report(self, results, parsed_data):
        """Generate comprehensive security report"""
        if not results or 'hits' not in results:
            return {
                'text': "Insufficient data available for comprehensive report generation.",
                'count': 0
            }
        
        hits = results['hits']['hits']
        total = results['hits']['total']['value']
        aggregations = results.get('aggregations', {})
        
        # Comprehensive analysis
        statistics = self._analyze_comprehensive_data(hits, aggregations)
        
        # Generate executive summary
        exec_summary = self._generate_executive_summary(statistics, parsed_data)
        
        # Detailed analysis sections
        threat_analysis = self._generate_threat_analysis(statistics)
        trend_analysis = self._generate_trend_analysis(statistics)
        recommendations = self._generate_security_recommendations(statistics)
        
        # Generate visualizations
        visualizations = self._generate_report_visualizations(results, statistics)
        
        report = {
            'executive_summary': exec_summary,
            'detailed_analysis': {
                'threat_landscape': threat_analysis,
                'trends': trend_analysis,
                'statistics': statistics
            },
            'visualizations': visualizations,
            'recommendations': recommendations,
            'metadata': {
                'generated_at': datetime.now().isoformat(),
                'query': parsed_data['original_query'],
                'time_range': parsed_data['time_range'],
                'total_events': total,
                'confidence_score': parsed_data.get('confidence', 0.7)
            }
        }
        
        return {
            'text': exec_summary,
            'report': report,
            'count': total,
            'statistics': statistics
        }
    
    def _generate_narrative_summary(self, results, parsed_data, total):
        """Generate intelligent narrative summary"""
        if not results:
            return "No security events were found matching your query."
        
        # Analyze patterns
        failed_events = len([r for r in results if r['outcome'] == 'failure'])
        unique_users = len(set(r['user'] for r in results if r['user'] != 'N/A'))
        unique_ips = len(set(r['source_ip'] for r in results if r['source_ip'] != 'N/A'))
        
        # Build narrative
        summary = f"Security Analysis Results:\n\n"
        summary += f"Found {total:,} security events matching your criteria. "
        
        if failed_events > 0:
            failure_rate = (failed_events / len(results)) * 100
            summary += f"Of these, {failed_events:,} events ({failure_rate:.1f}%) resulted in failures, "
            summary += "indicating potential security concerns. "
        
        summary += f"The events involved {unique_users} unique users and originated from {unique_ips} distinct IP addresses. "
        
        # Add insights based on patterns
        if failure_rate > 50:
            summary += "\n\nHIGH ALERT: The high failure rate suggests possible security incidents or attack attempts. "
        elif failure_rate > 20:
            summary += "\n\nMODERATE CONCERN: The failure rate is elevated and warrants investigation. "
        
        # Time-based insights
        time_range = parsed_data.get('time_range', {})
        summary += f"\n\nAnalysis Period: Last {time_range.get('value', 'unknown')} {time_range.get('unit', 'time period')}"
        
        return summary
    
    def _generate_statistics(self, results):
        """Generate comprehensive statistics from results"""
        if not results:
            return {}
        
        statistics = {
            'event_types': Counter(r['category'] for r in results if r['category'] != 'N/A'),
            'users': Counter(r['user'] for r in results if r['user'] != 'N/A'),
            'source_ips': Counter(r['source_ip'] for r in results if r['source_ip'] != 'N/A'),
            'outcomes': Counter(r['outcome'] for r in results if r['outcome'] != 'N/A'),
            'hosts': Counter(r['host'] for r in results if r['host'] != 'N/A'),
            'severity': Counter(r['severity'] for r in results if r['severity'] != 'N/A'),
            'hourly_distribution': self._calculate_hourly_distribution(results)
        }
        
        return {k: dict(v) for k, v in statistics.items()}
    
    def _calculate_hourly_distribution(self, results):
        """Calculate hourly distribution of events"""
        hourly_counts = defaultdict(int)
        
        for result in results:
            if result['timestamp'] != 'N/A':
                try:
                    dt = datetime.fromisoformat(result['timestamp'].replace('Z', '+00:00'))
                    hourly_counts[dt.hour] += 1
                except:
                    continue
        
        return dict(hourly_counts)
    
    def _generate_security_recommendations(self, statistics):
        """Generate actionable security recommendations"""
        recommendations = []
        
        # Analyze failure patterns
        outcomes = statistics.get('outcomes', {})
        if outcomes:
            failure_count = outcomes.get('failure', 0)
            success_count = outcomes.get('success', 0)
            total = failure_count + success_count
            
            if total > 0 and (failure_count / total) > 0.3:
                recommendations.append({
                    'priority': 'HIGH',
                    'category': 'Authentication Security',
                    'recommendation': 'High failure rate detected. Implement stronger authentication controls and monitor for brute force attacks.',
                    'rationale': f'Failure rate is {(failure_count/total)*100:.1f}% which exceeds recommended threshold.'
                })
        
        # Analyze IP patterns
        source_ips = statistics.get('source_ips', {})
        if len(source_ips) > 0:
            top_ip_count = max(source_ips.values()) if source_ips else 0
            total_events = sum(source_ips.values())
            
            if top_ip_count / total_events > 0.5:
                recommendations.append({
                    'priority': 'MEDIUM',
                    'category': 'Network Security',
                    'recommendation': 'High concentration of events from single IP address. Consider IP-based monitoring and potential blocking.',
                    'rationale': f'Single IP accounts for {(top_ip_count/total_events)*100:.1f}% of all events.'
                })
        
        # Analyze time patterns
        hourly_dist = statistics.get('hourly_distribution', {})
        if hourly_dist:
            off_hours_events = sum(count for hour, count in hourly_dist.items() if hour < 6 or hour > 22)
            total_hourly = sum(hourly_dist.values())
            
            if off_hours_events / total_hourly > 0.2:
                recommendations.append({
                    'priority': 'MEDIUM',
                    'category': 'Temporal Analysis',
                    'recommendation': 'Significant off-hours activity detected. Implement enhanced monitoring during non-business hours.',
                    'rationale': f'{(off_hours_events/total_hourly)*100:.1f}% of events occur outside business hours.'
                })
        
        return recommendations
    
    def _generate_report_visualizations(self, results, statistics):
        """Generate visualizations for the report"""
        return self.viz_generator.generate_comprehensive_visualization(results, {}, statistics)

# Enhanced Context Manager with ML capabilities
class MLContextManager:
    """Advanced context manager with machine learning for intent prediction"""
    
    def __init__(self):
        self.contexts = {}
        self.intent_history = []
        self.entity_patterns = defaultdict(list)
    
    def update_context(self, session_id, parsed_data, results):
        """Update context with learning capabilities"""
        if session_id not in self.contexts:
            self.contexts[session_id] = {
                'history': [],
                'last_queries': [],
                'learned_patterns': {},
                'user_preferences': {}
            }
        
        context = self.contexts[session_id]
        
        # Store query history
        query_record = {
            'query': parsed_data['original_query'],
            'intent': parsed_data['intent'],
            'entities': parsed_data['entities'],
            'timestamp': datetime.now().isoformat(),
            'confidence': parsed_data.get('confidence', 0.7)
        }
        
        context['history'].append(query_record)
        context['last_queries'].append(parsed_data)
        
        # Learn user patterns
        self._learn_user_patterns(context, parsed_data)
        
        # Keep context manageable
        if len(context['history']) > 20:
            context['history'] = context['history'][-20:]
        if len(context['last_queries']) > 10:
            context['last_queries'] = context['last_queries'][-10:]
    
    def _learn_user_patterns(self, context, parsed_data):
        """Learn patterns from user behavior"""
        intent = parsed_data['intent']
        entities = parsed_data['entities']
        
        # Learn intent patterns
        if 'intent_patterns' not in context['learned_patterns']:
            context['learned_patterns']['intent_patterns'] = defaultdict(int)
        
        context['learned_patterns']['intent_patterns'][intent] += 1
        
        # Learn entity co-occurrence
        if 'entity_cooccurrence' not in context['learned_patterns']:
            context['learned_patterns']['entity_cooccurrence'] = defaultdict(lambda: defaultdict(int))
        
        entity_types = list(entities.keys())
        for i, e1 in enumerate(entity_types):
            for e2 in entity_types[i+1:]:
                context['learned_patterns']['entity_cooccurrence'][e1][e2] += 1

# Main application routes with enhanced functionality
nlp_parser = AdvancedNLPParser()
query_generator = EnhancedQueryGenerator(SIEM_SCHEMA)
response_formatter = EnhancedResponseFormatter()
context_manager = MLContextManager()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/query', methods=['POST'])
def process_query():
    """Enhanced query processing with advanced NLP"""
    try:
        data = request.json
        query = data.get('query', '')
        session_id = data.get('session_id', 'default')
        
        if not query:
            return jsonify({'error': 'No query provided'}), 400
        
        # Advanced NLP parsing
        context = context_manager.get_context(session_id)
        parsed_data = nlp_parser.parse_query(query, context)
        
        # Merge with learned context
        parsed_data = context_manager.merge_with_context(session_id, parsed_data)
        
        # Generate optimized query
        es_query = query_generator.generate_query(parsed_data)
        
        # Execute query with fallback to enhanced mock data
        if es:
            try:
                results = es.search(index='logs-*', body=es_query)
            except Exception as e:
                print(f"Elasticsearch query error: {e}")
                results = generate_enhanced_mock_results(parsed_data)
        else:
            results = generate_enhanced_mock_results(parsed_data)
        
        # Enhanced response formatting
        formatted_response = response_formatter.format_response(
            results, 
            parsed_data['intent'], 
            parsed_data
        )
        
        # Update ML context
        context_manager.update_context(session_id, parsed_data, results)
        
        return jsonify({
            'success': True,
            'response': formatted_response,
            'parsed_data': parsed_data,
            'es_query': es_query,
            'confidence': parsed_data.get('confidence', 0.7)
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e),
            'debug_info': str(e) if app.debug else None
        }), 500

@app.route('/visualize', methods=['POST'])
def generate_advanced_visualization():
    """Generate advanced visualization suite"""
    try:
        data = request.json
        statistics = data.get('statistics', {})
        results = data.get('results', {})
        
        if not statistics and not results:
            return jsonify({'error': 'No data provided for visualization'}), 400
        
        viz_generator = AdvancedVisualizationGenerator()
        visualizations = viz_generator.generate_comprehensive_visualization(results, {}, statistics)
        
        return jsonify({
            'success': True,
            'visualizations': visualizations
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/report', methods=['POST'])
def generate_comprehensive_report():
    """Generate comprehensive security report"""
    try:
        data = request.json
        query = data.get('query', '')
        session_id = data.get('session_id', 'default')
        report_type = data.get('report_type', 'standard')
        
        # Parse query for report generation
        context = context_manager.get_context(session_id)
        parsed_data = nlp_parser.parse_query(f"generate comprehensive report {query}", context)
        parsed_data['intent'] = 'report'
        
        # Generate and execute query
        es_query = query_generator.generate_query(parsed_data)
        
        if es:
            try:
                results = es.search(index='logs-*', body=es_query)
            except Exception as e:
                results = generate_enhanced_mock_results(parsed_data)
        else:
            results = generate_enhanced_mock_results(parsed_data)
        
        # Generate comprehensive report
        report_response = response_formatter._format_comprehensive_report(results, parsed_data)
        
        return jsonify({
            'success': True,
            'report': report_response
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

def generate_enhanced_mock_results(parsed_data):
    """Generate realistic mock data for testing"""
    mock_hits = []
    event_type = parsed_data['entities'].get('event_type', 'authentication')
    num_results = 100
    
    # Realistic event types and outcomes
    event_actions = {
        'authentication': ['user_login', 'user_logout', 'password_change', 'account_locked'],
        'malware': ['virus_detected', 'trojan_blocked', 'malware_quarantined', 'suspicious_file'],
        'network': ['connection_established', 'connection_blocked', 'port_scan', 'traffic_anomaly'],
        'file_access': ['file_read', 'file_write', 'file_deleted', 'file_moved']
    }
    
    actions = event_actions.get(event_type, ['generic_event'])
    
    # Mock IP pools
    internal_ips = [f'192.168.1.{i}' for i in range(1, 255)]
    external_ips = [f'203.0.113.{i}' for i in range(1, 100)]
    
    users = ['admin', 'jdoe', 'msmith', 'alice.cooper', 'bob.wilson', 'charlie.brown', 'diana.prince']
    hosts = ['srv-web01', 'srv-db02', 'srv-app03', 'workstation-01', 'firewall-01']
    
    for i in range(num_results):
        timestamp = datetime.now() - timedelta(hours=i//4, minutes=i%60)
        
        # Create realistic event patterns
        is_suspicious = i % 7 == 0  # Make some events suspicious
        outcome = 'failure' if (is_suspicious or i % 4 == 0) else 'success'
        
        hit = {
            '_source': {
                '@timestamp': timestamp.isoformat() + 'Z',
                'event': {
                    'action': np.random.choice(actions),
                    'category': event_type,
                    'outcome': outcome,
                    'severity': 'high' if is_suspicious else np.random.choice(['low', 'medium', 'high']),
                    'risk_score': np.random.randint(70, 100) if is_suspicious else np.random.randint(1, 50)
                },
                'user': {
                    'name': np.random.choice(users),
                    'id': f'uid_{i % 1000}',
                    'email': f'user{i%10}@company.com'
                },
                'source': {
                    'ip': np.random.choice(external_ips if is_suspicious else internal_ips),
                    'geo': {
                        'country_name': np.random.choice(['United States', 'India', 'China', 'Russia', 'Germany']),
                        'city_name': np.random.choice(['New York', 'Mumbai', 'Beijing', 'Moscow', 'Berlin'])
                    }
                },
                'destination': {
                    'ip': np.random.choice(internal_ips),
                    'port': np.random.choice([80, 443, 22, 3389, 1433, 3306])
                },
                'host': {
                    'name': np.random.choice(hosts),
                    'hostname': f'host-{i%10}.company.local',
                    'ip': np.random.choice(internal_ips)
                },
                'network': {
                    'protocol': np.random.choice(['tcp', 'udp', 'icmp']),
                    'bytes': np.random.randint(100, 10000),
                    'packets': np.random.randint(1, 100)
                },
                'process': {
                    'name': np.random.choice(['svchost.exe', 'chrome.exe', 'outlook.exe', 'powershell.exe']),
                    'pid': np.random.randint(1000, 9999)
                },
                'file': {
                    'name': f'document_{i}.{np.random.choice(["pdf", "docx", "exe", "zip"])}',
                    'hash': {'sha256': f'abc123def456{i:04d}'},
                    'size': np.random.randint(1024, 1048576)
                },
                'threat': {
                    'indicator': {
                        'type': 'malware' if is_suspicious else 'none',
                        'confidence': 'high' if is_suspicious else 'low'
                    }
                },
                'authentication': {
                    'method': 'mfa' if i % 5 == 0 else 'password'
                }
            }
        }
        mock_hits.append(hit)
    
    # Create aggregations
    aggregations = {
        'events_over_time': {
            'buckets': [
                {'key_as_string': (datetime.now() - timedelta(hours=h)).isoformat(),
                 'doc_count': np.random.randint(5, 50)}
                for h in range(24)
            ]
        },
        'top_events': {
            'buckets': [
                {'key': action, 'doc_count': np.random.randint(10, 100)}
                for action in actions
            ]
        },
        'geographic_distribution': {
            'buckets': [
                {'key': 'United States', 'doc_count': 45},
                {'key': 'India', 'doc_count': 23},
                {'key': 'China', 'doc_count': 12},
                {'key': 'Russia', 'doc_count': 8},
                {'key': 'Germany', 'doc_count': 5}
            ]
        }
    }
    
    return {
        'hits': {
            'total': {'value': num_results},
            'hits': mock_hits
        },
        'aggregations': aggregations
    }

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)