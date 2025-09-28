# Enhanced Conversational SIEM Assistant - ISRO PS#25173

## Problem Statement
**Conversational SIEM Assistant for Investigation and Automated Threat Reporting using NLP**

This project implements a Natural Language Processing (NLP) powered interface that connects directly with ELK-based SIEMs (Elastic SIEM/Wazuh) to support conversational investigations and automated threat reporting without requiring knowledge of KQL or Elasticsearch DSL syntax.

## Core Features

### 1. Conversational Investigations
- **Multi-turn Natural Language Queries**: Support for follow-up questions like "What suspicious login attempts occurred yesterday?" followed by "Filter only VPN-related attempts."
- **Context Preservation**: Maintains conversation context across multiple queries for iterative investigation
- **Real-time Translation**: Converts natural language to optimized Elasticsearch DSL/KQL queries
- **Live SIEM Integration**: Direct API connectivity with Elastic SIEM and Wazuh platforms

### 2. Automated Report Generation
- **Natural Language Reporting**: Accept requests like "Generate a summary of malware detections in the past month with charts"
- **Dynamic Query Construction**: Automatically builds complex SIEM queries based on user intent
- **Multi-format Output**: Results presented as narratives, tables, charts, and visualizations
- **Executive Summaries**: AI-generated insights and recommendations

## System Architecture

### NLP Processing Engine
- **Intent Classification**: Identifies user goals (search, analyze, report, filter)
- **Entity Extraction**: Maps security terms to SIEM schema fields
- **Time Range Parser**: Converts natural time expressions to query filters
- **Context Manager**: Maintains multi-turn conversation state

### SIEM Connector Layer
- **Elasticsearch Integration**: Direct connection via official Python client
- **Wazuh API Support**: REST API integration for alert management
- **Query Optimization**: Intelligent index pattern selection and query tuning
- **Error Handling**: Graceful fallback and retry mechanisms

### Response Formatter
- **Adaptive Output**: Context-aware result presentation
- **Visualization Engine**: Dynamic chart generation based on data patterns
- **Insight Generation**: AI-powered security analysis and recommendations

## Key Technical Components

### Backend API (`app.py`)
```python
# Core NLP processor with advanced entity mapping
class AdvancedNLPProcessor:
    - Entity recognition for security concepts
    - Intent classification with confidence scoring  
    - Time range extraction and normalization
    - Context-aware query building
```

### Frontend Interface (`index.html`)
```javascript
# Real-time conversational interface
class ConversationalSIEMAssistant:
    - WebSocket integration for real-time updates
    - Dynamic query visualization
    - Context preservation across sessions
    - Performance metrics dashboard
```

## Installation & Setup

### Prerequisites
```bash
# Python 3.8+ required
pip install -r requirements.txt

# Download spaCy language model
python -m spacy download en_core_web_sm
```

### Environment Configuration
```bash
# SIEM Connection Settings
ELASTIC_HOSTS=localhost:9200
ELASTIC_USER=elastic
ELASTIC_PASSWORD=your_password
WAZUH_API_URL=https://localhost:55000
WAZUH_USER=wazuh
WAZUH_PASSWORD=your_wazuh_password

# Security Indices Configuration
SECURITY_INDEX=security-*
NETWORK_INDEX=network-*
AUTH_INDEX=auth-*
MALWARE_INDEX=malware-*
```

### Quick Start
```bash
# Start the backend API
python app.py

# Open frontend interface
open index.html
# or serve via web server for full functionality
```

## NLP Query Examples

### Basic Investigations
- "Show me failed login attempts from yesterday"
- "What malware was detected in the last week?"
- "Find network anomalies from suspicious IP addresses"

### Multi-turn Conversations
```
User: "Show me authentication failures from yesterday"
Assistant: [Shows results with KQL query]

User: "Filter only the ones from external IPs"
Assistant: [Applies additional filters while preserving context]

User: "Generate a report with charts"
Assistant: [Creates comprehensive report with visualizations]
```

### Report Generation
- "Create an executive summary of security incidents this month"
- "Generate malware detection trends with charts for the past week"
- "Produce a compliance report for authentication events"

## SIEM Integration Details

### Supported Platforms
- **Elasticsearch/ELK Stack**: Direct integration via REST API
- **Wazuh SIEM**: Native API connectivity for alerts and rules
- **Custom SIEM**: Extensible connector architecture

### Query Translation Examples
```
Natural Language: "failed login attempts yesterday"
Generated KQL: event.outcome:failure AND event.category:authentication AND @timestamp:[now-1d/d TO now/d]

Natural Language: "malware detected on Windows systems"
Generated DSL: {
  "query": {
    "bool": {
      "must": [
        {"match": {"event.category": "malware"}},
        {"match": {"host.os.family": "windows"}}
      ]
    }
  }
}
```

### Performance Optimizations
- **Smart Index Selection**: Automatic routing to relevant indices
- **Query Caching**: Reduces SIEM load for repeated queries
- **Result Pagination**: Efficient handling of large datasets
- **Parallel Processing**: Concurrent query execution where applicable

## Advanced Features

### Context Management
- Session-based conversation tracking
- Entity relationship mapping
- Temporal context preservation
- User preference learning

### Security & Compliance
- Query audit logging
- Role-based access control integration
- Data privacy protection
- Compliance reporting capabilities

### Extensibility
- Plugin architecture for custom analyzers
- Configurable entity mappings
- Custom visualization templates
- Third-party SIEM connectors

## Development & Customization

### Adding New Entity Types
```python
# Extend entity mappings in NLPProcessor
new_entity = {
    'dns_exfiltration': {
        'kql': 'event.category:network AND dns.question.type:TXT',
        'elasticsearch_dsl': {...},
        'description': 'DNS-based data exfiltration attempts'
    }
}
```

### Custom Visualization Templates
```javascript
// Add new chart types in frontend
customChartTypes = {
    'security_heatmap': {...},
    'threat_timeline': {...},
    'geo_threat_map': {...}
}
```

## Troubleshooting

### Common Issues
1. **SIEM Connection Failures**: Check network connectivity and credentials
2. **Query Performance**: Review index patterns and time ranges
3. **NLP Accuracy**: Update entity mappings for domain-specific terms

### Debug Mode
```bash
# Enable detailed logging
DEBUG=true python app.py
```

## Contributing
- Follow PEP 8 for Python code
- Use semantic versioning for releases
- Include unit tests for new features
- Update documentation for API changes

## License
MIT License - See LICENSE file for details

## Support
- Documentation: [Project Wiki](wiki_link)
- Issues: [GitHub Issues](issues_link)
- Security: [Security Policy](security_link)

---

**Note**: This implementation provides a comprehensive NLP-powered interface for SIEM operations, enabling security analysts to perform complex investigations using natural language queries while maintaining the full power and precision of underlying SIEM platforms.