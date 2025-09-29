# Advanced SIEM Assistant - ISRO Cybersecurity Intelligence Platform

## Overview

This enhanced SIEM Assistant provides sophisticated natural language processing capabilities for cybersecurity analysis, automated threat detection, and intelligent incident response. Built specifically for ELK-based SIEM systems like Elastic SIEM and Wazuh, it bridges the gap between complex query languages and intuitive natural language interaction.

## 🚀 Key Features

### Advanced NLP Processing
- **Sophisticated Entity Recognition**: Extracts IPs, domains, hashes, users, hosts, and complex security entities
- **Context-Aware Parsing**: Maintains conversation context across multi-turn queries
- **Semantic Field Mapping**: Intelligent mapping of natural language terms to SIEM schema fields
- **Fuzzy Matching**: Robust handling of typos and variations in security terminology
- **Intent Classification**: Automatically determines user intent (search, aggregate, report, visualize, etc.)

### Machine Learning Capabilities
- **Anomaly Detection**: ML-powered identification of unusual patterns and behaviors
- **Correlation Analysis**: Advanced correlation engine linking events across time, users, and systems
- **Predictive Analytics**: Threat prediction based on historical patterns and trends
- **Behavioral Analysis**: User and system behavior profiling for insider threat detection

### Advanced Visualizations
- **Interactive Dashboards**: Real-time security metrics and KPIs
- **Network Topology Graphs**: Visual representation of network relationships and attack paths
- **Geographic Mapping**: Geographic distribution of threats and events
- **Timeline Analysis**: Temporal analysis with attack progression visualization
- **Threat Landscape Overview**: Comprehensive security posture visualization
- **Word Clouds**: Visual representation of threat patterns and event types

### Intelligent Reporting
- **Executive Summaries**: Auto-generated executive-level security reports
- **Detailed Analytics**: Comprehensive technical analysis with recommendations
- **Compliance Reporting**: Automated compliance and audit trail generation
- **Threat Intelligence**: Integration of threat indicators and IOCs
- **Risk Assessment**: Automated risk scoring and prioritization

### Enhanced User Interface
- **Modern Design**: Clean, professional interface with advanced styling
- **Real-time Confidence Scoring**: AI confidence indicators for query results
- **Advanced Filters**: Dynamic filtering with visual feedback
- **Export Capabilities**: Multiple export formats (PDF, CSV, JSON)
- **Bookmark System**: Save and reuse complex queries
- **Responsive Design**: Full mobile and tablet compatibility

## 🛠 Installation and Setup

### Prerequisites
- Python 3.8 or higher
- Elasticsearch cluster (optional - mock data available for testing)
- Sufficient RAM (minimum 4GB recommended)

### Step 1: Clone the Repository
```bash
git clone https://github.com/knightcodecc/siem-assistant-isro.git
cd siem-assistant-isro
```

### Step 2: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 3: Install spaCy Language Model
```bash
python -m spacy download en_core_web_sm
```

### Step 4: Environment Configuration
Create a `.env` file in the root directory:
```env
# Elasticsearch Configuration
ELASTICSEARCH_HOST=http://localhost:9200
ELASTICSEARCH_USER=elastic
ELASTICSEARCH_PASSWORD=your_password

# OpenAI Configuration (optional)
OPENAI_API_KEY=your_openai_api_key

# Application Settings
FLASK_ENV=development
FLASK_DEBUG=True
```

### Step 5: Dataset Integration
The system automatically loads SIEM schema and security knowledge from the DATA_SET.pdf file in the repository. No additional configuration needed.

### Step 6: Run the Application
```bash
python app.py
```

The application will be available at `http://localhost:5000`

## 🔧 Configuration Options

### Elasticsearch Integration
- **Index Patterns**: Configurable index patterns (default: `logs-*`)
- **Field Mappings**: Customizable field mappings for different SIEM deployments
- **Query Optimization**: Automatic query optimization for performance
- **Aggregation Limits**: Configurable aggregation sizes and timeouts

### AI Model Configuration
- **Confidence Thresholds**: Adjustable confidence levels for query parsing
- **Entity Recognition**: Custom entity patterns and recognition rules
- **Intent Classification**: Configurable intent keywords and weights
- **Context Window**: Adjustable conversation context retention

### Security Features
- **Query Validation**: Input sanitization and validation
- **Rate Limiting**: Configurable API rate limits
- **Audit Logging**: Comprehensive audit trail for all queries
- **Access Control**: Role-based access control integration

## 📊 Usage Examples

### Basic Queries
```
Show me authentication failures from yesterday
List malware detections in the last 24 hours
Find suspicious login attempts from external IPs
```

### Advanced Analytics
```
Perform anomaly detection on network traffic patterns
Analyze correlation between failed logins and VPN usage
Generate executive summary of security events for last month
Create timeline visualization of attack progression
```

### Multi-turn Conversations
```
User: Show me failed login attempts from yesterday
Assistant: [Shows results]
User: Filter only those from external IPs
Assistant: [Applies additional filter]
User: Create a geographic visualization
Assistant: [Generates geographic chart]
```

## 🎯 Advanced Features

### Natural Language Understanding
The system understands complex security terminology and can parse queries like:
- "Show me brute force attacks against admin accounts from suspicious IP ranges"
- "Generate a correlation analysis between file access events and process executions"
- "Identify lateral movement patterns in the network over the past week"

### Contextual Intelligence
- Maintains conversation context across multiple queries
- Learns user preferences and query patterns
- Provides intelligent suggestions based on previous queries
- Auto-completes common security investigation workflows

### Threat Intelligence Integration
- Automatic IOC (Indicators of Compromise) extraction
- Threat actor attribution and campaign analysis
- MITRE ATT&CK framework mapping
- Vulnerability correlation and impact assessment

### Performance Optimization
- Intelligent query caching for faster responses
- Optimized Elasticsearch queries with proper indexing
- Parallel processing for large dataset analysis
- Memory-efficient data processing and visualization

## 🔍 Data Sources and Schema

### Supported Log Types
- **Authentication Logs**: Windows Security, Linux auth, SSO systems
- **Network Traffic**: Firewall logs, IDS/IPS alerts, flow records
- **Endpoint Security**: EDR alerts, antivirus detections, system events
- **Application Logs**: Web server logs, database audit trails
- **Cloud Security**: AWS CloudTrail, Azure Activity logs, GCP audit logs

### Field Mapping
The system automatically maps common security fields:
```python
{
    "user": ["user.name", "source.user.name", "user.id"],
    "ip": ["source.ip", "destination.ip", "client.ip"],
    "event": ["event.action", "event.type", "event.category"],
    "timestamp": ["@timestamp", "event.created", "event.start"],
    "host": ["host.name", "host.hostname", "agent.hostname"]
}
```

## 📈 Visualization Capabilities

### Chart Types
- **Time Series**: Event trends over time
- **Geographic Maps**: Global threat distribution
- **Network Graphs**: Attack path visualization
- **Heatmaps**: Correlation analysis
- **Pie Charts**: Event type distribution
- **Bar Charts**: Top threats and indicators

### Interactive Features
- Zoom and pan on timeline charts
- Clickable elements for drill-down analysis
- Export options (PNG, SVG, PDF)
- Real-time updates for streaming data

## 🛡️ Security and Compliance

### Data Privacy
- No sensitive data stored in application memory
- Configurable data retention policies
- GDPR compliance features
- Data anonymization options

### Audit and Compliance
- Complete audit trail of all queries and responses
- Compliance reporting for SOC 2, ISO 27001
- Query history and user activity logging
- Role-based access control integration

## 🚀 Deployment Options

### Development Environment
```bash
python app.py
# Runs on http://localhost:5000 with debug mode
```

### Production Deployment
```bash
gunicorn --bind 0.0.0.0:5000 --workers 4 app:app
# Production-ready deployment with multiple workers
```

### Docker Deployment
```dockerfile
FROM python:3.9
COPY . /app
WORKDIR /app
RUN pip install -r requirements.txt
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "app:app"]
```

### Kubernetes Deployment
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: siem-assistant
spec:
  replicas: 3
  selector:
    matchLabels:
      app: siem-assistant
  template:
    metadata:
      labels:
        app: siem-assistant
    spec:
      containers:
      - name: siem-assistant
        image: siem-assistant:latest
        ports:
        - containerPort: 5000
```

## 🔧 Troubleshooting

### Common Issues

#### Elasticsearch Connection Failed
```
Error: Elasticsearch connection error
Solution: Check ELASTICSEARCH_HOST and credentials in .env file
```

#### spaCy Model Not Found
```
Error: Can't find model 'en_core_web_sm'
Solution: Run 'python -m spacy download en_core_web_sm'
```

#### Memory Issues with Large Datasets
```
Solution: Increase system memory or adjust query limits in configuration
```

### Performance Tuning

#### For Large Elasticsearch Clusters
- Increase `search.max_buckets` setting
- Optimize index sharding strategy
- Use index templates for consistent field mapping

#### For High Query Volume
- Enable Redis caching
- Implement query result caching
- Use connection pooling

## 📚 API Documentation

### Query Endpoint
```http
POST /query
Content-Type: application/json

{
  "query": "Show me authentication failures",
  "session_id": "unique_session_id",
  "filters": {
    "severity": "high",
    "time_range": "24h"
  }
}
```

### Visualization Endpoint
```http
POST /visualize
Content-Type: application/json

{
  "statistics": {...},
  "chart_type": "timeline",
  "options": {}
}
```

### Report Generation Endpoint
```http
POST /report
Content-Type: application/json

{
  "query": "Generate security report",
  "report_type": "executive",
  "time_range": "7d"
}
```

## 🤝 Contributing

### Development Setup
1. Fork the repository
2. Create a feature branch
3. Install development dependencies: `pip install -r requirements.txt`
4. Run tests: `pytest`
5. Submit pull request

### Code Standards
- Follow PEP 8 style guidelines
- Add type hints for all functions
- Write comprehensive docstrings
- Include unit tests for new features

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

For support and questions:
- Create an issue on GitHub
- Email: cybersecurity@isro.gov.in
- Documentation: [Wiki](https://github.com/knightcodecc/siem-assistant-isro/wiki)

## 🔮 Roadmap

### Version 2.0
- Integration with additional SIEM platforms
- Advanced ML models for threat prediction
- Real-time streaming analytics
- Mobile application support

### Version 3.0
- Multi-tenant architecture
- Advanced threat hunting workflows
- Integration with SOAR platforms
- Automated incident response capabilities

---

**Built with ❤️ for ISRO Cybersecurity Team**#   U p d a t e d  
 