# SOCca Architecture Documentation

## 1. High-Level Overview

SOCca is an AI-powered security vulnerability tracking system designed for real-time monitoring of Common Vulnerabilities and Exposures (CVEs) and seamless integration with Microsoft Sentinel. The system follows a modular architecture with clear separation of concerns between data collection, processing, analysis, and reporting components.

```
+-------------+     +-------------+     +---------------+     +----------------+
| NVD API     |---->| CVE Monitor |---->| AI Analysis   |---->| Database Store |
| Integration |     | (mainv2.py) |     | (soccav5.py)  |     |                |
+-------------+     +-------------+     +---------------+     +----------------+
                                                                      |
                                                                      v
                          +----------------+     +-------------------+
                          | Microsoft      |<----| Sentinel Exporter |
                          | Sentinel       |     | (sentinel_        |
                          | Integration    |     |  exporter.py)     |
                          +----------------+     +-------------------+
```

The system processes data through a pipeline:
1. **Collection**: Monitors NVD for new CVEs
2. **Analysis**: Processes CVEs with AI to generate detailed reports
3. **Storage**: Stores both raw CVE data and AI-generated reports
4. **Integration**: Exports processed data to Microsoft Sentinel

## 2. Key Components and Responsibilities

### 2.1 CVE Monitor (mainv2.py)

Primary responsibility: Poll the NVD API for new CVEs and initiate processing.

Key functions:
- Connects to the NVD API using the `nvdlib` library
- Polls for new CVEs at regular intervals (configurable)
- Checks if CVEs have already been processed
- Stores raw CVE data in the database
- Triggers AI analysis for new CVEs

```
+--------------------+
| CVE Monitor        |
|--------------------|
| - Poll NVD API     |
| - Filter new CVEs  |
| - Store raw data   |
| - Trigger analysis |
+--------------------+
```

### 2.2 AI Analysis Engine (soccav5.py)

Primary responsibility: Generate comprehensive security reports for vulnerabilities.

Key functions:
- Connects to OpenAI API
- Fetches URL content from references
- Structures prompts for AI analysis
- Processes CVE data with AI models
- Saves generated reports to database
- Ensures reports are structured for Sentinel integration

```
+--------------------+
| AI Analysis Engine |
|--------------------|
| - Connect to OpenAI|
| - Process URLs     |
| - Generate reports |
| - Format for SIEM  |
| - Store reports    |
+--------------------+
```

### 2.3 URL Processor (url_processor.py)

Primary responsibility: Extract relevant content from vulnerability references.

Key functions:
- Fetches content from URLs
- Prioritizes URLs based on reputation
- Processes URLs in parallel
- Caches results for efficiency
- Extracts main content using readability
- Handles errors and timeouts gracefully

```
+--------------------+
| URL Processor      |
|--------------------|
| - Fetch content    |
| - Prioritize URLs  |
| - Cache results    |
| - Extract content  |
| - Handle errors    |
+--------------------+
```

### 2.4 Sentinel Exporter (sentinel_exporter.py)

Primary responsibility: Export CVE data and reports to Microsoft Sentinel.

Key functions:
- Connects to Microsoft Sentinel Log Analytics API
- Prepares CVE data for Sentinel ingestion
- Formats data according to Sentinel requirements
- Generates alert templates
- Handles direct API integration or file-based exports
- Includes MITRE ATT&CK mappings

```
+------------------------+
| Sentinel Exporter      |
|------------------------|
| - Connect to Sentinel  |
| - Format data for SIEM |
| - Generate alerts      |
| - Direct API export    |
| - File-based export    |
+------------------------+
```

### 2.5 Database Utilities (db_schema.py, db_export.py, db_import.py)

Primary responsibility: Manage database structures and data import/export.

Key functions:
- Define database schemas
- Initialize database structures
- Export database content to JSON
- Import data from JSON to database
- Provide backup and restore functionality

```
+------------------------+
| Database Utilities     |
|------------------------|
| - Define schemas       |
| - Initialize DBs       |
| - Import/export data   |
| - Backup/restore       |
+------------------------+
```

## 3. Data Flow Between Components

### 3.1 CVE Discovery and Processing

```
  +------------+     +------------+     +------------+     +------------+
  | NVD API    |---->| mainv2.py  |---->| soccav5.py |---->| Database   |
  | (External) |     | (Monitor)  |     | (Analysis) |     | (Storage)  |
  +------------+     +------------+     +------------+     +------------+
                          |                   |
                          v                   v
                    +------------+     +------------+
                    | processed  |     | url_       |
                    | _cves.db   |     | processor  |
                    +------------+     +------------+
                                             |
                                             v
                                       +------------+
                                       | URL content|
                                       | cache DB   |
                                       +------------+
```

1. `mainv2.py` polls the NVD API for new CVEs at regular intervals
2. For each new CVE, basic information is stored in `processed_cves.db`
3. The CVE data is passed to `soccav5.py` for AI analysis
4. `soccav5.py` uses `url_processor.py` to fetch and extract content from reference URLs
5. AI-generated reports are stored in `cve_reports.db`

### 3.2 Microsoft Sentinel Integration

```
  +------------+     +------------+     +------------+
  | Database   |---->| sentinel_  |---->| Microsoft  |
  | (Storage)  |     | exporter.py|     | Sentinel   |
  +------------+     +------------+     +------------+
        |                  |
        v                  v
  +------------+     +------------+
  | processed  |     | sentinel   |
  | _cves.db   |     | _output    |
  +------------+     | files      |
        |            +------------+
        v
  +------------+
  | cve_       |
  | reports.db |
  +------------+
```

1. `sentinel_exporter.py` queries the databases for processed CVEs and reports
2. Data is transformed into a format suitable for Microsoft Sentinel
3. Integration occurs through either:
   - Direct API integration using Log Analytics API
   - File-based exports for manual import
4. Alert templates are generated for Sentinel analytics rules

## 4. Database Schema and Data Storage

SOCca uses SQLite databases for data storage, with a clear separation of concerns:

### 4.1 processed_cves.db

Stores raw CVE data from the NVD API:

```
┌─────────────────────┐
│ processed_cves      │
├─────────────────────┤
│ cve_id (TEXT PK)    │
│ description (TEXT)  │
│ url (TEXT)          │
│ pub (TEXT)          │
│ data (TEXT)         │
│ cata (TEXT)         │
└─────────────────────┘
```

- `cve_id`: Unique identifier for the vulnerability (e.g., CVE-2023-1234)
- `description`: Official vulnerability description
- `url`: List of reference URLs (stored as string)
- `pub`: Publication date
- `data`: CVSS vulnerability scoring data
- `cata`: Category/metadata information

### 4.2 cve_reports.db

Stores AI-generated analysis reports:

```
┌─────────────────────┐
│ processed           │
├─────────────────────┤
│ cve_id (TEXT PK)    │
│ report (TEXT)       │
│ processed_date      │
└─────────────────────┘
```

- `cve_id`: Unique identifier for the vulnerability
- `report`: AI-generated report in structured JSON format
- `processed_date`: When the report was generated

### 4.3 url_cache.db

Caches content from reference URLs to improve performance:

```
┌─────────────────────┐
│ url_cache           │
├─────────────────────┤
│ url_hash (TEXT PK)  │
│ url (TEXT)          │
│ content (TEXT)      │
│ fetch_time (INT)    │
│ status_code (INT)   │
│ content_type (TEXT) │
└─────────────────────┘
```

- `url_hash`: SHA-256 hash of the URL (primary key)
- `url`: The original URL
- `content`: Cached content
- `fetch_time`: Timestamp when content was fetched
- `status_code`: HTTP status code
- `content_type`: Content type of the response

### 4.4 Additional Databases

```
┌───────────────────┐  ┌───────────────────┐  ┌───────────────────┐
│ posts.db          │  │ kev_data.db       │  │ alerts.db         │
├───────────────────┤  ├───────────────────┤  ├───────────────────┤
│ id (PK)           │  │ id (PK)           │  │ cve_id (PK)       │
│ report            │  │ cve_id            │  │ alert_time        │
└───────────────────┘  │ name              │  │ alert_type        │
                      │ vendor_project    │  └───────────────────┘
                      │ product           │
                      │ vulnerability_name│
                      │ date_added        │
                      │ short_description │
                      │ required_action   │
                      │ due_date          │
                      │ notes             │
                      └───────────────────┘
```

## 5. Integration with External Systems

### 5.1 NVD API Integration

SOCca integrates with the NVD API to fetch vulnerability data:

- Uses the NVD API 2.0 endpoint
- Handles rate limiting (5 requests per 30 seconds without API key)
- Filters vulnerabilities by publication date
- Extracts metadata, CVSS scores, and references
- Implements error handling and retries

Implementation: `nvdapi.py` provides the core functionality for NVD API interaction.

### 5.2 OpenAI Integration

SOCca uses OpenAI models to analyze vulnerabilities:

- Connects to OpenAI API using legacy client
- Structures prompts for comprehensive analysis
- Transforms raw vulnerability data into structured reports
- Includes Microsoft Sentinel-specific context
- Handles token limits and optimizes requests

Implementation: `soccav5.py` manages all OpenAI interactions.

### 5.3 Microsoft Sentinel Integration

SOCca integrates with Microsoft Sentinel via the Log Analytics API:

- Direct integration using REST API
- Formats data according to Log Analytics requirements
- Creates custom log types in Sentinel
- Generates alert templates for Sentinel analytics rules
- Maps vulnerabilities to MITRE ATT&CK tactics
- Supports direct API integration or file-based exports

Implementation: `sentinel_exporter.py` manages Sentinel integration.

## 6. Deployment Architecture

SOCca is designed to run as a Docker container with the option for microservice deployment:

```
┌─────────────────────────────────────────────────────┐
│                      Docker Host                     │
├─────────────────────────────────────────────────────┤
│ ┌───────────────────────────────────────────────┐   │
│ │                Docker Container                │   │
│ │                                               │   │
│ │  ┌────────────┐         ┌────────────────┐    │   │
│ │  │ mainv2.py  │         │ sentinel_      │    │   │
│ │  │ CVE polling├────────►│ exporter.py    │    │   │
│ │  └──────┬─────┘         │ hourly exports │    │   │
│ │         │               └────────┬───────┘    │   │
│ │  ┌──────▼─────┐                  │            │   │
│ │  │ soccav5.py │                  │            │   │
│ │  │ AI analysis│                  │            │   │
│ │  └────────────┘                  │            │   │
│ │                                  │            │   │
│ │  ┌────────────┐          ┌──────▼───────┐     │   │
│ │  │ Volumes    │◄─────────┤ Microsoft    │     │   │
│ │  │ Data & Logs│          │ Sentinel     │     │   │
│ │  └────────────┘          └──────────────┘     │   │
│ │                                               │   │
│ └───────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────┘
```

### 6.1 Container Components

- **Main Process**: Runs the CVE monitoring process
  - Executes `mainv2.py` continuously
  - Polls the NVD API at defined intervals
  - Triggers AI analysis for new CVEs

- **Sentinel Export**: Runs within the same container
  - Executes `sentinel_exporter.py` hourly
  - Exports new CVE data to Microsoft Sentinel
  - Generates alert templates

### 6.2 Deployment Options

1. **All-in-One Deployment**: Single container running all services
   - Simple management with `docker-compose.sh start`
   - All components in a single container
   - Simple and recommended for most users

2. **Microservices Deployment**: Separate containers for each component
   - Separate containers using `docker-compose.sh micro`
   - Scale individual components independently
   - More granular monitoring and control

3. **Production Deployment**: Optimized containers for production
   - Resource limits and production settings
   - Enhanced logging configuration
   - Better suited for mission-critical environments

### 6.3 Configuration Management

Configuration is managed through:
- Environment variables passed to Docker container
- `.env` file loaded by docker-compose
- Docker volumes for data persistence
- Configuration in `config.py`
- Command-line arguments for utilities (via docker exec)

## 7. System Initialization and Startup Sequence

When the SOCca Docker container starts, the following sequence occurs:

1. **Container Initialization**:
   - Docker builds and starts the container
   - Volumes are mounted for persistent data
   - Environment variables are loaded from `.env` file

2. **Application Startup**:
   - Container executes the startup.sh script
   - Directory structure is verified
   - Configuration in `config.py` is loaded

3. **Database Initialization**:
   - Check for existing databases in mounted volumes
   - Create database schemas if not existing
   - Initialize tables for:
     - CVE storage
     - Report storage
     - URL cache
     - Alert tracking

4. **Service Startup**:
   - Start CVE monitoring process in background
   - Begin polling NVD API
   - Configure Sentinel export scheduler

5. **Initial Operations**:
   - Perform initial export to Sentinel (if configured)
   - Generate alert templates
   - Set up hourly export schedule

## 8. Extension Points

SOCca is designed to be extensible in several ways:

1. **AI Analysis Customization**:
   - Edit system prompts in `soccav5.py`
   - Adjust token handling for different report sizes
   - Modify the report structure

2. **Adding New SIEM Integrations**:
   - Create new exporter modules following the pattern in `sentinel_exporter.py`
   - Implement format conversions for target systems

3. **Custom Alert Rules**:
   - Extend alert template generation in `sentinel_exporter.py`
   - Add specialized detection rules for specific vulnerability types

4. **Database Schema Extensions**:
   - Add new fields or tables in `db_schema.py`
   - Update db utilities to handle new schemas

## 9. Error Handling and Resilience

SOCca implements several resilience patterns:

1. **Graceful Degradation**:
   - Continues operation if NVD API is unavailable
   - Falls back to file exports if Sentinel API is unavailable

2. **Comprehensive Error Handling**:
   - Specific error types in exception handling
   - Detailed logging with context

3. **Automated Recovery**:
   - Systemd services restart on failure
   - Rate limiting and backoff for API calls

4. **State Persistence**:
   - Database records prevent duplicate processing
   - Caching of URL content to reduce external dependencies

## Conclusion

SOCca follows a modular, pipeline-oriented architecture that separates concerns between data collection, processing, analysis, and integration. The system is designed to run reliably in Docker containers, with a focus on Microsoft Sentinel integration for security operations centers.

The architecture allows for:
- Continuous monitoring of new vulnerabilities
- AI-powered analysis and contextualization
- Structured data for Microsoft Sentinel integration
- Flexible deployment options with Docker
- Extensibility for future requirements

Developers working on the system should pay special attention to the data flow between components and ensure that changes maintain the structured format required for Microsoft Sentinel integration.