# SOCca Project Guidelines

## Project Overview
AI-powered security vulnerability tracking system that monitors CVEs, processes them with AI analysis (OpenAI), and publishes security reports with Microsoft Sentinel integration.

## Project Focus
SOCca has been refocused to specialize in Microsoft Sentinel integration, providing:
- Real-time CVE monitoring and AI analysis
- Direct export to Microsoft Sentinel via Log Analytics API
- Analytics rule templates generation
- MITRE ATT&CK mapping for enhanced threat correlation

## Commands
- Run main script: `python3 kryptos_working/mainv2.py`
- Send data to Sentinel: `python3 kryptos_working/sentinel_exporter.py --direct-send`
- Generate Sentinel alert templates: `python3 kryptos_working/sentinel_exporter.py --alerts`
- Database check: `sqlite3 kryptos_working/processed_cves.db .tables`
- Check logs: `tail -f kryptos_working/logs/sentinel_exporter.log`
- Run all components: `./startup.sh`
- Setup systemd services: `sudo systemctl start socca-monitor socca-sentinel`

## Code Style Guidelines
- **Imports**: Standard library imports first, followed by third-party packages
- **Naming**: Use snake_case for functions and variables
- **Database**: Use context managers for database connections when possible
- **Error Handling**: Always include specific error types in try/except blocks
- **API Keys**: Store in separate files (like files/apikeys), not hardcoded
- **Comments**: Include brief comments for non-obvious functions
- **Functions**: Keep functions focused on a single responsibility
- **HTTP Requests**: Always include timeouts and error handling
- **Model References**: Use constants for OpenAI model names

## Tools & Dependencies
- SQLite for database storage
- OpenAI API for vulnerability analysis
- Microsoft Sentinel Log Analytics API for SIEM integration
- Requests library for HTTP operations
- BeautifulSoup/readability for web content parsing
- Custom token counter for token tracking
- JSON/NDJSON for data export formats
- Linux systemd for service management

## Project Changes Summary
The following changes were made to focus SOCca on Microsoft Sentinel:

1. **Code Updates**:
   - Removed generic SIEM connectors and replaced with Sentinel-specific integration
   - Updated config.py with Microsoft Sentinel settings
   - Modified AI report generation to include KQL query templates
   - Updated directory structure for Sentinel outputs

2. **Documentation Updates**:
   - Created comprehensive Microsoft Sentinel integration guides
   - Added simplified step-by-step setup instructions
   - Included KQL query examples for analyzing data in Sentinel
   - Updated deployment instructions for Linux servers
   - Created list of removable files for deprecated SIEM components

3. **New Features**:
   - Direct integration with Microsoft Sentinel Log Analytics API
   - Sentinel alert template generation for analytics rules
   - MITRE ATT&CK mapping for enhanced threat correlation
   - Linux systemd service configuration
   - Sentinel workbook query examples