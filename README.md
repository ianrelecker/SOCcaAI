# SOCca - AI-Powered CVE Intelligence with Microsoft Sentinel Integration

SOCca is an advanced security vulnerability monitoring and analysis platform containerized with Docker for easy deployment. It leverages AI to provide actionable intelligence on emerging threats with seamless Microsoft Sentinel integration.

## 🚀 Key Features

- **Real-time CVE Monitoring**: Automatically tracks new vulnerabilities as they're published to the NVD
- **AI-Powered Analysis**: Uses OpenAI models to generate comprehensive vulnerability reports with actionable insights
- **Intelligent Severity Assessment**: Goes beyond CVSS scores to provide context-aware risk evaluations
- **True Real-time Sentinel Integration**: Sends each CVE to Microsoft Sentinel immediately after processing
- **NIST NVD Direct Linking**: Each record links directly to the authoritative NIST National Vulnerability Database
- **Alert Template Generation**: Creates ready-to-use Sentinel analytics rules based on vulnerabilities
- **Docker Containerized**: Deployable anywhere with Docker for consistent operation and easy management
- **Microservices Ready**: Supports both all-in-one and microservices deployment patterns

## 📋 Quick Installation Guide

### Prerequisites

- Docker and Docker Compose
- NVD API key (free from https://nvd.nist.gov/developers/request-an-api-key)
- OpenAI API key
- Microsoft Sentinel workspace with Log Analytics access (for Sentinel integration)

### Docker Installation (Recommended)

The easiest way to run SOCca is using Docker:

```bash
# Clone the repository
git clone https://github.com/ianrelecker/SOCcaAI.git
cd SOCcaAI

# Make the Docker helper script executable
chmod +x docker-compose.sh

# Set up environment file
./docker-compose.sh setup
# Edit .env with your API keys and settings

# Start SOCca
./docker-compose.sh start
```

### Docker Deployment Options

SOCca supports multiple deployment options with Docker:

1. **All-in-one deployment**
   ```bash
   ./docker-compose.sh start
   ```

2. **Microservices deployment** (separate containers for monitor and Sentinel)
   ```bash
   ./docker-compose.sh micro
   ```

3. **Production deployment** (with resource limits)
   ```bash
   ./docker-compose.sh prod
   ```

### Useful Docker Commands

```bash
# Check service status
./docker-compose.sh status

# View logs
./docker-compose.sh logs

# Stop services
./docker-compose.sh stop

# Backup data
./docker-compose.sh backup

# Restore from backup
./docker-compose.sh restore
```

For complete step-by-step instructions, see the [Docker Quickstart Guide](DOCKER_QUICKSTART.md).

## 🛡️ Microsoft Sentinel Integration

### Setup Microsoft Sentinel Integration

1. **Get Microsoft Sentinel credentials**:
   - Navigate to your Log Analytics workspace in Azure Portal
   - Go to "Agents management" > "Log Analytics agent"
   - Note your Workspace ID and Primary Key

2. **Configure SOCca for Sentinel**:
   - Add these settings to your `.env` file:
   ```
   SENTINEL_WORKSPACE_ID=your-sentinel-workspace-id
   SENTINEL_PRIMARY_KEY=your-sentinel-primary-key
   SENTINEL_LOG_TYPE=SOCcaCVE    # Custom log type name
   SENTINEL_API_VERSION=2016-04-01
   ```

3. **Start the integration**:
   ```bash
   # Send vulnerability data to Sentinel
   python3 kryptos_working/sentinel_exporter.py --direct-send
   
   # Generate alert templates for Sentinel
   python3 kryptos_working/sentinel_exporter.py --alerts
   ```

### Using Vulnerability Data in Microsoft Sentinel

#### 1. Query the Data

Once data is in Sentinel, you can query it using KQL:

```kusto
// View all vulnerabilities
SOCcaCVE_CL
| limit 100

// High severity vulnerabilities in the last 24 hours
SOCcaCVE_CL
| where Severity_s == "Critical" or Severity_s == "High"
| where TimeGenerated > ago(24h)
| project CVE_ID_s, Description_s, CVSS_Score_d, AffectedProducts_s, MitreAttackTactics_s
```

#### 2. Create Workbooks

Create a custom workbook in Microsoft Sentinel:

1. Navigate to **Microsoft Sentinel** > **Workbooks** > **New**
2. Add a new query with this KQL:

```kusto
// CVE severity distribution over time
SOCcaCVE_CL
| summarize count() by Severity_s, bin(TimeGenerated, 1d)
| render columnchart
```

#### 3. Set Up Analytics Rules

Import the generated alert templates or create custom rules:

1. Go to **Microsoft Sentinel** > **Analytics** > **Create** > **Scheduled query rule**
2. Configure a rule using KQL like:

```kusto
SOCcaCVE_CL
| where CVSS_Score_d >= 8.0
| where AffectedProducts_s has_any("Windows Server", "Azure", "Office 365")
```

## 🚀 Docker Deployment Options

SOCca is designed to run in Docker containers with multiple deployment options to fit different needs:

### All-in-One Deployment (Recommended)

The simplest way to run SOCca with everything in a single container:

```bash
# Start SOCca with the helper script
./docker-compose.sh start
```

This runs the CVE monitor and Sentinel exporter in the same container, suitable for most use cases.

### Microservices Deployment

For more granular control, run the components in separate containers:

```bash
# Start SOCca as microservices
./docker-compose.sh micro
```

This runs:
- `socca-monitor` - Polls the NVD API and processes CVEs
- `socca-sentinel` - Exports data to Microsoft Sentinel on a schedule

### Production Deployment

For production environments with resource controls:

```bash
# Start SOCca in production mode
./docker-compose.sh prod
```

Features:
- CPU and memory limits
- Log rotation
- Separate production environment file
- Optimized for 24/7 operation

### Configuration & Management

The helper script provides comprehensive management:

```bash
# Show all available commands
./docker-compose.sh help

# Common operations
./docker-compose.sh logs     # View container logs
./docker-compose.sh status   # Check container status
./docker-compose.sh restart  # Restart containers
./docker-compose.sh backup   # Create a full backup
./docker-compose.sh restore  # Restore from backup
```

### Data Persistence

All data is stored in Docker volumes:
- `socca-data` - Databases and cached content
- `socca-logs` - Application logs
- `socca-kryptos-logs` - Component-specific logs

### Advanced Docker Configuration

For advanced users, edit docker-compose.yml directly:
- Add custom resource limits
- Configure networking options
- Set up additional volumes
- Add container labels

For detailed configuration options, refer to comments in the docker-compose.yml file.

## 📊 Advanced Configuration

### Customizing AI Analysis

To modify how vulnerabilities are analyzed:

1. Edit the system prompts in `soccav5.py` 
2. Adjust the token handling for larger or more detailed reports
3. Update the reporting structure to include additional fields

### Scheduling and Automation

The system has been optimized to ensure true real-time CVE processing with Microsoft Sentinel:

1. **Immediate CVE Processing**: Each CVE is sent to Microsoft Sentinel in real-time immediately after processing
2. **Verification**: Each send operation is verified to ensure data is properly tracked in the database
3. **Performance Metrics**: Processing time for each CVE is measured and logged
4. **Automatic Retry**: Failed sends are automatically retried with exponential backoff
5. **Alert Templates**: Alert templates are generated every 2 hours

For custom scheduling, you can use the microservices deployment mode:

```bash
# Start with dedicated Sentinel export service
./docker-compose.sh micro
```

## 📚 Documentation

- [Docker Quickstart Guide](DOCKER_QUICKSTART.md) - Docker deployment instructions
- [Architecture Documentation](ARCHITECTURE.md) - Comprehensive system architecture and component details
- [Microsoft Sentinel Integration Guide](kryptos_working/microsoft_sentinel.md) - Comprehensive Sentinel integration details

## 🔍 Troubleshooting

### Docker Deployment Issues

1. **Container doesn't start**:
   ```bash
   # Check container logs
   ./docker-compose.sh logs
   
   # Check container status
   ./docker-compose.sh status
   
   # Verify your .env file has required variables
   cat .env | grep -E 'API_KEY|WORKSPACE_ID'
   ```

2. **Database initialization errors**:
   ```bash
   # Force rebuild of the image
   ./docker-compose.sh build
   
   # Reset the container and volumes
   ./docker-compose.sh reset
   ./docker-compose.sh start
   ```

3. **Permission issues with volumes**:
   ```bash
   # Fix permissions in container
   docker exec -it socca bash -c "chmod -R 755 /app/kryptos_working/data"
   ```

4. **Container health checks failing**:
   ```bash
   # Check container health
   docker inspect --format "{{.State.Health.Status}}" socca
   
   # View container health logs
   docker inspect --format "{{json .State.Health}}" socca | jq
   ```

### Microsoft Sentinel Integration Issues

1. **Missing data in Sentinel**:
   - Verify SENTINEL_WORKSPACE_ID and SENTINEL_PRIMARY_KEY are correct
   - Check logs with `./docker-compose.sh logs`
   - Ensure outbound HTTPS connections are allowed

2. **API rate limiting**:
   - Adjust POLLING_INTERVAL in .env file to reduce API calls
   - Check NVD API logs for rate limit errors

3. **OpenAI API issues**:
   - Verify OPENAI_API_KEY is correctly set
   - Confirm that the specified models are available for your account
   - Check OpenAI response in logs

4. **Container networking issues**:
   ```bash
   # Check if container can reach external services
   docker exec -it socca curl -I https://services.nvd.nist.gov
   ```

For more detailed troubleshooting, see the logs:
```bash
./docker-compose.sh logs
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📞 Support

If you encounter any issues or have questions, please open an issue on GitHub.
