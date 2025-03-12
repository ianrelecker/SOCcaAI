# SOCca Docker Quickstart Guide

This guide will help you quickly deploy SOCca using Docker containers. Docker provides a consistent, isolated environment for SOCca to run, making deployment and management easier.

## Prerequisites

Before you begin, ensure you have:

1. Docker and Docker Compose installed on your system
2. NVD API key (get one for free at https://nvd.nist.gov/developers/request-an-api-key)
3. OpenAI API key
4. Microsoft Sentinel workspace (optional, for Sentinel integration)
5. At least 2GB of available RAM and 1GB of disk space

## Installation Steps

### 1. Clone the Repository

```bash
git clone https://github.com/ianrelecker/SOCcaAI.git
cd SOCcaAI
```

### 2. Make Helper Script Executable

```bash
chmod +x docker-compose.sh
```

### 3. Setup Environment

```bash
./docker-compose.sh setup
```

This will create a `.env` file from the template. Edit this file with your API keys and settings:

```bash
# Edit the .env file
nano .env
```

At minimum, you need to set:
- `NVD_API_KEY` - Your NVD API key
- `OPENAI_API_KEY` - Your OpenAI API key

For Microsoft Sentinel integration, also set:
- `SENTINEL_WORKSPACE_ID` - Your Log Analytics workspace ID
- `SENTINEL_PRIMARY_KEY` - Your Log Analytics primary key

### 4. Start SOCca

```bash
./docker-compose.sh start
```

This will:
1. Build the Docker image
2. Create necessary volumes
3. Start the SOCca container
4. Initialize the databases
5. Begin monitoring for new CVEs
6. Set up Sentinel integration (if configured)

### 5. Verify Operation

Check that everything is working properly:

```bash
# View container status
./docker-compose.sh status

# View logs
./docker-compose.sh logs
```

You should see logs indicating successful startup and CVE monitoring operations.

## Basic Operations

### Managing SOCca

```bash
# Stop SOCca
./docker-compose.sh stop

# Restart SOCca
./docker-compose.sh restart

# Check logs
./docker-compose.sh logs

# Check container status
./docker-compose.sh status
```

### Data Management

```bash
# Create a backup
./docker-compose.sh backup

# Restore from backup
./docker-compose.sh restore

# Reset everything (caution: destroys all data)
./docker-compose.sh reset
```

## Alternative Deployment Options

### Microservices Deployment

To run components in separate containers:

```bash
./docker-compose.sh micro
```

This deploys:
- `socca-monitor` - Handles CVE monitoring and AI analysis
- `socca-sentinel` - Handles Sentinel integration and exports

### Production Deployment

For production environments with resource limits:

```bash
./docker-compose.sh prod
```

This configures:
- CPU and memory limits
- Log rotation
- Optimized for long-term reliability

## Accessing Data

SOCca stores data in Docker volumes:

```bash
# List all volumes
docker volume ls | grep socca

# Inspect volume contents
docker run --rm -v socca-data:/data alpine ls -la /data
```

## Upgrading SOCca

To upgrade to a newer version:

```bash
# Pull latest code
git pull

# Rebuild the image
./docker-compose.sh build

# Restart the services
./docker-compose.sh restart
```

## Troubleshooting

### Common Issues

1. **Container fails to start**
   ```bash
   # Check detailed logs
   ./docker-compose.sh logs
   ```

2. **API connection issues**
   ```bash
   # Verify container can connect to external services
   docker exec -it socca curl -I https://services.nvd.nist.gov
   docker exec -it socca curl -I https://api.openai.com
   ```

3. **Volume permission issues**
   ```bash
   # Fix permissions
   docker exec -it socca bash -c "chmod -R 755 /app/kryptos_working/data"
   ```

### Checking Container Health

```bash
# View container health status
docker inspect --format "{{.State.Health.Status}}" socca
```

## Next Steps

- Configure custom OpenAI models in your .env file
- Set up Microsoft Sentinel workbooks using the templates
- Explore the architecture documentation to understand the system better

For more detailed information, refer to the [main documentation](README.md) and [architecture document](ARCHITECTURE.md).