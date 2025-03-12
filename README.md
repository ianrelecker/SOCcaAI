# SOCca Core

Minimal Docker container that:
1. Pulls CVEs from NVD API
2. Analyzes them with OpenAI
3. Sends them to Microsoft Sentinel

## Overview

This container provides a streamlined pipeline for security vulnerability management. 
It constantly polls the NVD API for new vulnerabilities, analyzes them using AI, and 
sends the results directly to Microsoft Sentinel for integration into your security operations.

## Features

- Single Python file implementation
- Real-time CVE monitoring and analysis
- Immediate Sentinel integration
- Alert template generation
- NIST NVD direct linking

## Quick Start

```bash
# 1. Clone the repository
git clone <repository-url>
cd socca

# 2. Configure your environment
cp .env.example .env
# Edit .env with your API keys

# 3. Deploy
./deploy.sh
```

## Configuration (.env file)

```
# Required API Keys
NVD_API_KEY=your_nvd_api_key              # From https://nvd.nist.gov/developers/request-an-api-key
OPENAI_API_KEY=your_openai_api_key        # From https://platform.openai.com/
SENTINEL_WORKSPACE_ID=your_workspace_id   # From Microsoft Sentinel
SENTINEL_PRIMARY_KEY=your_primary_key     # From Microsoft Sentinel

# Optional Settings
OPENAI_MODEL=gpt-4o-mini                  # OpenAI model to use
POLLING_INTERVAL=600                      # Seconds between NVD API checks
```

## How It Works

1. The container polls the NVD API at regular intervals for new CVEs
2. Each new CVE is analyzed using OpenAI to generate a detailed security report
3. The CVE data and analysis are sent to Microsoft Sentinel via the Log Analytics API
4. Alert templates are generated to help security teams respond to threats

## Logs and Data

- All data is stored in a SQLite database within the Docker volume
- Logs are available via `docker logs socca`
- Database and alert templates are persisted in Docker volumes

## Docker Commands

```bash
# View logs
docker logs -f socca

# Stop container
docker-compose down

# Restart container
docker-compose restart
```

## Minimal Architecture

This solution uses:
- Python with SQLite for data storage
- Docker for containerization
- OpenAI API for vulnerability analysis
- Microsoft Sentinel Log Analytics API for security integration

All in a single file with no unnecessary dependencies.