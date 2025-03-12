# SOCca Core Guidelines

## Project Overview
Minimal container that monitors CVEs from NVD API, analyzes with OpenAI, and exports to Microsoft Sentinel.

## Commands
- Build & run: `./deploy.sh`
- Run manually: `docker-compose up -d`
- View logs: `docker logs -f socca`
- Stop container: `docker-compose down`

## Code Style
- **Python**: Follow PEP 8
- **Imports**: Standard lib first, then third-party, then local
- **Functions**: Use type hints; document with docstrings
- **Variables**: Use snake_case; constants in UPPER_CASE
- **Error handling**: Use specific exception types with contextual logging
- **Database**: Always use context managers for connections
- **API calls**: Implement retry logic with exponential backoff
- **JSON**: Use proper serialization/deserialization, not string methods

## Architecture
Single Python file (socca_core.py) with three core functions:
1. Pull CVEs from NVD
2. Analyze with OpenAI
3. Send to Microsoft Sentinel

Data storage is handled by SQLite with persistent Docker volumes.