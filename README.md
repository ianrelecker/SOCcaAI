# SOCcaAI 🛡️

**Supercharge your security operations with AI-powered vulnerability intelligence!**

SOCcaAI is a blazing-fast pipeline that:
1. 🔍 **Pulls CVEs** from NVD API in real-time
2. 🧠 **Analyzes them with OpenAI** for contextual insight
3. 🚀 **Sends them to Microsoft Sentinel** for immediate action

## ✨ Why SOCcaAI?

Traditional vulnerability monitoring is slow, noisy, and lacks context. SOCcaAI transforms this experience:

- **Real-time vulnerability detection** - Know about threats as they emerge
- **AI-powered analysis** - Get detailed impact assessments beyond CVSS scores
- **Instant Sentinel integration** - Feed your SIEM with pre-analyzed, actionable intelligence
- **Zero maintenance** - Single container with persistent storage and automatic recovery

## 🚀 Quick Start

### Option 1: Using the published Docker image

```bash
# Pull and run the published image with environment variables
docker run -d --name socca \
  -e NVD_API_KEY=your_nvd_api_key \
  -e OPENAI_API_KEY=your_openai_api_key \
  -e SENTINEL_WORKSPACE_ID=your_workspace_id \
  -e SENTINEL_PRIMARY_KEY=your_primary_key \
  -v socca_data:/app/data \
  -v socca_logs:/app/logs \
  ghcr.io/ianrelecker/socca:latest
```

### Option 2: Using an environment file

Create a `.env` file with your variables:
```
# IMPORTANT: Do not include comments on the same line as values!
NVD_API_KEY=your_nvd_api_key
OPENAI_API_KEY=your_openai_api_key
SENTINEL_WORKSPACE_ID=your_workspace_id
SENTINEL_PRIMARY_KEY=your_primary_key
POLLING_INTERVAL=60
```

Then run:
```bash
docker run -d --name socca \
  --env-file .env \
  -v socca_data:/app/data \
  -v socca_logs:/app/logs \
  ghcr.io/ianrelecker/socca:latest
```

### Option 3: Using Docker Compose

Create a `docker-compose.yml` file:
```yaml
version: '3'
services:
  socca:
    image: ghcr.io/ianrelecker/socca:latest
    container_name: socca
    env_file: .env
    volumes:
      - socca_data:/app/data
      - socca_logs:/app/logs
    restart: unless-stopped

volumes:
  socca_data:
  socca_logs:
```

Then simply run:
```bash
docker-compose up -d
```

### Option 4: Build from source

```bash
# 1. Clone the repository
git clone https://github.com/ianrelecker/soccaAi.git
cd socca

# 2. Configure your environment
cp .env.example .env
# Edit .env with your API keys

# 3. Deploy
./deploy.sh
```

## ⚙️ Configuration (.env file)

```
# Required API Keys
NVD_API_KEY=your_nvd_api_key              # From https://nvd.nist.gov/developers/request-an-api-key
OPENAI_API_KEY=your_openai_api_key        # From https://platform.openai.com/
SENTINEL_WORKSPACE_ID=your_workspace_id   # From Microsoft Sentinel
SENTINEL_PRIMARY_KEY=your_primary_key     # From Microsoft Sentinel

# Optional Settings
OPENAI_MODEL=gpt-4o-mini                  # OpenAI model to use
POLLING_INTERVAL=60                      # Seconds between NVD API checks
```

## 📊 How It Works

1. **Monitor**: Continuously poll the NVD API for new CVEs
2. **Analyze**: Use OpenAI to generate comprehensive security reports with:
   - Severity assessment and impact analysis
   - Affected systems and exploitation vectors
   - Detection strategies with KQL queries
   - MITRE ATT&CK mapping
3. **Integrate**: Send enriched data to Microsoft Sentinel in real-time
4. **Alert**: Generate actionable templates for security response

## 📝 Logs and Data

```bash
# View real-time logs
docker logs -f socca

# Check the database (contains all processed CVEs)
docker exec -it socca sqlite3 /app/data/socca.db 'SELECT COUNT(*) FROM cves'

# View recent alert templates 
docker exec -it socca ls -la /app/data/
```

## 🔄 System Architecture

SOCcaAI uses a minimal, efficient architecture:
- **Python** with SQLite for lightweight, persistent storage
- **Docker** for easy deployment and isolation
- **OpenAI API** for advanced vulnerability analysis
- **Microsoft Sentinel API** for security integration

All packaged in a single file with no bloat or unnecessary dependencies!

## 📊 Microsoft Sentinel Resources

Ready-to-use Sentinel resources are available in the `sentinel_resources` directory:

- **KQL Queries**: Advanced search templates for finding critical vulnerabilities
- **Workbooks**: Interactive dashboards for CVE visualization and trends
- **Detection Rules**: Pre-built analytics rules for automated alerting
- **Playbooks**: Response automation workflows for incident management
- **Hunting Queries**: Specialized queries for proactive threat hunting

See the [sentinel_resources/README.md](sentinel_resources/README.md) for implementation details.

---
