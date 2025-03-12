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

## ⚙️ Configuration (.env file)

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