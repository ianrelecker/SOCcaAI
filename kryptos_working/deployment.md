# SOCca Deployment Guide

This document provides detailed instructions for deploying SOCca both locally and to Azure using pipelines.

## Local Deployment

### Prerequisites

1. Python 3.8+ installed on your system
2. Git for cloning the repository
3. API keys:
   - NVD API key (free from https://nvd.nist.gov/developers/request-an-api-key)
   - OpenAI API key
   - Microsoft Sentinel workspace credentials (Workspace ID and Primary Key)

### Installation Steps

1. **Clone the repository**:
   ```bash
   git clone https://github.com/yourusername/soccav2.git
   cd soccav2
   ```

2. **Install dependencies**:
   ```bash
   # Make the installation script executable
   chmod +x install_dependencies.sh
   
   # Run the installation script
   ./install_dependencies.sh
   ```
   
   The script will:
   - Install required Python packages
   - Create necessary directories
   - Set up symbolic links for kryptos_working
   - Set executable permissions on scripts

3. **Configure environment**:
   ```bash
   cp .env.example .env
   # Edit .env with your API keys and configuration
   nano .env
   ```
   
   Key environment variables to configure:
   - `NVD_API_KEY`: Your NVD API key
   - `OPENAI_API_KEY`: Your OpenAI API key
   - Microsoft Sentinel integration settings:
     - `SENTINEL_WORKSPACE_ID`: Your Sentinel workspace ID
     - `SENTINEL_PRIMARY_KEY`: Your Sentinel primary key
     - `SENTINEL_LOG_TYPE`: Custom log type (default: SOCcaCVE)
     - `SENTINEL_API_VERSION`: API version (default: 2016-04-01)

4. **Initialize databases**:
   ```bash
   python setup.py
   ```

### Running SOCca Locally

SOCca consists of several components that should run simultaneously in separate terminals:

1. **CVE Monitor** (collects and analyzes vulnerabilities):
   ```bash
   python kryptos_working/mainv2.py
   ```

2. **Report Generator** (creates periodic summaries):
   ```bash
   python kryptos_working/hourlyreportgen.py
   ```

3. **Microsoft Sentinel Exporter** (sends data to Sentinel):
   ```bash
   # Send latest vulnerabilities directly to Microsoft Sentinel
   python kryptos_working/sentinel_exporter.py --direct-send
   
   # Or generate alert templates for Microsoft Sentinel
   python kryptos_working/sentinel_exporter.py --alerts
   
   # Or export to file for manual upload
   python kryptos_working/sentinel_exporter.py --file-export
   ```

For long-term deployments, you may want to set up these components as system services using systemd, supervisor, or similar tools.

## Azure Deployment

SOCca can be deployed to Azure using Azure Pipelines and Azure Web App services.

### Prerequisites

1. Azure account with permission to create web apps
2. Azure DevOps project for CI/CD pipelines
3. Service connection in Azure DevOps configured to your Azure subscription

### Pipeline Configuration

1. **Connect your repository to Azure DevOps**:
   - Set up a new project in Azure DevOps
   - Import your Git repository
   - Set up a service connection to your Azure subscription

2. **Set up pipeline variables**:
   In your Azure DevOps project, go to Pipelines > Library > Variable groups and create a group with:
   
   - `NVD_API_KEY`: Your NVD API key
   - `OPENAI_API_KEY`: Your OpenAI API key
   - `SENTINEL_WORKSPACE_ID`: Your Microsoft Sentinel workspace ID
   - `SENTINEL_PRIMARY_KEY`: Your Microsoft Sentinel primary key
   - `SENTINEL_LOG_TYPE`: Custom log type (default: SOCcaCVE)
   - `SENTINEL_API_VERSION`: API version (default: 2016-04-01)

3. **Use the existing azure-pipelines.yml file**
   
   SOCca already includes an Azure Pipelines configuration file that:
   - Runs tests
   - Installs dependencies
   - Deploys to an Azure Web App
   - Configures environment variables

### Creating Azure Resources

1. **Create an Azure App Service**:
   ```bash
   # Using Azure CLI
   az group create --name socca-resources --location eastus
   
   az appservice plan create \
     --name socca-service-plan \
     --resource-group socca-resources \
     --sku B1 \
     --is-linux
   
   az webapp create \
     --resource-group socca-resources \
     --plan socca-service-plan \
     --name socca-sentinel \
     --runtime "PYTHON:3.10" \
     --startup-file startup.sh
   ```

2. **Configure Web App settings**:
   ```bash
   az webapp config appsettings set \
     --resource-group socca-resources \
     --name socca-sentinel \
     --settings \
       SCM_DO_BUILD_DURING_DEPLOYMENT=true \
       ENABLE_ORYX_BUILD=true \
       NVD_API_KEY="your-nvd-api-key" \
       OPENAI_API_KEY="your-openai-api-key" \
       SENTINEL_WORKSPACE_ID="your-sentinel-workspace-id" \
       SENTINEL_PRIMARY_KEY="your-sentinel-primary-key" \
       SENTINEL_LOG_TYPE="SOCcaCVE" \
       SENTINEL_API_VERSION="2016-04-01"
   ```

### Running the Pipeline

1. Go to your Azure DevOps project
2. Navigate to Pipelines
3. Create a new pipeline using the existing azure-pipelines.yml file
4. Run the pipeline

The pipeline will:
1. Test the application
2. Install dependencies
3. Deploy to the Azure Web App
4. Configure the environment variables

### Post-Deployment Verification

After deployment:

1. **Check Web App logs**:
   ```bash
   az webapp log tail --name socca-sentinel --resource-group socca-resources
   ```

2. **Verify sentinel_exporter.py is running**:
   - Check the logs for successful data transmission:
   ```bash
   az webapp log download --name socca-sentinel --resource-group socca-resources
   ```

3. **Verify Microsoft Sentinel integration**:
   - Check the Log Analytics workspace for new logs
   - Look for the custom log type you configured (e.g., SOCcaCVE_CL)
   - Run a KQL query to verify data ingestion:
   ```
   SOCcaCVE_CL
   | limit 10
   ```

## Troubleshooting

### Common Local Deployment Issues

1. **Missing dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Permission issues with scripts**:
   ```bash
   chmod +x kryptos_working/*.py
   ```

3. **Database initialization failures**:
   ```bash
   # Remove existing databases and recreate
   rm -f *.db
   python setup.py
   ```

### Common Azure Deployment Issues

1. **Pipeline failures**:
   - Check that your service connection is configured correctly
   - Verify all required pipeline variables are set

2. **Startup issues in Azure**:
   - Check Web App logs for startup errors
   - Verify startup.sh has executable permissions
   - Make sure the app settings are correctly configured

3. **Microsoft Sentinel integration failures**:
   - Verify workspace ID and primary key are correct
   - Check logs for connection errors to Microsoft Sentinel
   - Verify network security groups allow outbound HTTPS traffic

## References

- [Azure Web Apps Documentation](https://docs.microsoft.com/en-us/azure/app-service/)
- [Azure Pipelines Documentation](https://docs.microsoft.com/en-us/azure/devops/pipelines/)
- [Microsoft Sentinel Documentation](https://docs.microsoft.com/en-us/azure/sentinel/)
- [Log Analytics Data Collector API](https://docs.microsoft.com/en-us/azure/azure-monitor/logs/data-collector-api)