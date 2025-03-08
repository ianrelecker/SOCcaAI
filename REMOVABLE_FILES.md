# Removable Files

The following files can be safely deleted from the repository as they are no longer needed after removing Azure pipelines deployment support:

1. `azure-pipelines.yml` - The Azure Pipelines configuration file

No other files need to be deleted, as the documentation has been updated to remove references to Azure pipelines while maintaining the core functionality for Linux server deployment.

## Modified Files

The following files have been modified to remove Azure pipelines references:

1. `startup.sh` - Removed Azure App Service references
2. `kryptos_working/deployment.md` - Completely revised to focus on Linux server deployment
3. `kryptos_working/quickstart.md` - Replaced Azure deployment section with Linux server deployment

## Additional Simplification (Optional)

If you want to further simplify the repository, consider the following optional cleanup:

1. Review `SENTINEL_INTEGRATION_SUMMARY.md` to remove any Azure deployment references
2. Check the `.env.example` file (if it exists) to remove any Azure-specific environment variables
3. Update any remaining documentation files that may reference Azure