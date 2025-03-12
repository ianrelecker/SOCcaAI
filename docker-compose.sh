#!/bin/bash
# Helper script for Docker deployment of SOCca

set -e  # Exit on error

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to display help
show_help() {
    echo -e "${BLUE}SOCca Docker Helper Script${NC}"
    echo
    echo "Usage: $0 [command]"
    echo
    echo "Commands:"
    echo "  start       - Start SOCca (all-in-one deployment)"
    echo "  stop        - Stop SOCca containers"
    echo "  restart     - Restart SOCca containers"
    echo "  logs        - View logs from SOCca containers"
    echo "  status      - Check status of SOCca containers"
    echo "  build       - Build SOCca Docker image"
    echo "  micro       - Start SOCca in microservices mode (separate containers)"
    echo "  prod        - Start SOCca in production mode (with resource limits)"
    echo "  backup      - Backup SOCca data"
    echo "  restore     - Restore SOCca data from backup"
    echo "  reset       - Remove all SOCca containers, volumes, and data"
    echo "  setup       - Set up SOCca environment file"
    echo "  help        - Show this help message"
    echo
    echo -e "${YELLOW}Note:${NC} Make sure Docker and Docker Compose are installed"
    echo
}

# Check if docker is installed
check_docker() {
    if ! command -v docker &> /dev/null; then
        echo -e "${RED}Error: Docker is not installed. Please install Docker first.${NC}"
        exit 1
    fi

    if ! command -v docker-compose &> /dev/null; then
        echo -e "${RED}Error: Docker Compose is not installed. Please install Docker Compose first.${NC}"
        exit 1
    fi
}

# Check if environment file exists
check_env() {
    if [ ! -f .env ]; then
        echo -e "${YELLOW}Warning: .env file not found. Would you like to create one from template? (y/n)${NC}"
        read -r create_env
        if [[ $create_env =~ ^[Yy]$ ]]; then
            setup_env
        else
            echo -e "${RED}Error: .env file is required for SOCca to function correctly.${NC}"
            exit 1
        fi
    fi
}

# Setup environment file
setup_env() {
    if [ -f .env.example ]; then
        cp .env.example .env
        echo -e "${GREEN}.env file created from template.${NC}"
        echo -e "${YELLOW}Please edit the .env file to set your API keys and configuration.${NC}"
        echo -e "${BLUE}Required variables:${NC}"
        echo "  - NVD_API_KEY (get from https://nvd.nist.gov/developers/request-an-api-key)"
        echo "  - OPENAI_API_KEY (get from https://platform.openai.com/)"
        echo
        echo -e "${BLUE}For Microsoft Sentinel integration:${NC}"
        echo "  - SENTINEL_WORKSPACE_ID"
        echo "  - SENTINEL_PRIMARY_KEY"
        echo
        echo -e "${GREEN}Run '$0 start' after configuring your .env file${NC}"
    else
        echo -e "${RED}Error: .env.example file not found.${NC}"
        exit 1
    fi
}

# Start all-in-one deployment
start_allinone() {
    check_env
    echo -e "${BLUE}Starting SOCca (all-in-one deployment)...${NC}"
    docker-compose up -d socca
    echo -e "${GREEN}SOCca started. View logs with '$0 logs'${NC}"
}

# Start microservices deployment
start_micro() {
    check_env
    echo -e "${BLUE}Starting SOCca (microservices deployment)...${NC}"
    # Uncomment the service definitions in docker-compose.yml
    sed -i.bak -e 's/# socca-monitor:/socca-monitor:/g' \
              -e 's/#   build:/  build:/g' \
              -e 's/#   container_name:/  container_name:/g' \
              -e 's/#   restart:/  restart:/g' \
              -e 's/#   volumes:/  volumes:/g' \
              -e 's/#     -/    -/g' \
              -e 's/#   env_file:/  env_file:/g' \
              -e 's/#   environment:/  environment:/g' \
              -e 's/#   command:/  command:/g' \
              -e 's/#   healthcheck:/  healthcheck:/g' \
              -e 's/#   depends_on:/  depends_on:/g' \
              docker-compose.yml

    sed -i.bak -e 's/# socca-sentinel:/socca-sentinel:/g' docker-compose.yml
    
    # Start the services
    docker-compose up -d socca-monitor socca-sentinel
    echo -e "${GREEN}SOCca microservices started. View logs with '$0 logs'${NC}"
    
    # Restore the original file
    mv docker-compose.yml.bak docker-compose.yml
}

# Start production deployment
start_prod() {
    check_env
    echo -e "${BLUE}Starting SOCca (production deployment)...${NC}"
    
    # Uncomment the production service definition in docker-compose.yml
    sed -i.bak -e 's/# socca-prod:/socca-prod:/g' \
              -e 's/#   build:/  build:/g' \
              -e 's/#   container_name:/  container_name:/g' \
              -e 's/#   restart:/  restart:/g' \
              -e 's/#   volumes:/  volumes:/g' \
              -e 's/#     -/    -/g' \
              -e 's/#   env_file:/  env_file:/g' \
              -e 's/#   environment:/  environment:/g' \
              -e 's/#   deploy:/  deploy:/g' \
              -e 's/#     resources:/    resources:/g' \
              -e 's/#       limits:/      limits:/g' \
              -e 's/#         cpus:/        cpus:/g' \
              -e 's/#         memory:/        memory:/g' \
              -e 's/#       reservations:/      reservations:/g' \
              -e 's/#   logging:/  logging:/g' \
              -e 's/#     driver:/    driver:/g' \
              -e 's/#     options:/    options:/g' \
              -e 's/#       max-size:/      max-size:/g' \
              -e 's/#       max-file:/      max-file:/g' \
              docker-compose.yml
    
    # Check if .env.prod exists, if not create from .env
    if [ ! -f .env.prod ]; then
        cp .env .env.prod
        echo -e "${YELLOW}Created .env.prod from .env file. Consider reviewing it for production settings.${NC}"
    fi
    
    # Start the production service
    docker-compose up -d socca-prod
    echo -e "${GREEN}SOCca production deployment started. View logs with '$0 logs'${NC}"
    
    # Restore the original file
    mv docker-compose.yml.bak docker-compose.yml
}

# Stop containers
stop_containers() {
    echo -e "${BLUE}Stopping SOCca containers...${NC}"
    docker-compose down
    echo -e "${GREEN}SOCca containers stopped.${NC}"
}

# View logs
view_logs() {
    echo -e "${BLUE}Viewing SOCca logs (press Ctrl+C to exit)...${NC}"
    docker-compose logs -f
}

# Build SOCca image
build_image() {
    echo -e "${BLUE}Building SOCca Docker image...${NC}"
    docker-compose build
    echo -e "${GREEN}SOCca Docker image built.${NC}"
}

# Check status of containers
check_status() {
    echo -e "${BLUE}SOCca container status:${NC}"
    docker-compose ps
}

# Backup SOCca data
backup_data() {
    backup_dir="./backup_$(date +%Y%m%d_%H%M%S)"
    echo -e "${BLUE}Backing up SOCca data to $backup_dir...${NC}"
    
    # Create backup directory
    mkdir -p "$backup_dir"
    
    # Stop containers to ensure data consistency
    echo -e "${YELLOW}Stopping containers for consistent backup...${NC}"
    docker-compose stop
    
    # Backup volumes
    echo "Backing up volumes..."
    docker run --rm -v socca-data:/source -v $(pwd)/$backup_dir:/backup \
        alpine tar -czf /backup/socca-data.tar.gz -C /source .
    
    docker run --rm -v socca-logs:/source -v $(pwd)/$backup_dir:/backup \
        alpine tar -czf /backup/socca-logs.tar.gz -C /source .
    
    docker run --rm -v socca-kryptos-logs:/source -v $(pwd)/$backup_dir:/backup \
        alpine tar -czf /backup/socca-kryptos-logs.tar.gz -C /source .
    
    # Backup environment file
    cp .env "$backup_dir/.env.backup"
    
    # Restart containers
    echo -e "${YELLOW}Restarting containers...${NC}"
    docker-compose start
    
    echo -e "${GREEN}Backup completed to $backup_dir${NC}"
}

# Restore from backup
restore_data() {
    echo -e "${BLUE}Available backups:${NC}"
    ls -d backup_*/ 2>/dev/null || { echo -e "${RED}No backups found.${NC}"; exit 1; }
    
    echo -e "${YELLOW}Enter backup directory name to restore from:${NC}"
    read -r backup_dir
    
    if [ ! -d "$backup_dir" ]; then
        echo -e "${RED}Error: Backup directory $backup_dir not found.${NC}"
        exit 1
    fi
    
    echo -e "${YELLOW}Warning: This will overwrite current data. Proceed? (y/n)${NC}"
    read -r confirm
    if [[ ! $confirm =~ ^[Yy]$ ]]; then
        echo -e "${RED}Restore cancelled.${NC}"
        exit 1
    fi
    
    # Stop containers
    echo -e "${YELLOW}Stopping containers...${NC}"
    docker-compose down
    
    # Restore volumes
    echo "Restoring volumes..."
    docker run --rm -v socca-data:/target -v $(pwd)/$backup_dir:/backup \
        alpine sh -c "rm -rf /target/* && tar -xzf /backup/socca-data.tar.gz -C /target"
    
    docker run --rm -v socca-logs:/target -v $(pwd)/$backup_dir:/backup \
        alpine sh -c "rm -rf /target/* && tar -xzf /backup/socca-logs.tar.gz -C /target"
    
    docker run --rm -v socca-kryptos-logs:/target -v $(pwd)/$backup_dir:/backup \
        alpine sh -c "rm -rf /target/* && tar -xzf /backup/socca-kryptos-logs.tar.gz -C /target"
    
    # Restore environment file (optional)
    if [ -f "$backup_dir/.env.backup" ]; then
        echo -e "${YELLOW}Restore environment file? (y/n)${NC}"
        read -r restore_env
        if [[ $restore_env =~ ^[Yy]$ ]]; then
            cp "$backup_dir/.env.backup" .env
            echo "Environment file restored."
        fi
    fi
    
    # Start containers
    echo -e "${YELLOW}Starting containers...${NC}"
    docker-compose up -d
    
    echo -e "${GREEN}Restore completed from $backup_dir${NC}"
}

# Reset everything
reset_all() {
    echo -e "${RED}WARNING: This will remove all SOCca containers, volumes, and data!${NC}"
    echo -e "${RED}This action cannot be undone. Proceed? (y/n)${NC}"
    read -r confirm
    if [[ ! $confirm =~ ^[Yy]$ ]]; then
        echo -e "${GREEN}Reset cancelled.${NC}"
        exit 1
    fi
    
    echo -e "${YELLOW}Removing all SOCca containers and volumes...${NC}"
    docker-compose down -v
    
    echo -e "${GREEN}Reset completed. Use '$0 setup' to set up SOCca again.${NC}"
}

# Main execution
check_docker

# Parse command line arguments
if [ $# -eq 0 ]; then
    show_help
    exit 1
fi

case "$1" in
    start)
        start_allinone
        ;;
    stop)
        stop_containers
        ;;
    restart)
        stop_containers
        start_allinone
        ;;
    logs)
        view_logs
        ;;
    status)
        check_status
        ;;
    build)
        build_image
        ;;
    micro)
        start_micro
        ;;
    prod)
        start_prod
        ;;
    backup)
        backup_data
        ;;
    restore)
        restore_data
        ;;
    reset)
        reset_all
        ;;
    setup)
        setup_env
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        echo -e "${RED}Error: Unknown command '$1'${NC}"
        show_help
        exit 1
        ;;
esac

exit 0