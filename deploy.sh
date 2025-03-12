#!/bin/bash
# Deployment script for SOCca Core

set -e

echo "SOCca Core - Complete Rebuild and Deploy"
echo "======================================"

# Setup environment
[ ! -f .env ] && cp .env.example .env
echo "Environment file ready"

# Determine docker command
if command -v docker-compose &>/dev/null; then
    COMPOSE_CMD="docker-compose"
else
    COMPOSE_CMD="docker compose"
fi

# Stop and remove any existing containers
echo "Stopping and removing any existing containers..."
$COMPOSE_CMD down -v 2>/dev/null || true
docker rm -f socca 2>/dev/null || true

# Remove any old images
echo "Removing old images..."
docker rmi -f socca_socca 2>/dev/null || true

# Clean build and start
echo "Building and starting fresh container..."
$COMPOSE_CMD build --no-cache
$COMPOSE_CMD up -d

echo
echo "SOCca Core successfully deployed!"
echo "View logs with: docker logs -f socca"
echo