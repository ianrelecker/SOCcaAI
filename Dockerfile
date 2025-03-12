# Multi-stage build for SOCca

# Build stage
FROM python:3.10-slim AS builder

# Set working directory
WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libxml2-dev \
    libxslt-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements file
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# Runtime stage
FROM python:3.10-slim

# Set working directory
WORKDIR /app

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV TZ=UTC
ENV PYTHONPATH=/app

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libxml2 \
    libxslt1.1 \
    sqlite3 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Copy installed Python packages from builder stage
COPY --from=builder /install /usr/local

# Copy source code
COPY . .

# Create necessary directories with proper permissions
RUN mkdir -p /app/logs \
    /app/kryptos_working/logs \
    /app/kryptos_working/data/cache \
    /app/kryptos_working/data/exports \
    /app/kryptos_working/data/sentinel_output \
    && chmod +x /app/startup.sh

# Create and setup volumes
VOLUME ["/app/kryptos_working/data", "/app/logs", "/app/kryptos_working/logs"]

# Use non-root user for security
RUN useradd -m socca
RUN chown -R socca:socca /app
USER socca

# Health check
HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD python -c "import sqlite3; sqlite3.connect('/app/kryptos_working/processed_cves.db').close() && echo 'Database connection successful'" || exit 1

# Run the application
ENTRYPOINT ["/app/startup.sh"]