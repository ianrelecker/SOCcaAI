FROM python:3.10-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1

# Install minimal dependencies
RUN apt-get update && apt-get install -y sqlite3 && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Install Python requirements
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Create directories and setup volumes
RUN mkdir -p /app/logs /app/data
VOLUME ["/app/data", "/app/logs"]

# Copy source code
COPY socca_core.py ./
RUN chmod +x ./socca_core.py

# Use non-root user
RUN useradd -m socca && chown -R socca:socca /app
USER socca

# Run the application
CMD ["python", "/app/socca_core.py"]