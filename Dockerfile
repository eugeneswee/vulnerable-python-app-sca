# Use older Python base image with vulnerabilities
FROM python:3.8.10-slim

LABEL maintainer="SCA Lab"
LABEL version="1.0"
LABEL description="Vulnerable Python app for SCA testing"

WORKDIR /app

# Upgrade pip to avoid warnings but pin to compatible version
RUN pip install --upgrade pip==21.3.1

# Copy requirements first for better layer caching
COPY requirements.txt .

# Install dependencies with specific versions to avoid conflicts
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY app.py .

# Create non-root user for security (though app still has vulnerabilities)
RUN useradd -m -u 1000 appuser && chown -R appuser:appuser /app
USER appuser

EXPOSE 5001

# Note: Health check removed due to Debian Buster EOL issues
# The Jenkins pipeline test stage will verify application functionality

CMD ["python", "app.py"]
