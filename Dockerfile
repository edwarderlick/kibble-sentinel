# Production Dockerfile for Technocore PoUI Sentinel (kibble_agent.py)
FROM python:3.12-slim

# Prevent python from writing pyc files and buffering stdout
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PORT=5000

WORKDIR /app

# Install build dependencies if needed
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy dependency specifications and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY kibble_agent.py .
COPY pytest.ini .
COPY tests/ ./tests/

# Run tests during build to guarantee integrity
RUN pytest tests/

# Expose health server port
EXPOSE 5000

# Run kibble_agent.py
CMD ["python", "kibble_agent.py"]
