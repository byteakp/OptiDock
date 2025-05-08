# =====================================
# Original Dockerfile (Before Optimization)
# =====================================

FROM python:3.9

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . /app

RUN apt-get update && apt-get install -y curl vim

EXPOSE 8080

CMD ["python", "app.py"]

# =====================================
# Optimized Dockerfile (After Analysis)
# =====================================

# Build stage
FROM python:3.10-slim AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Runtime stage
FROM python:3.10-slim

WORKDIR /app

# Install runtime dependencies only
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Copy only necessary files from builder
COPY --from=builder /usr/local/lib/python3.10/site-packages/ /usr/local/lib/python3.10/site-packages/
COPY --from=builder /app/ /app/

# Set Python path and expose port
ENV PYTHONPATH=/app
EXPOSE 8080

# Create a non-root user and switch to it
RUN useradd -m appuser
USER appuser

CMD ["python", "app.py"]