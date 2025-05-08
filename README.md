# Container Optimization Tool (COT)

A powerful CLI tool for analyzing and optimizing Docker containers.

![Container Optimization Tool](https://drive.google.com/file/d/11lD6Yk3OrllETneSWG0zdN2fLptEmwhi/view?usp=sharing)
https://drive.google.com/file/d/1cc3PiD_k6QrFzTqa92m6jPr07yjZFuED/view?usp=sharing
## Features

- **Image Analysis**: Deep inspection of Docker images to identify optimization opportunities
- **Multi-Stage Build Suggestions**: Automatically generates multi-stage Dockerfile templates
- **Security Scanning**: Identifies common vulnerabilities in container images
- **Dockerfile Optimization**: Analyzes and improves existing Dockerfiles
- **Cost Estimation**: Calculates potential savings from optimizations

## Installation

```bash
# Clone the repository
git clone https://github.com/byteakp/OptiDock.git
cd container-optimization-tool

# Install requirements
pip install -r requirements.txt

# Install the tool
pip install -e .

# Verify installation
container-opt --version
```

## Usage

### Analyze a Docker Image

```bash
# Analyze an image for all optimization opportunities
container-opt analyze python:3.9

# Analyze for specific optimization types
container-opt analyze --type security nginx:latest
container-opt analyze --type size node:14
container-opt analyze --type cost postgres:13

# Analyze with an existing Dockerfile
container-opt analyze --dockerfile ./Dockerfile myapp:latest

# Show only summary information
container-opt analyze --no-details python:3.9
```

### Optimize a Dockerfile

```bash
# Generate an optimized version of a Dockerfile
container-opt optimize-dockerfile ./Dockerfile

# Save to a custom location
container-opt optimize-dockerfile ./Dockerfile --output ./Dockerfile.optimized
```

## Sample Output

```
================================================================================
🐳 CONTAINER OPTIMIZATION REPORT FOR python:3.9
================================================================================
📊 Image Size: 943.57 MB
📅 Report Generated: 2025-05-08 10:15:32
--------------------------------------------------------------------------------

🔒 SECURITY VULNERABILITIES: 3
--------------------------------------------------------------------------------
CRITICAL: 0
HIGH: 1
MEDIUM: 2
LOW: 0

Details:
  1. [HIGH] pyyaml: Code Execution vulnerability in PyYAML
     Fix: Update to version 5.4.0
     CVE: CVE-2020-14343

  2. [MEDIUM] urllib3: Improper certificate validation
     Fix: Update to version 1.26.5
     CVE: CVE-2021-33503

  3. [MEDIUM] libc6: Memory corruption vulnerability
     Fix: Update to version 2.31-13+deb11u4
     CVE: CVE-2021-35942


📦 SIZE OPTIMIZATION OPPORTUNITIES: 4
--------------------------------------------------------------------------------
Total Potential Size Reduction: ~195.0 MB

Details:
  1. APT_CACHE: Package manager cache not cleaned after installation
     Potential Savings: 20-100MB
     Suggestion: Add 'apt-get clean && rm -rf /var/lib/apt/lists/*' after installations

  2. PIP_CACHE: Python pip cache not removed
     Potential Savings: 10-50MB
     Suggestion: Use '--no-cache-dir' with pip or remove cache directory

  3. TEMP_FILES: Temporary files and documentation may be included
     Potential Savings: 5-50MB
     Suggestion: Remove temporary files, documentation, and test files

  4. MULTI_STAGE: Python web application could benefit from multi-stage build
     Potential Savings: 100-200MB
     Suggestion: Use multi-stage build to separate build and runtime dependencies


📄 DOCKERFILE OPTIMIZATION SUGGESTIONS: 3
--------------------------------------------------------------------------------

Details:
  1. Line 1: FROM python:3.9
     Suggestion: FROM python:3.10-slim
     Reason: Consider using a smaller base image like python:3.10-slim
     Potential Savings: 50-200MB

  2. Line 5: RUN pip install -r requirements.txt
     Suggestion: RUN pip install --no-cache-dir -r requirements.txt
     Reason: Use --no-cache-dir with pip to avoid storing package cache
     Potential Savings: 10-50MB

  3. Line 8: COPY . /app
     Suggestion: COPY . /app
     Reason: Consider using a .dockerignore file to exclude unnecessary files (node_modules, .git, etc.)
     Potential Savings: Variable, potentially 10-500MB


🏗️ MULTI-STAGE BUILD RECOMMENDATION
--------------------------------------------------------------------------------
A multi-stage build could significantly reduce image size.

Suggested Dockerfile:
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

# Copy only necessary files from builder
COPY --from=builder /usr/local/lib/python3.10/site-packages/ /usr/local/lib/python3.10/site-packages/
COPY --from=builder /app/ /app/

# Set Python path and run command
ENV PYTHONPATH=/app

CMD ["python", "app.py"]


💰 COST SAVINGS ESTIMATE
--------------------------------------------------------------------------------

Estimated Monthly Cost Savings (based on 10 containers):
- Storage: $0.02/month
- Transfer: $0.29/month
- Total: $0.31/month

Additional Benefits:
- Build time reduction: ~9 seconds per build
- Reduced deployment time: ~7 seconds per deployment
- Lower resource usage during container startup


🚀 SUMMARY RECOMMENDATIONS
--------------------------------------------------------------------------------
1. Fix 1 critical/high security vulnerabilities
2. Implement multi-stage build to significantly reduce image size
3. Clean package manager caches after installation

================================================================================
```

## Advanced Usage

### Configuration File

You can create a `cot.yaml` configuration file in your project to set defaults:

```yaml
default_optimization_type: size
report_detail_level: high
cost_calculator:
  container_count: 20
  monthly_deployments: 15
```

### Integration with CI/CD

Add to your GitHub Actions workflow:

```yaml
- name: Analyze Docker image
  run: |
    pip install container-optimization-tool
    container-opt analyze --type all myapp:latest --dockerfile ./Dockerfile
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
