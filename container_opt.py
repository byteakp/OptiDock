#!/usr/bin/env python3
"""
Container Optimization Tool (COT) - A CLI tool for analyzing and optimizing Docker images

Features:
- Analyze Docker images for size optimization opportunities
- Suggest multi-stage builds to reduce image size
- Scan for security vulnerabilities
- Generate optimized Dockerfiles from existing ones
- Provide metrics on potential cost savings
"""

import argparse
import sys
import os
import json
import re
import subprocess
import tempfile
import shutil
from enum import Enum
from typing import Dict, List, Optional, Tuple, Any
import logging
from dataclasses import dataclass
from datetime import datetime
import textwrap

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("container-optimization-tool")

class ColoredFormatter(logging.Formatter):
    """Custom formatter to add colors to terminal output"""
    
    COLORS = {
        'WARNING': '\033[33m',  # Yellow
        'INFO': '\033[32m',     # Green
        'DEBUG': '\033[34m',    # Blue
        'CRITICAL': '\033[41m', # Red background
        'ERROR': '\033[31m'     # Red
    }
    RESET = '\033[0m'
    
    def format(self, record):
        log_message = super().format(record)
        if record.levelname in self.COLORS:
            log_message = f"{self.COLORS[record.levelname]}{log_message}{self.RESET}"
        return log_message

# Apply colored formatter to console handler
console_handler = logging.StreamHandler()
console_formatter = ColoredFormatter('%(levelname)s: %(message)s')
console_handler.setFormatter(console_formatter)
logger.handlers = [console_handler]

class OptimizationType(Enum):
    """Types of optimizations that can be performed"""
    SIZE = "size"
    SECURITY = "security"
    COST = "cost"
    ALL = "all"

@dataclass
class VulnerabilityIssue:
    """Container vulnerability issue data"""
    severity: str
    package: str
    description: str
    fix_version: Optional[str] = None
    cve_id: Optional[str] = None

@dataclass
class SizeIssue:
    """Container size issue data"""
    issue_type: str
    description: str
    potential_savings: str
    suggestion: str

@dataclass
class DockerfileOptimization:
    """Dockerfile optimization suggestion"""
    line_number: int
    original_line: str
    suggested_line: str
    reason: str
    savings_estimate: str

@dataclass
class OptimizationReport:
    """Full optimization report for a Docker image"""
    image_name: str
    image_size: str
    vulnerabilities: List[VulnerabilityIssue]
    size_issues: List[SizeIssue]
    dockerfile_optimizations: List[DockerfileOptimization]
    multi_stage_suggestion: Optional[str] = None
    estimated_cost_savings: Optional[str] = None
    report_date: datetime = datetime.now()

class DockerClient:
    """Wrapper for Docker commands"""
    
    @staticmethod
    def check_docker_available() -> bool:
        """Check if Docker is available on the system"""
        try:
            subprocess.run(["docker", "--version"], 
                          check=True, 
                          stdout=subprocess.PIPE, 
                          stderr=subprocess.PIPE)
            return True
        except (subprocess.SubprocessError, FileNotFoundError):
            return False
    
    @staticmethod
    def image_exists(image_name: str) -> bool:
        """Check if a Docker image exists locally"""
        try:
            result = subprocess.run(
                ["docker", "image", "inspect", image_name],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            return result.returncode == 0
        except subprocess.SubprocessError:
            return False
    
    @staticmethod
    def get_image_size(image_name: str) -> str:
        """Get the size of a Docker image"""
        try:
            result = subprocess.run(
                ["docker", "image", "inspect", image_name, "--format", "{{.Size}}"],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            size_bytes = int(result.stdout.strip())
            # Convert to human readable format
            for unit in ['B', 'KB', 'MB', 'GB']:
                if size_bytes < 1024.0:
                    return f"{size_bytes:.2f} {unit}"
                size_bytes /= 1024.0
            return f"{size_bytes:.2f} TB"
        except subprocess.SubprocessError:
            return "Unknown"
    
    @staticmethod
    def get_image_layers(image_name: str) -> List[Dict[str, Any]]:
        """Get layer info for a Docker image"""
        try:
            result = subprocess.run(
                ["docker", "image", "inspect", image_name, "--format", "{{json .RootFS.Layers}}"],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            return json.loads(result.stdout.strip())
        except (subprocess.SubprocessError, json.JSONDecodeError):
            return []
    
    @staticmethod
    def get_image_history(image_name: str) -> List[Dict[str, Any]]:
        """Get history of a Docker image to analyze commands used"""
        try:
            result = subprocess.run(
                ["docker", "history", "--no-trunc", "--format", "{{json .}}", image_name],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            # Each line is a separate JSON object
            history = []
            for line in result.stdout.strip().split('\n'):
                if line:
                    history.append(json.loads(line))
            return history
        except (subprocess.SubprocessError, json.JSONDecodeError):
            return []

class VulnerabilityScanner:
    """Perform security scans on Docker images"""
    
    @staticmethod
    def scan_image(image_name: str) -> List[VulnerabilityIssue]:
        """
        Scan image for security vulnerabilities.
        
        In a real implementation, this would use Trivy, Clair, or Docker Scout.
        This is a simplified mock implementation.
        """
        logger.info(f"Scanning image {image_name} for vulnerabilities...")
        
        # Mock vulnerabilities - in a real implementation, we'd use an actual scanner
        mock_vulnerabilities = []
        
        # Simulate finding common vulnerabilities
        if "python" in image_name:
            mock_vulnerabilities.extend([
                VulnerabilityIssue(
                    severity="HIGH",
                    package="pyyaml",
                    description="Code Execution vulnerability in PyYAML",
                    fix_version="5.4.0",
                    cve_id="CVE-2020-14343"
                ),
                VulnerabilityIssue(
                    severity="MEDIUM",
                    package="urllib3",
                    description="Improper certificate validation",
                    fix_version="1.26.5",
                    cve_id="CVE-2021-33503"
                )
            ])
        elif "node" in image_name or "javascript" in image_name:
            mock_vulnerabilities.extend([
                VulnerabilityIssue(
                    severity="CRITICAL",
                    package="lodash",
                    description="Prototype pollution in lodash",
                    fix_version="4.17.21",
                    cve_id="CVE-2021-23337"
                )
            ])
        elif "debian" in image_name or "ubuntu" in image_name:
            mock_vulnerabilities.extend([
                VulnerabilityIssue(
                    severity="HIGH",
                    package="openssl",
                    description="Buffer overflow vulnerability",
                    fix_version="1.1.1k-1",
                    cve_id="CVE-2021-3449"
                ),
                VulnerabilityIssue(
                    severity="MEDIUM",
                    package="libc6",
                    description="Memory corruption vulnerability",
                    fix_version="2.31-13+deb11u4",
                    cve_id="CVE-2021-35942"
                )
            ])
        
        # Add some generic vulnerabilities
        mock_vulnerabilities.append(
            VulnerabilityIssue(
                severity="LOW",
                package="base-image",
                description="Using outdated base image",
                fix_version="latest",
                cve_id=None
            )
        )
        
        logger.info(f"Found {len(mock_vulnerabilities)} potential vulnerabilities")
        return mock_vulnerabilities

class SizeOptimizer:
    """Analyze and optimize Docker image size"""
    
    @staticmethod
    def analyze_size_issues(image_name: str, history: List[Dict[str, Any]]) -> List[SizeIssue]:
        """Analyze Docker image for size optimization opportunities"""
        size_issues = []
        
        # Check for common patterns in history that suggest size issues
        apt_get_no_clean = False
        pip_cache_not_removed = False
        multiple_run_commands = 0
        previous_cmd = ""
        
        for item in history:
            cmd = item.get("CreatedBy", "")
            
            # Look for apt-get without clean
            if "apt-get install" in cmd and "apt-get clean" not in cmd:
                apt_get_no_clean = True
            
            # Look for pip install without cache removal
            if "pip install" in cmd and "--no-cache-dir" not in cmd:
                pip_cache_not_removed = True
            
            # Count RUN commands that could be combined
            if cmd.startswith("/bin/sh -c") and previous_cmd.startswith("/bin/sh -c"):
                multiple_run_commands += 1
                
            previous_cmd = cmd
        
        # Add size issues based on analysis
        if apt_get_no_clean:
            size_issues.append(
                SizeIssue(
                    issue_type="APT_CACHE",
                    description="Package manager cache not cleaned after installation",
                    potential_savings="20-100MB",
                    suggestion="Add 'apt-get clean && rm -rf /var/lib/apt/lists/*' after installations"
                )
            )
        
        if pip_cache_not_removed:
            size_issues.append(
                SizeIssue(
                    issue_type="PIP_CACHE",
                    description="Python pip cache not removed",
                    potential_savings="10-50MB",
                    suggestion="Use '--no-cache-dir' with pip or remove cache directory"
                )
            )
        
        if multiple_run_commands > 1:
            size_issues.append(
                SizeIssue(
                    issue_type="MULTIPLE_RUNS",
                    description=f"Found {multiple_run_commands} RUN commands that could be combined",
                    potential_savings="5-20MB",
                    suggestion="Combine RUN commands using && to reduce layer count"
                )
            )
            
        # Check for common file types that might be unnecessarily included
        size_issues.append(
            SizeIssue(
                issue_type="TEMP_FILES",
                description="Temporary files and documentation may be included",
                potential_savings="5-50MB",
                suggestion="Remove temporary files, documentation, and test files"
            )
        )
        
        # Check if multi-stage builds could be beneficial
        if "django" in image_name or "flask" in image_name or "fastapi" in image_name:
            size_issues.append(
                SizeIssue(
                    issue_type="MULTI_STAGE",
                    description="Python web application could benefit from multi-stage build",
                    potential_savings="100-200MB",
                    suggestion="Use multi-stage build to separate build and runtime dependencies"
                )
            )
        elif "node" in image_name or "react" in image_name or "vue" in image_name:
            size_issues.append(
                SizeIssue(
                    issue_type="MULTI_STAGE",
                    description="JavaScript application could benefit from multi-stage build",
                    potential_savings="300-500MB",
                    suggestion="Use multi-stage build to separate npm build from runtime"
                )
            )
        elif "golang" in image_name or "go:" in image_name:
            size_issues.append(
                SizeIssue(
                    issue_type="MULTI_STAGE",
                    description="Go application could benefit from multi-stage build",
                    potential_savings="700-900MB",
                    suggestion="Use multi-stage build to compile Go binary and copy to minimal base image"
                )
            )
            
        return size_issues

    @staticmethod
    def generate_multi_stage_dockerfile(image_name: str) -> Optional[str]:
        """Generate a multi-stage Dockerfile suggestion based on image analysis"""
        
        base_image = image_name
        if ":" in image_name:
            base_image = image_name.split(":")[0]
        
        # Define templates for different types of applications
        if "python" in base_image or "django" in base_image or "flask" in base_image:
            return textwrap.dedent("""
            # Build stage
            FROM python:3.10-slim AS builder
            
            WORKDIR /app
            
            # Install build dependencies
            RUN apt-get update && apt-get install -y --no-install-recommends \\
                build-essential \\
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
            """).strip()
            
        elif "node" in base_image or "javascript" in base_image or "react" in base_image:
            return textwrap.dedent("""
            # Build stage
            FROM node:18-alpine AS builder
            
            WORKDIR /app
            
            # Copy package files and install dependencies
            COPY package*.json ./
            RUN npm ci
            
            # Copy source and build
            COPY . .
            RUN npm run build
            
            # Runtime stage
            FROM nginx:alpine
            
            # Copy built files from builder to nginx
            COPY --from=builder /app/build /usr/share/nginx/html
            
            # Expose port and start nginx
            EXPOSE 80
            CMD ["nginx", "-g", "daemon off;"]
            """).strip()
            
        elif "golang" in base_image or "go:" in base_image:
            return textwrap.dedent("""
            # Build stage
            FROM golang:1.19-alpine AS builder
            
            WORKDIR /app
            
            # Copy go module files and download dependencies
            COPY go.mod go.sum ./
            RUN go mod download
            
            # Copy source code and build
            COPY . .
            RUN CGO_ENABLED=0 GOOS=linux go build -o /app/server .
            
            # Runtime stage - using scratch (minimal image)
            FROM scratch
            
            # Copy the compiled binary
            COPY --from=builder /app/server /server
            
            # Run the binary
            ENTRYPOINT ["/server"]
            """).strip()
            
        elif "java" in base_image or "maven" in base_image or "gradle" in base_image:
            return textwrap.dedent("""
            # Build stage
            FROM maven:3.8-openjdk-17 AS builder
            
            WORKDIR /app
            
            # Copy pom and download dependencies
            COPY pom.xml .
            RUN mvn dependency:go-offline
            
            # Copy source and build
            COPY src ./src
            RUN mvn package -DskipTests
            
            # Runtime stage
            FROM openjdk:17-jre-slim
            
            WORKDIR /app
            
            # Copy JAR from builder
            COPY --from=builder /app/target/*.jar app.jar
            
            # Run the application
            CMD ["java", "-jar", "app.jar"]
            """).strip()
            
        # Default case
        return textwrap.dedent("""
        # Build stage
        FROM {}:latest AS builder
        
        WORKDIR /app
        
        # Copy and build your application
        COPY . .
        
        # Runtime stage
        FROM {}:latest
        
        WORKDIR /app
        
        # Copy only necessary files from builder
        COPY --from=builder /app/your-binary /app/
        
        # Run your application
        CMD ["/app/your-binary"]
        """).strip().format(base_image, base_image)

class DockerfileAnalyzer:
    """Analyze and optimize Dockerfiles"""
    
    @staticmethod
    def analyze_dockerfile(dockerfile_path: str) -> List[DockerfileOptimization]:
        """Analyze a Dockerfile for optimization opportunities"""
        optimizations = []
        
        if not os.path.exists(dockerfile_path):
            logger.error(f"Dockerfile not found at {dockerfile_path}")
            return optimizations
        
        try:
            with open(dockerfile_path, 'r') as f:
                lines = f.readlines()
        except Exception as e:
            logger.error(f"Error reading Dockerfile: {e}")
            return optimizations
            
        # Process Dockerfile line by line
        for i, line in enumerate(lines):
            line_num = i + 1
            stripped_line = line.strip()
            
            # Skip empty lines and comments
            if not stripped_line or stripped_line.startswith('#'):
                continue
                
            # Check FROM command
            if stripped_line.startswith('FROM'):
                # Check if using latest tag
                if ':latest' in stripped_line or stripped_line.split()[1].count(':') == 0:
                    optimizations.append(
                        DockerfileOptimization(
                            line_number=line_num,
                            original_line=stripped_line,
                            suggested_line=stripped_line.replace(':latest', ':specific-version').replace(
                                stripped_line.split()[1], stripped_line.split()[1] + ':specific-version' 
                                if ':' not in stripped_line.split()[1] else stripped_line.split()[1]),
                            reason="Using 'latest' tag or no tag is unpredictable and can cause inconsistent builds",
                            savings_estimate="Security improvement"
                        )
                    )
                    
                # Check if using large base images
                base_image = stripped_line.split()[1].split(':')[0]
                for large_image, alternative in [
                    ('ubuntu', 'alpine'), 
                    ('debian', 'alpine'),
                    ('python', 'python:3.10-slim'),
                    ('node', 'node:18-alpine')
                ]:
                    if large_image in base_image and 'slim' not in stripped_line and 'alpine' not in stripped_line:
                        optimizations.append(
                            DockerfileOptimization(
                                line_number=line_num,
                                original_line=stripped_line,
                                suggested_line=stripped_line.replace(base_image, alternative.split(':')[0]),
                                reason=f"Consider using a smaller base image like {alternative}",
                                savings_estimate="50-200MB"
                            )
                        )
                        
            # Check RUN commands
            elif stripped_line.startswith('RUN'):
                # Check for apt-get without cleanup
                if 'apt-get install' in stripped_line and not (
                    'apt-get clean' in stripped_line or 
                    'rm -rf /var/lib/apt/lists/*' in stripped_line
                ):
                    optimized = stripped_line + ' && apt-get clean && rm -rf /var/lib/apt/lists/*'
                    optimizations.append(
                        DockerfileOptimization(
                            line_number=line_num,
                            original_line=stripped_line,
                            suggested_line=optimized,
                            reason="Clean up apt cache to reduce image size",
                            savings_estimate="20-100MB"
                        )
                    )
                    
                # Check for pip without --no-cache-dir
                if 'pip install' in stripped_line and '--no-cache-dir' not in stripped_line:
                    optimized = stripped_line.replace('pip install', 'pip install --no-cache-dir')
                    optimizations.append(
                        DockerfileOptimization(
                            line_number=line_num,
                            original_line=stripped_line,
                            suggested_line=optimized,
                            reason="Use --no-cache-dir with pip to avoid storing package cache",
                            savings_estimate="10-50MB"
                        )
                    )
                    
                # Check for npm without cache cleanup
                if 'npm install' in stripped_line and 'npm cache clean' not in stripped_line:
                    if '&&' in stripped_line:
                        optimized = stripped_line + ' && npm cache clean --force'
                    else:
                        optimized = stripped_line + ' && npm cache clean --force'
                    optimizations.append(
                        DockerfileOptimization(
                            line_number=line_num,
                            original_line=stripped_line,
                            suggested_line=optimized,
                            reason="Clean npm cache to reduce image size",
                            savings_estimate="10-50MB"
                        )
                    )
                
            # Check COPY commands - suggest .dockerignore
            elif stripped_line.startswith('COPY . ') or stripped_line.startswith('COPY ./ '):
                optimizations.append(
                    DockerfileOptimization(
                        line_number=line_num,
                        original_line=stripped_line,
                        suggested_line=stripped_line,
                        reason="Consider using a .dockerignore file to exclude unnecessary files (node_modules, .git, etc.)",
                        savings_estimate="Variable, potentially 10-500MB"
                    )
                )
                
        # Check for multi-stage build opportunity
        has_multi_stage = any('AS ' in line for line in lines)
        if not has_multi_stage:
            optimizations.append(
                DockerfileOptimization(
                    line_number=0,
                    original_line="",
                    suggested_line="# Consider using multi-stage builds",
                    reason="Multi-stage builds separate build-time and runtime dependencies",
                    savings_estimate="100-500MB depending on application type"
                )
            )
            
        return optimizations
    
    @staticmethod
    def generate_optimized_dockerfile(dockerfile_path: str, optimizations: List[DockerfileOptimization]) -> str:
        """Generate an optimized version of a Dockerfile based on suggestions"""
        if not os.path.exists(dockerfile_path):
            return "# Error: Original Dockerfile not found"
            
        try:
            with open(dockerfile_path, 'r') as f:
                lines = f.readlines()
                
            # Apply optimizations
            for opt in optimizations:
                if opt.line_number > 0 and opt.line_number <= len(lines):
                    # Only replace if this isn't a general suggestion (line_number=0)
                    lines[opt.line_number - 1] = opt.suggested_line + '\n'
                    
            return ''.join(lines)
        except Exception as e:
            logger.error(f"Error generating optimized Dockerfile: {e}")
            return "# Error generating optimized Dockerfile"

class CostEstimator:
    """Estimate cost implications of Docker image optimizations"""
    
    @staticmethod
    def estimate_cost_savings(
        image_name: str, 
        current_size: str, 
        optimized_size_estimate: str,
        container_count: int = 10
    ) -> str:
        """
        Estimate cost savings based on image size reduction
        
        Args:
            image_name: Name of the Docker image
            current_size: Current size in human-readable format
            optimized_size_estimate: Estimated optimized size in human-readable format
            container_count: Estimated number of containers deployed
        
        Returns:
            String with cost savings estimation
        """
        # Convert sizes to bytes for calculation
        def size_to_bytes(size_str: str) -> int:
            size = float(size_str.split()[0])
            unit = size_str.split()[1].upper()
            
            if unit == "B":
                return int(size)
            elif unit == "KB":
                return int(size * 1024)
            elif unit == "MB":
                return int(size * 1024 * 1024)
            elif unit == "GB":
                return int(size * 1024 * 1024 * 1024)
            elif unit == "TB":
                return int(size * 1024 * 1024 * 1024 * 1024)
            else:
                return 0
        
        try:
            current_bytes = size_to_bytes(current_size)
            if "%" in optimized_size_estimate:
                # If it's a percentage reduction
                percentage = float(optimized_size_estimate.strip('%')) / 100
                optimized_bytes = int(current_bytes * (1 - percentage))
            else:
                # If it's an absolute size
                optimized_bytes = size_to_bytes(optimized_size_estimate)
            
            # Calculate difference
            diff_bytes = current_bytes - optimized_bytes
            diff_mb = diff_bytes / (1024 * 1024)
            
            # Assume costs
            storage_cost_per_gb_month = 0.10  # $0.10 per GB per month
            transfer_cost_per_gb = 0.15  # $0.15 per GB transfer
            
            # Monthly calculations
            monthly_storage_savings = (diff_bytes / (1024 * 1024 * 1024)) * storage_cost_per_gb_month
            
            # Transfer calculations (assume 10 deployments per month per container)
            monthly_deployments = 10
            total_transfer_savings = (diff_bytes / (1024 * 1024 * 1024)) * transfer_cost_per_gb * monthly_deployments * container_count
            
            # Build time improvements (rough estimate)
            build_time_savings_seconds = diff_mb * 0.05  # Assume 0.05 seconds per MB saved
            
            # Format the response
            result = f"""
Estimated Monthly Cost Savings (based on {container_count} containers):
- Storage: ${monthly_storage_savings:.2f}/month
- Transfer: ${total_transfer_savings:.2f}/month
- Total: ${(monthly_storage_savings + total_transfer_savings):.2f}/month

Additional Benefits:
- Build time reduction: ~{int(build_time_savings_seconds)} seconds per build
- Reduced deployment time: ~{int(build_time_savings_seconds * 0.8)} seconds per deployment
- Lower resource usage during container startup
            """
            
            return result.strip()
        except Exception as e:
            logger.error(f"Error estimating cost savings: {e}")
            return "Could not calculate cost savings due to an error"

class ContainerOptimizationTool:
    """Main class for the container optimization tool"""
    
    def __init__(self):
        self.docker_client = DockerClient()
        self.vulnerability_scanner = VulnerabilityScanner()
        self.size_optimizer = SizeOptimizer()
        self.dockerfile_analyzer = DockerfileAnalyzer()
        self.cost_estimator = CostEstimator()
    
    def analyze_image(
        self, 
        image_name: str, 
        optimization_type: OptimizationType = OptimizationType.ALL,
        dockerfile_path: Optional[str] = None
    ) -> OptimizationReport:
        """
        Analyze a Docker image and generate optimization recommendations
        
        Args:
            image_name: Name of the Docker image to analyze
            optimization_type: Type of optimization to perform
            dockerfile_path: Path to Dockerfile (optional)
            
        Returns:
            OptimizationReport with analysis results
        """
        logger.info(f"Starting analysis of image: {image_name}")
        
        # Check if Docker is available
        if not self.docker_client.check_docker_available():
            logger.error("Docker is not available. Please install Docker and make sure it's running.")
            sys.exit(1)
        
        # Check if image exists
        if not self.docker_client.image_exists(image_name):
            logger.error(f"Image '{image_name}' not found locally. Please pull it first with 'docker pull {image_name}'")
            sys.exit(1)
        
        # Get basic image info
        image_size = self.docker_client.get_image_size(image_name)
        logger.info(f"Image size: {image_size}")
        
        # Get image history for analysis
        history = self.docker_client.get_image_history(image_name)
        
        # Collect vulnerabilities if requested
        vulnerabilities = []
        if optimization_type in [OptimizationType.SECURITY, OptimizationType.ALL]:
            vulnerabilities = self.vulnerability_scanner.scan_image(image_name)
        
        # Analyze size issues if requested
        size_issues = []
        if optimization_type in [OptimizationType.SIZE, OptimizationType.ALL]:
            size_issues = self.size_optimizer.analyze_size_issues(image_name, history)
        
        # Generate multi-stage dockerfile suggestion if appropriate
        multi_stage_suggestion = None
        if optimization_type in [OptimizationType.SIZE, OptimizationType.ALL] and any(
            issue.issue_type == "MULTI_STAGE" for issue in size_issues
        ):
            multi_stage_suggestion = self.size_optimizer.generate_multi_stage_dockerfile(image_name)
        
        # Analyze Dockerfile if provided
        dockerfile_optimizations = []
        if dockerfile_path and os.path.exists(dockerfile_path):
            dockerfile_optimizations = self.dockerfile_analyzer.analyze_dockerfile(dockerfile_path)
        
        # Estimate cost savings
        estimated_savings = None
        if optimization_type in [OptimizationType.COST, OptimizationType.ALL]:
            # Calculate potential size savings as percentage
            total_savings_mb = sum(
                int(issue.potential_savings.split('-')[1].strip('MB'))  # Use high end of range
                for issue in size_issues 
                if 'MB' in issue.potential_savings
            )
            
            # Convert current size to MB for percentage calculation
            current_size_parts = image_size.split()
            current_size_value = float(current_size_parts[0])
            current_size_unit = current_size_parts[1]
            
            # Convert to MB for consistent calculation
            if current_size_unit == "B":
                current_size_mb = current_size_value / (1024 * 1024)
            elif current_size_unit == "KB":
                current_size_mb = current_size_value / 1024
            elif current_size_unit == "MB":
                current_size_mb = current_size_value
            elif current_size_unit == "GB":
                current_size_mb = current_size_value * 1024
            elif current_size_unit == "TB":
                current_size_mb = current_size_value * 1024 * 1024
            else:
                current_size_mb = 0
                
            # Calculate optimized size and percentage savings
            optimized_size_mb = max(0, current_size_mb - total_savings_mb)
            percentage_savings = (total_savings_mb / current_size_mb) * 100 if current_size_mb > 0 else 0
            
            optimized_size = f"{optimized_size_mb:.2f} MB"
            percentage_str = f"{percentage_savings:.1f}%"
            
            estimated_savings = self.cost_estimator.estimate_cost_savings(
                image_name, 
                image_size, 
                optimized_size
            )
        
        # Create and return the report
        return OptimizationReport(
            image_name=image_name,
            image_size=image_size,
            vulnerabilities=vulnerabilities,
            size_issues=size_issues,
            dockerfile_optimizations=dockerfile_optimizations,
            multi_stage_suggestion=multi_stage_suggestion,
            estimated_cost_savings=estimated_savings
        )
    
    def generate_optimized_dockerfile(self, dockerfile_path: str) -> str:
        """Generate an optimized version of a Dockerfile"""
        optimizations = self.dockerfile_analyzer.analyze_dockerfile(dockerfile_path)
        return self.dockerfile_analyzer.generate_optimized_dockerfile(dockerfile_path, optimizations)
    
    def print_report(self, report: OptimizationReport, show_details: bool = True):
        """Print the optimization report to console"""
        
        print("\n" + "="*80)
        print(f"🐳 CONTAINER OPTIMIZATION REPORT FOR {report.image_name}")
        print("="*80)
        
        print(f"📊 Image Size: {report.image_size}")
        print(f"📅 Report Generated: {report.report_date.strftime('%Y-%m-%d %H:%M:%S')}")
        print("-"*80)
        
        # Print vulnerability summary
        if report.vulnerabilities:
            print(f"\n🔒 SECURITY VULNERABILITIES: {len(report.vulnerabilities)}")
            print("-"*80)
            
            # Group by severity
            severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
            for vuln in report.vulnerabilities:
                severity_counts[vuln.severity] = severity_counts.get(vuln.severity, 0) + 1
                
            print(f"CRITICAL: {severity_counts.get('CRITICAL', 0)}")
            print(f"HIGH: {severity_counts.get('HIGH', 0)}")
            print(f"MEDIUM: {severity_counts.get('MEDIUM', 0)}")
            print(f"LOW: {severity_counts.get('LOW', 0)}")
            
            if show_details:
                print("\nDetails:")
                for i, vuln in enumerate(report.vulnerabilities):
                    print(f"  {i+1}. [{vuln.severity}] {vuln.package}: {vuln.description}")
                    if vuln.fix_version:
                        print(f"     Fix: Update to version {vuln.fix_version}")
                    if vuln.cve_id:
                        print(f"     CVE: {vuln.cve_id}")
                    print()
        
        # Print size optimization summary
        if report.size_issues:
            print(f"\n📦 SIZE OPTIMIZATION OPPORTUNITIES: {len(report.size_issues)}")
            print("-"*80)
            
            # Calculate total potential savings
            total_savings = "Variable"
            savings_values = []
            for issue in report.size_issues:
                if "-" in issue.potential_savings:
                    # Take the mid-point of the range
                    min_val, max_val = issue.potential_savings.split("-")
                    min_num = float(min_val.strip().rstrip("MB"))
                    max_num = float(max_val.strip().rstrip("MB"))
                    savings_values.append((min_num + max_num) / 2)
            
            if savings_values:
                total_mb = sum(savings_values)
                total_savings = f"~{total_mb:.1f} MB"
                
            print(f"Total Potential Size Reduction: {total_savings}")
            
            if show_details:
                print("\nDetails:")
                for i, issue in enumerate(report.size_issues):
                    print(f"  {i+1}. {issue.issue_type}: {issue.description}")
                    print(f"     Potential Savings: {issue.potential_savings}")
                    print(f"     Suggestion: {issue.suggestion}")
                    print()
        
        # Print Dockerfile optimization summary
        if report.dockerfile_optimizations:
            print(f"\n📄 DOCKERFILE OPTIMIZATION SUGGESTIONS: {len(report.dockerfile_optimizations)}")
            print("-"*80)
            
            if show_details:
                print("\nDetails:")
                for i, opt in enumerate(report.dockerfile_optimizations):
                    if opt.line_number > 0:
                        print(f"  {i+1}. Line {opt.line_number}: {opt.original_line}")
                        print(f"     Suggestion: {opt.suggested_line}")
                    else:
                        print(f"  {i+1}. General suggestion: {opt.suggested_line}")
                    print(f"     Reason: {opt.reason}")
                    print(f"     Potential Savings: {opt.savings_estimate}")
                    print()
        
        # Print multi-stage build suggestion
        if report.multi_stage_suggestion:
            print("\n🏗️ MULTI-STAGE BUILD RECOMMENDATION")
            print("-"*80)
            print("A multi-stage build could significantly reduce image size.")
            
            if show_details:
                print("\nSuggested Dockerfile:")
                print(report.multi_stage_suggestion)
                print()
        
        # Print cost savings
        if report.estimated_cost_savings:
            print("\n💰 COST SAVINGS ESTIMATE")
            print("-"*80)
            print(report.estimated_cost_savings)
            print()
        
        # Print summary recommendations
        print("\n🚀 SUMMARY RECOMMENDATIONS")
        print("-"*80)
        
        recommendations = []
        
        if report.vulnerabilities:
            critical_high = sum(1 for v in report.vulnerabilities if v.severity in ["CRITICAL", "HIGH"])
            if critical_high > 0:
                recommendations.append(f"Fix {critical_high} critical/high security vulnerabilities")
        
        if report.size_issues:
            multi_stage = any(issue.issue_type == "MULTI_STAGE" for issue in report.size_issues)
            if multi_stage:
                recommendations.append("Implement multi-stage build to significantly reduce image size")
            
            apt_cache = any(issue.issue_type == "APT_CACHE" for issue in report.size_issues)
            if apt_cache:
                recommendations.append("Clean package manager caches after installation")
        
        if not recommendations:
            recommendations.append("No critical issues found")
            
        for i, rec in enumerate(recommendations):
            print(f"{i+1}. {rec}")
            
        print("\n" + "="*80)

def main():
    """Main entry point for the CLI tool"""
    parser = argparse.ArgumentParser(
        description="Container Optimization Tool - Analyze and optimize Docker images",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze an image for all optimization opportunities
  container-opt analyze python:3.9
  
  # Analyze an image for security vulnerabilities only
  container-opt analyze --type security nginx:latest
  
  # Analyze an image with its Dockerfile
  container-opt analyze --dockerfile ./Dockerfile node:14
  
  # Generate an optimized Dockerfile
  container-opt optimize-dockerfile ./Dockerfile
        """
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Command to run")
    
    # Analyze command
    analyze_parser = subparsers.add_parser("analyze", help="Analyze a Docker image")
    analyze_parser.add_argument("image", help="Docker image to analyze (e.g., python:3.9)")
    analyze_parser.add_argument(
        "--type", 
        choices=["all", "security", "size", "cost"],
        default="all",
        help="Type of analysis to perform"
    )
    analyze_parser.add_argument(
        "--dockerfile", 
        help="Path to the Dockerfile used to build the image"
    )
    analyze_parser.add_argument(
        "--no-details", 
        action="store_true",
        help="Show summary only, without detailed information"
    )
    
    # Optimize Dockerfile command
    optimize_parser = subparsers.add_parser("optimize-dockerfile", help="Generate an optimized Dockerfile")
    optimize_parser.add_argument("dockerfile", help="Path to the Dockerfile to optimize")
    optimize_parser.add_argument(
        "--output",
        help="Path to save the optimized Dockerfile (default: Dockerfile.optimized)"
    )
    
    args = parser.parse_args()
    
    # Initialize the tool
    tool = ContainerOptimizationTool()
    
    if args.command == "analyze":
        try:
            # Convert optimization type string to enum
            opt_type = OptimizationType(args.type)
            
            # Run analysis
            report = tool.analyze_image(
                image_name=args.image,
                optimization_type=opt_type,
                dockerfile_path=args.dockerfile
            )
            
            # Print report
            tool.print_report(report, show_details=not args.no_details)
            
        except Exception as e:
            logger.error(f"Error analyzing image: {e}")
            sys.exit(1)
            
    elif args.command == "optimize-dockerfile":
        try:
            # Generate optimized Dockerfile
            optimized = tool.generate_optimized_dockerfile(args.dockerfile)
            
            # Save or print the result
            output_path = args.output or "Dockerfile.optimized"
            with open(output_path, "w") as f:
                f.write(optimized)
                
            logger.info(f"Optimized Dockerfile saved to {output_path}")
            
        except Exception as e:
            logger.error(f"Error optimizing Dockerfile: {e}")
            sys.exit(1)
    
    else:
        parser.print_help()

if __name__ == "__main__":
    main()