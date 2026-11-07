FROM python:3.10-slim

# Create a non-root user
RUN useradd -m -s /bin/bash sentinel

WORKDIR /app

# Install dependencies first for Docker caching
COPY pyproject.toml .
RUN pip install --no-cache-dir . fastapi uvicorn pydantic pyyaml requests

# Copy the application code
COPY src/ ./src/
COPY tests/ ./tests/

# Create the logs directory and assign ownership to the non-root user
RUN mkdir -p logs && chown -R sentinel:sentinel /app

# Switch to the non-root user for security
USER sentinel

# Set environment variables
ENV PYTHONPATH=/app/src
ENV AI_SENTINEL_AUDIT_PATH=/app/logs/audit.jsonl

EXPOSE 8000

# Start the application using our unified CLI
CMD ["python", "src/ai_sentinel/cli.py", "serve", "--host", "0.0.0.0", "--port", "8000"]