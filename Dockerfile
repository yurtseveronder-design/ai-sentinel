FROM python:3.11-slim

WORKDIR /app

# Install system dependencies if required
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt fastapi uvicorn pydantic prometheus-client streamlit requests pytest

# Copy source code and test suite into container
COPY src/ ./src/
COPY tests/ ./tests/
COPY app_dashboard.py ./

EXPOSE 8000
EXPOSE 8501

# Default command runs the FastAPI production gateway via Uvicorn
CMD ["uvicorn", "ai_sentinel.api.gateway:app", "--host", "0.0.0.0", "--port", "8000"]