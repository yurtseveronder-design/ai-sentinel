FROM python:3.10-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN useradd -m -s /bin/bash sentinel
WORKDIR /app

COPY pyproject.toml README.md LICENSE MANIFEST.in ./
COPY src/ ./src/
RUN pip install --no-cache-dir .

RUN chown -R sentinel:sentinel /app
USER sentinel

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request as u; u.urlopen('http://127.0.0.1:8000/health')"

CMD ["ai-sentinel", "serve", "--host", "0.0.0.0", "--port", "8000"]
