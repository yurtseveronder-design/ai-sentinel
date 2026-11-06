# Architecture Overview

`ai-sentinel` is organized into a modular structure separating core security logic, gateway routing, and pipeline integrations.

## Core Modules

### 1. Core Security (`src/ai_sentinel/core/`)
- **`shield.py`**: Houses `SecurityShield` and `ShieldVerdict`, unifying threat scanning, pattern matching, Base64 decoding inspection, and rate-limit evaluation.
- **`normalizer.py`**: Sanitizes and standardizes incoming prompt text before evaluation.
- **`config_loader.py`**: Manages YAML-based configuration loading for threat signatures and risk thresholds.

### 2. Gateway (`src/ai_sentinel/gateway/`)
- **`app.py`**: A FastAPI application providing core REST endpoints:
  - `POST /v1/scan`: Evaluates payloads for prompt injection or abuse.
  - `GET /v1/inspect`: Returns current security configuration settings.
  - `GET /health`: Health check endpoint.
  - `GET /metrics`: Prometheus-compatible telemetry endpoint.
- Implements singleton startup loading to avoid redundant model/config reloading per request, alongside optional `X-API-Key` authentication.

### 3. Integrations (`src/ai_sentinel/integrations/`)
- Provides decorators and helper utilities (`decorator.py`) to easily wrap Python function calls and LLM invocation pipelines with security inspection checks.

### 4. Test Suite (`tests/`)
- An extensive `pytest` suite validating gateway behavior, adversarial resistance, rate limiting, and normalizer edge cases.