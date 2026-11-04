# API Tests

A robust, production-ready API test automation framework built for reliable contract validation, robust retry logic, and seamless CI/CD execution[cite: 8].

## What It Solves
Testing REST APIs reliably requires more than just basic status code checks. This framework handles data contract validation, network flakes with automatic retries, and clean reporting out of the box.

## Core Features
* **Pydantic Contract Validation (`schemas/`):** Ensures API response structures match expected schemas precisely.
* **Resilient Networking (`utils/`):** Built-in automatic retries with exponential backoff to handle flaky network conditions.
* **Comprehensive Reporting:** Integrated Allure reporting for clear visual test results[cite: 8].
* **Containerized Execution:** Docker support for running tests consistently across any environment.
* **Automated CI/CD:** Continuous test execution configured via GitHub Actions[cite: 8].

## Project Structure
* `schemas/`: Pydantic models for API response contracts.
* `tests/`: Automated test suite covering endpoints.
* `utils/`: Helper functions, including retry logic and request handlers.
* `assets/`: Test assets and documentation files.
* `.github/workflows/`: Automated CI pipeline configuration.

## Quick Start
1. Clone the repository and install dependencies.
2. Run the test suite locally using pytest:
   ```bash
   python -m pytest -v
