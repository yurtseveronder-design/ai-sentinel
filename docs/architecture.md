\# AI Sentinel Architecture



AI Sentinel is a modular, high-security RAG (Retrieval-Augmented Generation) and AI testing monorepo designed for robust prompt injection defense, automated validation, and API testing.



\## Workspace Layout



```text

ai-sentinel/

├── apps/

│   └── sentinel-ui/         # FastAPI backend and RAG UI application

├── packages/

│   ├── sentinel-core/       # Core security guardrails (BioImmuneShield) \& utilities

│   ├── prompt-shield/       # Adversarial testing and mutation engine

│   └── api-tester/          # Automated API security testing suite

├── .github/

│   └── workflows/ci.yml     # Unified CI/CD pipeline configuration

└── docs/

&#x20;   └── architecture.md      # System architecture overview

