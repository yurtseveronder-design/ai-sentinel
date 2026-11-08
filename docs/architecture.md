\# AI Sentinel Architecture



AI Sentinel is built around a strict, deliberate modular layering pattern designed for safety, predictability, and ease of audit.



\## Layering Overview



\[ Incoming Request ]

│

▼

┌────────────────────────────────────────┐

│  API Gateway (FastAPI Shell)           │  <- Thin transport \& auth layer

└──────────────────┬─────────────────────┘

│

▼

┌────────────────────────────────────────┐

│  SecurityShield                        │  <- Threat evaluation \& risk scoring

└──────────────────┬─────────────────────┘

│

▼

┌────────────────────────────────────────┐

│  InputNormalizer                       │  <- Pure, dependency-free sanitization

└────────────────────────────────────────┘



\## Component Responsibilities



1\. \*\*InputNormalizer (`src/ai\_sentinel/core/normalizer.py`)\*\*: 

&#x20;  \* Pure, dependency-free sanitization core. 

&#x20;  \* Handles decoding, normalization, and stripping of control characters or homoglyphs. 

&#x20;  \* Completely decoupled from web frameworks or business logic.



2\. \*\*SecurityShield (`src/ai\_sentinel/core/shield.py`)\*\*:

&#x20;  \* Evaluation engine sitting directly on top of the normalizer.

&#x20;  \* Executes rule-based pattern matching, calculates risk scores, and returns structured `SecurityVerdict` objects against a configurable `block\_threshold`.



3\. \*\*API Gateway (`src/ai\_sentinel/api/gateway.py`)\*\*:

&#x20;  \* Thin FastAPI shell wrapper.

&#x20;  \* Handles HTTP routing, API key header validation, and payload deserialization, delegating core evaluation entirely to the shield.









