# RAG Performance Bench

**Purpose:** RAG Quality, Latency, Throughput Telemetry, and Cognitive Resonance benchmarking.

---

## Ecosystem Architecture
* **[rag-perf-bench](https://github.com/yurtseveronder-design/rag-perf-bench)** *(Current)*: Focuses exclusively on RAG performance, latency, and DeepEval quality metrics.
* **[prompt-shield-tester](https://github.com/yurtseveronder-design/prompt-shield-tester)**: Focuses strictly on adversarial security, prompt injections, and threat guardrails.

---

## Example Output (`performance_report.md`)

```markdown
# RAG Performance & Quality Telemetry Report

| Metric | Score / Value |
| :--- | :--- |
| **Mean Latency (P95)** | `240ms` |
| **Throughput** | `42.5 req/sec` |
| **DeepEval Faithfulness** | `0.94` |
| **Cognitive Resonance Index** | `0.89` |

### Benchmark Evaluation Log
| Query ID | Latency (ms) | Faithfulness | Resonance Score | Status |
| :--- | :--- | :--- | :--- | :--- |
| `Q_001` | `210` | `0.96` | `0.91` | **✅ PASSED** |
| `Q_002` | `255` | `0.92` | `0.87` | **✅ PASSED** |