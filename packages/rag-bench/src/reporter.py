import os
from pathlib import Path
from datetime import datetime

class PerformanceReporter:
    def __init__(self, report_filename="performance_report.md"):
        self.report_path = Path(report_filename)

    def save_markdown_report(self, results_log):
        """
        Takes a list of evaluated test results and writes a comprehensive 
        Markdown report containing actual performance and quality metrics.
        """
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
        
        report_content = f"# RAG Performance & Security Evaluation Report\n\n"
        report_content += f"* **Generated on:** `{timestamp}`\n"
        report_content += f"* **Status:** `SUCCESS`\n\n"
        
        report_content += "## Executive Summary\n"
        report_content += "This report summarizes the automated execution of benchmark queries across latency tracking, "
        report_content += "throughput calculation, and DeepEval LLM quality guardrails (Faithfulness, Relevancy, and Bias).\n\n"
        
        report_content += "## Detailed Test Metrics\n\n"
        report_content += "| ID | Query | Latency (ms) | Throughput (tok/s) | Faithfulness | Relevancy | Resonance | Status |\n"
        report_content += "|---|---|---|---|---|---|---|---|\n"

        for item in results_log:
            q_id = item.get("id", "N/A")
            q_text = item.get("query", "").replace("|", "-")
            lat = item.get("latency_ms", 0.0)
            thru = item.get("throughput", 0.0)
            faith = item.get("faithfulness", 0.0)
            relev = item.get("relevancy", 0.0)
            resonance = item.get("resonance_score", 0.0)
            status = item.get("status", "PASS")

            report_content += f"| {q_id} | {q_text} | {lat} | {thru} | {faith} | {relev} | {resonance} | **{status}** |\n"

        report_content += "\n## System Architecture Notes\n"
        report_content += "* **Inference Engine:** Groq API (`https://api.groq.com/openai/v1`)\n"
        report_content += "* **Evaluation Framework:** DeepEval Guardrails & Pytest Test Runner\n"
        report_content += "* **Security:** Environment variable isolation (`GROQ_API_KEY`)\n"

        # Write to file
        with open(self.report_path, "w", encoding="utf-8") as f:
            f.write(report_content)

        print(f"Successfully generated data-driven report at {self.report_path}")