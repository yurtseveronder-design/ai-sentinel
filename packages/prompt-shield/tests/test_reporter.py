from src.reporter import PerformanceReporter

def test_performance_report_generation():
    sample_data = [
        {
            "id": "Q-101",
            "latency_ms": 240,
            "faithfulness": 0.95,
            "relevancy": 0.90,
            "resonance_score": 0.88,
            "status": "PASS"
        },
        {
            "id": "Q-102",
            "latency_ms": 310,
            "faithfulness": 0.89,
            "relevancy": 0.85,
            "resonance_score": 0.82,
            "status": "PASS"
        }
    ]
    
    reporter = PerformanceReporter(output_path="performance_report.md")
    reporter.generate_report(sample_data)
    
    with open("performance_report.md", "r", encoding="utf-8") as f:
        content = f.read()
        
    assert "Q-101" in content
    assert "0.88" in content
    assert "Detailed Execution Log" in content