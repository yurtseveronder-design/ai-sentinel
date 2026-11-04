import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
import json
from src.metrics import PerformanceTracker
from src.client import LocalModelClient
from src.reporter import PerformanceReporter
from deepeval.test_case import LLMTestCase
from deepeval.metrics import FaithfulnessMetric, AnswerRelevancyMetric
from deepeval.models.base_model import DeepEvalBaseLLM
from groq import Groq
from deepeval import assert_test

class GroqEvaluator(DeepEvalBaseLLM):
    def __init__(self, model_name="llama-3.3-70b-versatile"):
        self.client = Groq()
        self.model_name = model_name
    def load_model(self):
        return self.client
    def get_model_name(self):
        return self.model_name
    def generate(self, prompt: str) -> str:
        chat_completion = self.client.chat.completions.create(
            messages=[{"role": "user", "content": prompt}],
            model=self.model_name,
        )
        return chat_completion.choices[0].message.content
    async def a_generate(self, prompt: str) -> str:
        return self.generate(prompt)
    DUMMY_MODEL_NAME = "Groq Llama Guard"

DATASET_PATH = Path(__file__).parent.parent / 'datasets' / 'queries.json'
with open(DATASET_PATH, 'r', encoding='utf-8') as f:
    data = json.load(f)

def test_rag_quality_and_performance():
    tracker = PerformanceTracker()
    client = LocalModelClient()
    reporter = PerformanceReporter()
    queries = data['benchmark_queries']
    results_log = []
    cloud_evaluator = GroqEvaluator()
    faithfulness_metric = FaithfulnessMetric(threshold=0.7, model=cloud_evaluator, include_reason=True)
    relevancy_metric = AnswerRelevancyMetric(threshold=0.7, model=cloud_evaluator, include_reason=True)
    for item in queries:
        query_text = item['query']
        response, token_count, latency, retrieved_context = client.generate_response(query_text)
        throughput = tracker.calculate_throughput(token_count, latency)
        results_log.append({'id': item['id'], 'query': query_text, 'latency': latency, 'throughput': throughput})
        assert latency < 0.5
        assert throughput >= 5.0
        test_case = LLMTestCase(input=query_text, actual_output=response, retrieval_context=retrieved_context)
        assert_test(test_case, [faithfulness_metric, relevancy_metric])
    reporter.save_markdown_report(results_log)
    assert Path('performance_report.md').exists()
