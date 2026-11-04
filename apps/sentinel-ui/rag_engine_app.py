import math
import re

class SimpleVectorRAGEngine:
    def __init__(self, documents=None):
        self.documents = documents or [
            {"id": "doc1", "text": "Prompt engineering requires clear instructions, constraints, and few-shot examples."},
            {"id": "doc2", "text": "RAG (Retrieval-Augmented Generation) fetches relevant context to ground LLM responses."},
            {"id": "doc3", "text": "Guardrails validate inputs and outputs to prevent prompt injection and data leaks."}
        ]

    def _text_to_vector(self, text):
        words = re.findall(r'\w+', text.lower())
        vector = {}
        for word in words:
            vector[word] = vector.get(word, 0) + 1
        return vector

    def _cosine_similarity(self, vec1, vec2):
        intersection = set(vec1.keys()) & set(vec2.keys())
        numerator = sum([vec1[x] * vec2[x] for x in intersection])
        
        sum1 = sum([vec1[x] ** 2 for x in vec1.keys()])
        sum2 = sum([vec2[x] ** 2 for x in vec2.keys()])
        
        denominator = math.sqrt(sum1) * math.sqrt(sum2)
        if not denominator:
            return 0.0
        return float(numerator) / denominator

    def retrieve(self, query, top_k=2):
        if not query.strip() or not self.documents:
            return []

        query_vec = self._text_to_vector(query)
        scored_docs = []

        for doc in self.documents:
            doc_vec = self._text_to_vector(doc.get("text", ""))
            score = self._cosine_similarity(query_vec, doc_vec)
            if score > 0.0:
                scored_docs.append((score, doc))

        scored_docs.sort(key=lambda x: x[0], reverse=True)
        return [doc for score, doc in scored_docs[:top_k]]

if __name__ == "__main__":
    engine = SimpleVectorRAGEngine()
    results = engine.retrieve("How does RAG ground LLM responses?")
    print("Vector RAG Retrieval Results:", results)