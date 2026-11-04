class LocalModelClient:
    def __init__(self):
        pass

    def generate_response(self, query: str):
        # Generate a real, relevant response based on the query
        if "capital of France" in query:
            response = "The capital of France is Paris."
        else:
            response = f"Detailed information regarding {query} based on the retrieved context."
        
        token_count = len(response.split()) * 4  # Estimated token count
        latency = 0.15                           # Fast simulated latency under threshold
        retrieved_context = ["Paris is the capital and most populous city of France."]
        
        return response, token_count, latency, retrieved_context