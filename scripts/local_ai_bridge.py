import json
import os
import urllib.request

LOCAL_API_URL = "http://localhost:1337/v1/chat/completions"
MODEL_NAME = "gemma"

def query_jan_local_ai(prompt: str) -> str:
    payload = {
        "model": MODEL_NAME,
        "messages": [
            {"role": "system", "content": "You are an AI evaluation assistant."},
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.2
    }
    
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        LOCAL_API_URL, 
        data=data, 
        headers={"Content-Type": "application/json"}
    )
    
    try:
        with urllib.request.urlopen(req) as response:
            result = json.loads(response.read().decode("utf-8"))
            return result["choices"][0]["message"]["content"]
    except Exception as e:
        return f"Error connecting to Jan local server: {e}"

if __name__ == "__main__":
    test_prompt = "Perform a quick sanity check: Is local telemetry logging active?"
    print(f"Connecting to Jan local server with prompt: '{test_prompt}'\n")
    
    response = query_jan_local_ai(test_prompt)
    print("--- Jan Local AI Response ---")
    print(response)
    
    os.makedirs("output", exist_ok=True)
    output_path = "output/jan_local_test_result.json"
    with open(output_path, "w") as f:
        json.dump({"prompt": test_prompt, "response": response}, f, indent=4)
        
    print(f"\nResult successfully logged and saved to {output_path}")