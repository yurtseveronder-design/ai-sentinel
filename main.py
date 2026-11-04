from fastapi import FastAPI

app = FastAPI()

@app.get("/")
def read_root():
    return {"status": "online", "service": "ai-sentinel", "message": "AI Sentinel Security Shield is active"}