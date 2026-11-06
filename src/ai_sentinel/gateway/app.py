from fastapi import FastAPI, HTTPException
from ai_sentinel.core.config_loader import ConfigLoader

# 1. Initialize FastAPI app first
app = FastAPI(
    title="AI-Sentinel Security Gateway",
    version="1.0.0",
    description="Production-grade AI safety proxy and evaluation framework"
)

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

@app.get("/v1/inspect")
async def inspect_config():
    try:
        loader = ConfigLoader()
        config_data = loader.load_config()
        return {"status": "success", "config": config_data}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Configuration load error: {str(e)}")

# Add your existing scan endpoint and other logic below if needed