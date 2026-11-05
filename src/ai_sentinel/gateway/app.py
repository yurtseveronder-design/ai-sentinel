from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Optional
from ai_sentinel.core.classifier import ThreatClassifier, SemanticGuardrail
from ai_sentinel.core.rag_shield import RagShield
from ai_sentinel.core.config_loader import ConfigLoader

app = FastAPI(
    title="AI-Sentinel Security Gateway",
    description="Production-grade AI safety proxy and evaluation framework",
    version="1.0.0"
)

class ScanRequest(BaseModel):
    prompt: Optional[str] = None
    chunks: Optional[List[str]] = None

@app.get("/health")
def health_check():
    cfg = ConfigLoader.load_config()
    return {
        "status": "healthy",
        "mode": cfg.get("mode", "enforce"),
        "version": "1.0.0"
    }

@app.post("/v1/scan")
def scan_payload(request: ScanRequest):
    classifier = ThreatClassifier()
    semantic_guard = SemanticGuardrail()
    rag_shield = RagShield()
    
    results = {}
    max_risk = 0.0
    
    # 1. Analyze prompt if provided
    if request.prompt:
        classification = classifier.analyze(request.prompt)
        semantic = semantic_guard.check(request.prompt)
        
        prompt_risk = max(classification.get("risk_score", 0.0), semantic.get("risk_score", 0.0))
        max_risk = max(max_risk, prompt_risk)
        
        results["prompt_analysis"] = {
            "classification": classification,
            "semantic_guard": semantic
        }
        
    # 2. Scan RAG chunks if provided
    if request.chunks:
        rag_result = rag_shield.scan_chunks(request.chunks)
        max_risk = max(max_risk, rag_result.get("risk_score", 0.0))
        results["rag_shield"] = rag_result
        
    # 3. Determine blocking status based on config
    cfg = ConfigLoader.load_config()
    block_threshold = cfg.get("thresholds", {}).get("risk_score_block", 0.8)
    mode = cfg.get("mode", "enforce")
    
    is_blocked = (max_risk >= block_threshold) and (mode == "enforce")
    
    return {
        "is_blocked": is_blocked,
        "max_risk_score": max_risk,
        "mode": mode,
        "details": results
    }