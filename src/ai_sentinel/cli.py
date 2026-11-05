import argparse
import sys
from ai_sentinel.core.shield import BioImmuneShield

def main():
    parser = argparse.ArgumentParser(description="AI-Sentinel Security CLI Utility")
    parser.add_argument("prompt", type=str, help="The prompt text to inspect")
    parser.add_argument("--mode", type=str, default="moderate", help="Shield mode (strict, moderate, permissive)")
    parser.add_argument("--session", type=str, default=None, help="Optional session ID for sliding window tracking")
    parser.add_argument("--config", type=str, default=None, help="Path to JSON config file")
    
    args = parser.parse_args()
    
    shield = BioImmuneShield(mode=args.mode, config_path=args.config)
    verdict = shield.inspect(args.prompt, session_id=args.session)
    
    print("\n=== AI-SENTINEL SECURITY VERDICT ===")
    print(f"Action:          {verdict.action}")
    print(f"Risk Score:      {verdict.risk_score}")
    print(f"Confidence:      {verdict.confidence}")
    print(f"Cumulative Risk: {verdict.cumulative_risk}")
    print(f"Matched Rules:   {verdict.matched_rules}")
    print(f"Sanitized Text:  {verdict.sanitized_text}")
    print(f"Timestamp:       {verdict.timestamp}")
    print("=====================================\n")
    
    if verdict.action == "BLOCK":
        sys.exit(1)
    else:
        sys.exit(0)

if __name__ == "__main__":
    main()