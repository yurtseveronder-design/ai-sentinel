import sys
import os
import argparse
import uvicorn

def main():
    parser = argparse.ArgumentParser(description="AI Sentinel Security Gateway & Inspection CLI")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Serve command
    serve_parser = subparsers.add_parser("serve", help="Start the secure FastAPI gateway server")
    serve_parser.add_argument("--host", default="127.0.0.1", help="Host to bind to")
    serve_parser.add_argument("--port", type=int, default=8000, help="Port to bind to")
    serve_parser.add_argument("--reload", action="store_true", help="Enable auto-reload for development")

    # Inspect command
    inspect_parser = subparsers.add_parser("inspect", help="Inspect a text string locally using SecurityShield")
    inspect_parser.add_argument("--text", required=True, help="Text string to inspect for threats")
    inspect_parser.add_argument("--mode", default="moderate", help="Shield sensitivity mode")

    args = parser.parse_args()

    if args.command == "serve":
        print(f"Starting AI Sentinel Gateway on {args.host}:{args.port}...")
        uvicorn.run("ai_sentinel.api.gateway:app", host=args.host, port=args.port, reload=args.reload)
    elif args.command == "inspect":
        from ai_sentinel.core.shield import SecurityShield
        shield = SecurityShield(mode=args.mode)
        verdict = shield.inspect(text=args.text)
        print(f"\n--- Inspection Verdict ---")
        print(f"Action: {verdict.action}")
        print(f"Flagged: {verdict.flagged}")
        print(f"Risk Score: {verdict.risk_score}")
        print(f"Reasons: {verdict.reason}")
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()