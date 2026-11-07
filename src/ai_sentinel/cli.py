import argparse
import sys
import uvicorn
from ai_sentinel.core.shield import SecurityShield

def main():
    parser = argparse.ArgumentParser(description="AI Sentinel CLI Inspector and Gateway Runner")
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # Inspect command
    inspect_parser = subparsers.add_parser("inspect", help="Inspect a prompt or text string")
    inspect_parser.add_argument("--text", type=str, required=True, help="Text to inspect")
    inspect_parser.add_argument("--config", type=str, default=None, help="Path to threat signatures YAML")

    # Serve command
    serve_parser = subparsers.add_parser("serve", help="Start the FastAPI security gateway")
    serve_parser.add_argument("--host", type=str, default="127.0.0.1", help="Bind host")
    serve_parser.add_argument("--port", type=int, default=8000, help="Bind port")
    serve_parser.add_argument("--reload", action="store_true", help="Enable reload")

    args = parser.parse_args()

    if args.command == "inspect":
        try:
            shield = SecurityShield(config_path=args.config)
            verdict = shield.inspect(text=args.text)
            print("\n--- Inspection Verdict ---")
            print(f"Action: {verdict.action}")
            print(f"Flagged: {verdict.flagged}")
            print(f"Risk Score: {verdict.risk_score}")
            print(f"Reasons: {verdict.reason}")
        except Exception as e:
            print(f"Error during inspection: {e}", file=sys.stderr)
            sys.exit(1)

    elif args.command == "serve":
        print(f"Starting AI Sentinel Gateway on {args.host}:{args.port}...")
        uvicorn.run("ai_sentinel.api.gateway:app", host=args.host, port=args.port, reload=args.reload)

    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()