"""
Command-Line Interface Client for SHA-256 Research Platform v3.0
Acts as a client of the application service layer.
"""

import sys
import argparse
import json
import uvicorn
from typing import List, Optional

from .storage.db import DatabaseManager
from .models.runtime import LocalModelRuntime
from .models.hardware import probe_hardware
from .workers.worker import ResearchWorkerPool
from .agent.tools import ToolRegistry
from .agent.loop import AutonomousResearchCampaign


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="sha256-platform",
        description="SHA-256 Research Platform v3.0 Client"
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # 1. status
    subparsers.add_parser("status", help="Show system, hardware, and research counts")

    # 2. serve
    serve_p = subparsers.add_parser("serve", help="Launch headless REST & WebSocket API server")
    serve_p.add_argument("--host", default="127.0.0.1", help="Host address (default 127.0.0.1)")
    serve_p.add_argument("--port", type=int, default=8000, help="Port number (default 8000)")

    # 3. models
    models_p = subparsers.add_parser("models", help="Manage local models")
    models_sub = models_p.add_subparsers(dest="models_action")
    models_sub.add_parser("list", help="List registered models")
    load_p = models_sub.add_parser("load", help="Load model")
    load_p.add_argument("model_id", help="ID of model to load")
    unload_p = models_sub.add_parser("unload", help="Unload model")
    unload_p.add_argument("model_id", help="ID of model to unload")

    # 4. hypothesis
    hyp_p = subparsers.add_parser("hypothesis", help="Manage research hypotheses")
    hyp_sub = hyp_p.add_subparsers(dest="hyp_action")
    hyp_sub.add_parser("list", help="List all hypotheses")
    create_h = hyp_sub.add_parser("create", help="Create hypothesis")
    create_h.add_argument("title", help="Hypothesis title")
    create_h.add_argument("--desc", default="", help="Hypothesis description")

    # 5. experiment
    exp_p = subparsers.add_parser("experiment", help="Manage cryptanalysis experiments")
    exp_sub = exp_p.add_subparsers(dest="exp_action")
    run_exp = exp_sub.add_parser("run", help="Run experiment")
    run_exp.add_argument("rounds", type=int, help="Target rounds (1..64)")
    run_exp.add_argument("--solver", default="cadical", help="SAT solver")
    run_exp.add_argument("--timeout", type=int, default=60, help="Timeout in seconds")

    # 6. campaign
    camp_p = subparsers.add_parser("campaign", help="Autonomous research campaigns")
    camp_sub = camp_p.add_subparsers(dest="camp_action")
    start_c = camp_sub.add_parser("start", help="Start campaign cycle")
    start_c.add_argument("--rounds", type=int, default=4, help="Starting rounds (default 4)")
    start_c.add_argument("--solver", default="cadical", help="SAT solver")

    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return 0

    db = DatabaseManager()
    runtime = LocalModelRuntime(db)
    worker_pool = ResearchWorkerPool(db)
    tools = ToolRegistry(db, runtime, worker_pool)

    if args.command == "status":
        hw = probe_hardware()
        counts = db.get_system_counts()
        print("===============================================================")
        print("    SHA-256 Autonomous Research Platform Status (v3.0.0)      ")
        print("===============================================================")
        print(f" CPU:              {hw.cpu_model} ({hw.cpu_cores} cores, {hw.cpu_threads} threads)")
        print(f" RAM:              {hw.total_ram_bytes // (1024*1024)} MB (Budget: {hw.conservative_memory_budget_bytes // (1024*1024)} MB)")
        print(f" Vulkan Compute:   {'AVAILABLE' if hw.vulkan_available else 'NOT AVAILABLE'}")
        if hw.vulkan_available:
            print(f" Device:           {hw.vulkan_device_name} ({hw.vulkan_device_type or 'GPU'})")
        print(f" Active Models:    {len(runtime.list_models())} registered (Loaded: {runtime.loaded_model_id or 'None'})")
        print(f" Experiments DB:   {counts['experiments']} experiments, {counts['hypotheses']} hypotheses, {counts['artifacts']} artifacts")
        return 0

    elif args.command == "serve":
        print(f"Starting Headless API Server on http://{args.host}:{args.port}")
        from .api.app import app
        uvicorn.run(app, host=args.host, port=args.port, log_level="info")
        return 0

    elif args.command == "models":
        if args.models_action == "list":
            for m in runtime.list_models():
                status = "LOADED" if m["is_loaded"] else "IDLE"
                print(f" - [{status}] {m['model_id']}: {m['name']} ({m['model_class']}, {m['runtime']}, {m['backend']})")
            return 0
        elif args.models_action == "load":
            runtime.load_model(args.model_id)
            print(f"Model {args.model_id} loaded successfully.")
            return 0
        elif args.models_action == "unload":
            runtime.unload_model(args.model_id)
            print(f"Model {args.model_id} unloaded.")
            return 0

    elif args.command == "hypothesis":
        if args.hyp_action == "list":
            res = tools.list_hypotheses({})
            for h in res.get("hypotheses", []):
                print(f" - [{h.get('trust_level', 'L0')}] {h['id']}: {h['title']}")
            return 0
        elif args.hyp_action == "create":
            res = tools.create_hypothesis({"title": args.title, "description": args.desc})
            print(f"Hypothesis created: {res['hypothesis_id']} ({res['title']})")
            return 0

    elif args.command == "experiment":
        if args.exp_action == "run":
            res = tools.create_experiment({
                "rounds": args.rounds,
                "solver": args.solver,
                "timeout": args.timeout
            })
            print(f"Experiment {res.get('experiment_id')}: Status {res.get('status')}")
            return 0

    elif args.command == "campaign":
        if args.camp_action == "start":
            worker_pool.start()
            campaign = AutonomousResearchCampaign(db, tools, worker_pool)
            print(f"Executing autonomous research cycle on {args.rounds} rounds...")
            res = campaign.run_cycle(target_rounds=args.rounds, solver=args.solver)
            print(f"Cycle completed. Verified: {res['stages']['VERIFY']['verified']}")
            worker_pool.stop()
            return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
