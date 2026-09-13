"""
Headless REST API and WebSocket Server for SHA-256 Research Platform v3.0
Implemented with Starlette ASGI engine for maximum compatibility, performance,
and zero dependency fragility across Python versions.

Endpoints:
  GET  /api/status
  GET  /api/system
  GET  /api/models
  POST /api/models/{model_id}/load
  POST /api/models/{model_id}/unload
  GET  /api/hypotheses
  POST /api/hypotheses
  GET  /api/experiments
  POST /api/experiments
  GET  /api/experiments/{id}
  POST /api/experiments/{id}/cancel
  GET  /api/jobs
  GET  /api/evidence
  GET  /api/evidence/{id}
  POST /api/verify
  GET  /api/reports
  POST /api/campaign/start
  POST /api/campaign/stop
  GET  /api/campaign/status
  GET  /api/events
  WS   /ws/events
  GET  / (Serves Web Frontend Dashboard)
"""

import os
import json
import asyncio
import threading
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

from starlette.applications import Starlette
from starlette.responses import JSONResponse, HTMLResponse, FileResponse
from starlette.routing import Route, WebSocketRoute, Mount
from starlette.staticfiles import StaticFiles
from starlette.requests import Request
from starlette.websockets import WebSocket, WebSocketDisconnect

from ..storage.db import DatabaseManager
from ..models.runtime import LocalModelRuntime
from ..models.hardware import probe_hardware
from ..workers.worker import ResearchWorkerPool
from ..agent.tools import ToolRegistry, ToolValidationError
from ..agent.loop import AutonomousResearchCampaign
from ..agent.trust import TrustLevel, EpistemicIntegrityError

# Global platform instances
db = DatabaseManager()
runtime = LocalModelRuntime(db)
worker_pool = ResearchWorkerPool(db)
worker_pool.start()
tools = ToolRegistry(db, runtime, worker_pool)
campaign = AutonomousResearchCampaign(db, tools, worker_pool)


class ConnectionManager:
    """Manages live WebSocket clients for real-time research events."""
    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self._lock = threading.Lock()

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        with self._lock:
            self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        with self._lock:
            if websocket in self.active_connections:
                self.active_connections.remove(websocket)

    async def broadcast(self, message: Dict[str, Any]):
        msg_str = json.dumps(message, default=str)
        with self._lock:
            conns = list(self.active_connections)
        for ws in conns:
            try:
                await ws.send_text(msg_str)
            except Exception:
                pass


ws_manager = ConnectionManager()


# 1. System & Status Endpoints
async def get_status(request: Request) -> JSONResponse:
    hw = probe_hardware()
    counts = db.get_system_counts()
    return JSONResponse({
        "status": "ONLINE",
        "version": "v3.0.0",
        "loaded_model": runtime.loaded_model_id,
        "counts": counts,
        "vulkan_available": hw.vulkan_available,
        "device": hw.vulkan_device_name or hw.cpu_model
    })

async def get_system(request: Request) -> JSONResponse:
    hw = probe_hardware()
    return JSONResponse({
        "hardware": hw.to_dict(),
        "memory_budget_bytes": hw.conservative_memory_budget_bytes,
        "workers": worker_pool.max_workers,
        "timestamp": datetime.now(timezone.utc).isoformat()
    })


# 2. Models Endpoints
async def list_models(request: Request) -> JSONResponse:
    return JSONResponse({"models": runtime.list_models()})

async def load_model(request: Request) -> JSONResponse:
    model_id = request.path_params.get("model_id")
    try:
        ok = runtime.load_model(model_id)
        asyncio.create_task(ws_manager.broadcast({"event": "MODEL_LOADED", "model_id": model_id}))
        return JSONResponse({"model_id": model_id, "loaded": ok})
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=400)

async def unload_model(request: Request) -> JSONResponse:
    model_id = request.path_params.get("model_id")
    ok = runtime.unload_model(model_id)
    asyncio.create_task(ws_manager.broadcast({"event": "MODEL_UNLOADED", "model_id": model_id}))
    return JSONResponse({"model_id": model_id, "unloaded": ok})


# 3. Hypotheses Endpoints
async def list_hypotheses(request: Request) -> JSONResponse:
    res = tools.list_hypotheses({})
    return JSONResponse(res)

async def create_hypothesis(request: Request) -> JSONResponse:
    try:
        data = await request.json()
    except Exception:
        data = {}
    try:
        res = tools.create_hypothesis(data)
        asyncio.create_task(ws_manager.broadcast({"event": "HYPOTHESIS_CREATED", "data": res}))
        return JSONResponse(res)
    except ToolValidationError as e:
        return JSONResponse({"error": str(e)}, status_code=400)


# 4. Experiments Endpoints
async def list_experiments(request: Request) -> JSONResponse:
    conn = db.get_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM experiments ORDER BY created_at DESC LIMIT 100")
        rows = [dict(r) for r in cur.fetchall()]
        return JSONResponse({"experiments": rows})
    finally:
        conn.close()

async def create_experiment(request: Request) -> JSONResponse:
    try:
        data = await request.json()
    except Exception:
        data = {}

    rounds = data.get("rounds")
    if rounds is None:
        return JSONResponse({"error": "Field 'rounds' is required."}, status_code=400)

    # ANTI-CLAMPING CHECK
    try:
        rounds = int(rounds)
    except (ValueError, TypeError):
        return JSONResponse({"error": "Field 'rounds' must be an integer."}, status_code=400)

    if rounds < 1 or rounds > 64:
        return JSONResponse({
            "error": f"Anti-clamping violation: rounds must be between 1 and 64 (got {rounds})."
        }, status_code=400)

    res = tools.create_experiment(data)
    if res.get("status") == "REJECTED":
        return JSONResponse({"error": res.get("error")}, status_code=400)

    asyncio.create_task(ws_manager.broadcast({"event": "EXPERIMENT_QUEUED", "data": res}))
    return JSONResponse(res)

async def get_experiment(request: Request) -> JSONResponse:
    exp_id = request.path_params.get("experiment_id")
    try:
        res = tools.get_experiment({"experiment_id": exp_id})
        return JSONResponse(res)
    except ToolValidationError as e:
        return JSONResponse({"error": str(e)}, status_code=404)

async def cancel_experiment(request: Request) -> JSONResponse:
    exp_id = request.path_params.get("experiment_id")
    res = tools.cancel_experiment({"experiment_id": exp_id})
    asyncio.create_task(ws_manager.broadcast({"event": "EXPERIMENT_CANCELLED", "data": res}))
    return JSONResponse(res)


# 5. Jobs & Evidence Endpoints
async def list_jobs(request: Request) -> JSONResponse:
    conn = db.get_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM jobs ORDER BY created_at DESC LIMIT 100")
        rows = [dict(r) for r in cur.fetchall()]
        return JSONResponse({"jobs": rows})
    finally:
        conn.close()

async def list_evidence(request: Request) -> JSONResponse:
    conn = db.get_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM artifacts ORDER BY created_at DESC LIMIT 100")
        rows = [dict(r) for r in cur.fetchall()]
        return JSONResponse({"artifacts": rows})
    finally:
        conn.close()

async def get_evidence_package(request: Request) -> JSONResponse:
    exp_id = request.path_params.get("experiment_id")
    exp_dir = os.path.join("evidence", "experiments", exp_id)
    manifest_path = os.path.join(exp_dir, "manifest.json")
    if not os.path.exists(manifest_path):
        return JSONResponse({"error": f"Evidence package for '{exp_id}' not found."}, status_code=404)
    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)
    return JSONResponse(manifest)

async def verify_candidate(request: Request) -> JSONResponse:
    try:
        data = await request.json()
    except Exception:
        data = {}
    try:
        res = tools.verify_candidate(data)
        return JSONResponse(res)
    except ToolValidationError as e:
        return JSONResponse({"error": str(e)}, status_code=400)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=400)


# 6. Reports & Campaigns
async def list_reports(request: Request) -> JSONResponse:
    conn = db.get_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM reports ORDER BY created_at DESC")
        return JSONResponse({"reports": [dict(r) for r in cur.fetchall()]})
    finally:
        conn.close()

async def start_campaign(request: Request) -> JSONResponse:
    try:
        data = await request.json()
    except Exception:
        data = {}

    rounds = int(data.get("target_rounds", 4))
    solver = data.get("solver", "cadical")

    if rounds < 1 or rounds > 64:
        return JSONResponse({"error": f"Anti-clamping violation: rounds must be in [1, 64] (got {rounds})."}, status_code=400)

    def _run():
        res = campaign.run_cycle(target_rounds=rounds, solver=solver)
        asyncio.run(ws_manager.broadcast({"event": "CAMPAIGN_CYCLE_FINISHED", "data": res}))

    t = threading.Thread(target=_run, daemon=True)
    t.start()

    return JSONResponse({"status": "STARTED", "target_rounds": rounds, "solver": solver})

async def stop_campaign(request: Request) -> JSONResponse:
    campaign.is_active = False
    return JSONResponse({"status": "STOPPED"})

async def get_campaign_status(request: Request) -> JSONResponse:
    return JSONResponse({
        "is_active": campaign.is_active,
        "completed_cycles": campaign.cycle_count,
        "active_jobs": len(worker_pool.active_jobs)
    })

async def get_events(request: Request) -> JSONResponse:
    limit = int(request.query_params.get("limit", 50))
    conn = db.get_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,))
        return JSONResponse({"events": [dict(r) for r in cur.fetchall()]})
    finally:
        conn.close()


# 7. WebSocket Live Events
async def websocket_events(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            await websocket.send_text(json.dumps({"event": "PONG", "received": data}))
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)


# 8. Frontend UI Static Serving
FRONTEND_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "frontend")

async def serve_index(request: Request):
    index_file = os.path.join(FRONTEND_DIR, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return HTMLResponse("<h1>SHA-256 Research Platform v3.0 (Headless Backend Active)</h1>")


routes = [
    Route("/api/status", get_status, methods=["GET"]),
    Route("/api/system", get_system, methods=["GET"]),
    Route("/api/models", list_models, methods=["GET"]),
    Route("/api/models/{model_id}/load", load_model, methods=["POST"]),
    Route("/api/models/{model_id}/unload", unload_model, methods=["POST"]),
    Route("/api/hypotheses", list_hypotheses, methods=["GET"]),
    Route("/api/hypotheses", create_hypothesis, methods=["POST"]),
    Route("/api/experiments", list_experiments, methods=["GET"]),
    Route("/api/experiments", create_experiment, methods=["POST"]),
    Route("/api/experiments/{experiment_id}", get_experiment, methods=["GET"]),
    Route("/api/experiments/{experiment_id}/cancel", cancel_experiment, methods=["POST"]),
    Route("/api/jobs", list_jobs, methods=["GET"]),
    Route("/api/evidence", list_evidence, methods=["GET"]),
    Route("/api/evidence/{experiment_id}", get_evidence_package, methods=["GET"]),
    Route("/api/verify", verify_candidate, methods=["POST"]),
    Route("/api/reports", list_reports, methods=["GET"]),
    Route("/api/campaign/start", start_campaign, methods=["POST"]),
    Route("/api/campaign/stop", stop_campaign, methods=["POST"]),
    Route("/api/campaign/status", get_campaign_status, methods=["GET"]),
    Route("/api/events", get_events, methods=["GET"]),
    WebSocketRoute("/ws/events", websocket_events),
    Route("/", serve_index, methods=["GET"]),
]

if os.path.isdir(FRONTEND_DIR):
    routes.append(Mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static"))

app = Starlette(debug=False, routes=routes)
