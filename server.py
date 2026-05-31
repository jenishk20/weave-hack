"""
server.py — FastAPI HTTP gateway around orchestrate().

Start: uvicorn server:app --host 0.0.0.0 --port 8765 --reload
The interceptor shell script POSTs here; the response drives block/allow.
"""
from __future__ import annotations

import dataclasses
import os

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel

import weave_shim as W
from orchestrator import orchestrate

load_dotenv()
W.init(os.getenv("WANDB_PROJECT", "quarantine"))

app = FastAPI(title="Quarantine — npm supply-chain scanner", version="1.0.0")


class ScanRequest(BaseModel):
    package: str
    version: str = "latest"


@app.post("/scan")
def scan(req: ScanRequest):
    if not req.package or "/" in req.package:
        raise HTTPException(status_code=400, detail="Invalid package name")
    result = orchestrate(req.package, req.version)
    return JSONResponse(content=_to_json(result))


@app.get("/health")
def health():
    return {"status": "ok"}


def _to_json(obj):
    """Recursively convert dataclasses to plain dicts for JSON serialisation."""
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {k: _to_json(v) for k, v in dataclasses.asdict(obj).items()}
    if isinstance(obj, dict):
        return {k: _to_json(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_to_json(i) for i in obj]
    return obj
