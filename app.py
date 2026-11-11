"""Prompt-Injection Guard - demo web app (FastAPI).

Endpoints:
    GET  /              demo UI (single page)
    GET  /api/samples   built-in sample prompts for the UI
    POST /api/score     score a prompt -> {score, verdict, findings, ...}
    GET  /healthz       liveness check

MVP hardening (see README "Security notes"):
  * request body size limit (default 16 KB) -> 413
  * prompt length limit via schema validation (default 4,000 chars) -> 422
  * per-IP in-memory rate limit (default 30 requests / 60 s) -> 429
  * logs record score / verdict / detector names + a truncated SHA-256 of
    the prompt - NEVER the raw prompt text
  * basic security headers on every response

Configuration comes from the environment (see .env.example); all values
have safe defaults so the app runs with zero setup.
"""

from __future__ import annotations

import hashlib
import logging
import os
import time
from collections import defaultdict, deque
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from guard.engine import GuardEngine
from guard.samples import SAMPLES

BASE_DIR = Path(__file__).resolve().parent

MAX_BODY_BYTES = int(os.getenv("GUARD_MAX_BODY_BYTES", "16384"))
MAX_PROMPT_CHARS = int(os.getenv("GUARD_MAX_PROMPT_CHARS", "4000"))
RATE_LIMIT = int(os.getenv("GUARD_RATE_LIMIT", "30"))
RATE_WINDOW = int(os.getenv("GUARD_RATE_WINDOW_SECONDS", "60"))
FLAG_THRESHOLD = int(os.getenv("GUARD_FLAG_THRESHOLD", "30"))
BLOCK_THRESHOLD = int(os.getenv("GUARD_BLOCK_THRESHOLD", "65"))

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("prompt-guard")

engine = GuardEngine(flag_threshold=FLAG_THRESHOLD, block_threshold=BLOCK_THRESHOLD)

app = FastAPI(title="Prompt-Injection Guard", version="0.1.0")
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")

# --------------------------------------------------------------------------
# Rate limiting (simple in-memory sliding window per client IP)
# --------------------------------------------------------------------------
_hits: dict[str, deque[float]] = defaultdict(deque)


def rate_limited(ip: str) -> bool:
    now = time.monotonic()
    window = _hits[ip]
    while window and window[0] <= now - RATE_WINDOW:
        window.popleft()
    if len(window) >= RATE_LIMIT:
        return True
    window.append(now)
    return False


# --------------------------------------------------------------------------
# Middleware: body size limit + security headers
# --------------------------------------------------------------------------
@app.middleware("http")
async def hardening(request: Request, call_next):
    if request.url.path == "/api/score":
        length = request.headers.get("content-length")
        if length is not None and int(length) > MAX_BODY_BYTES:
            return JSONResponse(status_code=413, content={"detail": "Request body too large"})
        client_ip = request.client.host if request.client else "unknown"
        if rate_limited(client_ip):
            return JSONResponse(status_code=429, content={"detail": "Rate limit exceeded"})
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'"
    )
    return response


# --------------------------------------------------------------------------
# API
# --------------------------------------------------------------------------
class ScoreRequest(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=MAX_PROMPT_CHARS)


class ScoreResponse(BaseModel):
    score: int
    verdict: str
    heuristic_score: int
    statistical_score: float
    findings: list[dict]


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return (BASE_DIR / "static" / "index.html").read_text(encoding="utf-8")


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok"}


@app.get("/api/samples")
def samples() -> dict:
    return SAMPLES


@app.post("/api/score", response_model=ScoreResponse)
def score(body: ScoreRequest) -> dict:
    result = engine.evaluate(body.prompt)
    # Log metadata only: score, verdict, detector names, truncated hash.
    prompt_hash = hashlib.sha256(body.prompt.encode("utf-8")).hexdigest()[:12]
    logger.info(
        "score=%s verdict=%s detectors=%s prompt_sha256=%s",
        result.score,
        result.verdict,
        [f.detector for f in result.findings],
        prompt_hash,
    )
    return result.to_dict()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=int(os.getenv("PORT", "8000")))
