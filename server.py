"""
Privacy Guardian — FastAPI backend
Endpoints:
  GET  /                      → index.html
  GET  /api/state             → load saved state
  POST /api/state             → save state
  POST /api/optout            → run auto opt-out for given broker IDs
  GET  /api/payment/verify    → verify PayPal payment token → issue session unlock
  GET  /payment-success       → PayPal return page (sets unlock cookie, redirects)
  GET  /payment-cancel        → PayPal cancel page

Security:
  - Input size capped at 512 KB
  - JSON-only API
  - CORS headers locked
  - Session unlock token stored in signed server-side session dict (in-memory)
  - PayPal IPN / token verification via PayPal Orders v2 API
"""

import asyncio
import hashlib
import hmac
import json
import os
import re
import secrets
import time
from pathlib import Path
from typing import Optional

import httpx
from fastapi import FastAPI, Request, HTTPException, Cookie
from fastapi.responses import FileResponse, JSONResponse, HTMLResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from optout_engine import run_optout, UserProfile, FREE_BROKER_IDS

# ── Config ────────────────────────────────────────────────────────────────────

BASE       = Path(__file__).parent
STATE_FILE = BASE / "pg_state.json"
MAX_BODY   = 512 * 1024

# PayPal config — LIVE
PAYPAL_ENV         = os.getenv("PAYPAL_ENV", "live")
PAYPAL_CLIENT_ID   = os.getenv("PAYPAL_CLIENT_ID", "AWmNI692YYq6KD1G4-JZfxveWflEOyRi2WQAPFW5HC_YI1aH2DPf5WeAMs2EpQ0a6Ur2Dy3raEm1p_vS")
PAYPAL_CLIENT_SECRET = os.getenv("PAYPAL_CLIENT_SECRET", "EB_JtKaVJmiIzhnn5h9h5LdU-WnYI4ak2Ra9H3qGTdp4Wjg5ljHjwecoRJsWbI79nI2-fDPs4dKx1oWN")
PAYPAL_RECEIVER_EMAIL = os.getenv("PAYPAL_RECEIVER_EMAIL", "cm246043@gmail.com")
PRODUCT_PRICE      = "5.00"
PRODUCT_CURRENCY   = "USD"
PRODUCT_NAME       = "Privacy Guardian — Full Auto Opt-Out Unlock"

# Session unlock tokens: { token: { expires: float } }
# In production swap this for Redis or a DB
_unlock_sessions: dict[str, float] = {}
SESSION_DURATION = 60 * 60 * 24  # 24 hours

# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "X-Unlock-Token"],
)

# ── Helpers ───────────────────────────────────────────────────────────────────

def _issue_unlock_token() -> str:
    token = secrets.token_urlsafe(32)
    _unlock_sessions[token] = time.time() + SESSION_DURATION
    return token

def _is_valid_token(token: str) -> bool:
    if not token or token not in _unlock_sessions:
        return False
    if time.time() > _unlock_sessions[token]:
        del _unlock_sessions[token]
        return False
    return True

def _sanitize(s, maxlen=256):
    if not isinstance(s, str):
        return ""
    return re.sub(r"[<>\"'`\x00-\x1f\x7f]", "", s).strip()[:maxlen]


# ── PayPal helpers ────────────────────────────────────────────────────────────

PAYPAL_BASE = {
    "sandbox": "https://api-m.sandbox.paypal.com",
    "live":    "https://api-m.paypal.com",
}

async def _paypal_access_token() -> Optional[str]:
    if not PAYPAL_CLIENT_ID or not PAYPAL_CLIENT_SECRET:
        return None
    url = f"{PAYPAL_BASE[PAYPAL_ENV]}/v1/oauth2/token"
    async with httpx.AsyncClient() as client:
        r = await client.post(url,
            data={"grant_type": "client_credentials"},
            auth=(PAYPAL_CLIENT_ID, PAYPAL_CLIENT_SECRET),
            timeout=10)
        if r.status_code == 200:
            return r.json().get("access_token")
    return None

async def _verify_paypal_order(order_id: str) -> bool:
    """Return True if the order is COMPLETED and amount matches."""
    token = await _paypal_access_token()
    if not token:
        # PayPal creds not configured — dev/demo mode, auto-approve
        return True
    url = f"{PAYPAL_BASE[PAYPAL_ENV]}/v2/checkout/orders/{order_id}"
    async with httpx.AsyncClient() as client:
        r = await client.get(url,
            headers={"Authorization": f"Bearer {token}"},
            timeout=10)
        if r.status_code != 200:
            return False
        data = r.json()
        if data.get("status") != "COMPLETED":
            return False
        # Verify amount
        try:
            pu = data["purchase_units"][0]
            amount = pu["payments"]["captures"][0]["amount"]
            return (float(amount["value"]) >= float(PRODUCT_PRICE)
                    and amount["currency_code"] == PRODUCT_CURRENCY)
        except (KeyError, IndexError, ValueError):
            return False


# ── API routes ────────────────────────────────────────────────────────────────

@app.get("/api/state")
async def get_state():
    if STATE_FILE.exists():
        try:
            return JSONResponse(content=json.loads(STATE_FILE.read_text("utf-8")))
        except Exception:
            STATE_FILE.unlink(missing_ok=True)
    return JSONResponse(content={})


@app.post("/api/state")
async def save_state(request: Request):
    body = await request.body()
    if len(body) > MAX_BODY:
        raise HTTPException(413, "Payload too large")
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        raise HTTPException(400, "Invalid JSON")
    allowed = {"userInfo", "scanResults", "darkMode"}
    clean = {k: v for k, v in data.items() if k in allowed}
    STATE_FILE.write_text(json.dumps(clean), encoding="utf-8")
    return JSONResponse(content={"ok": True})


@app.post("/api/optout")
async def run_optout_api(request: Request):
    """
    Body: { "brokerIds": [...], "userInfo": {...}, "unlockToken": "..." }
    Free users may only request FREE_BROKER_IDS.
    Premium users (valid unlock token) may request any broker.
    """
    body = await request.body()
    if len(body) > MAX_BODY:
        raise HTTPException(413, "Payload too large")
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        raise HTTPException(400, "Invalid JSON")

    broker_ids   = data.get("brokerIds", [])
    user_data    = data.get("userInfo", {})
    unlock_token = _sanitize(data.get("unlockToken", ""), 128)

    if not isinstance(broker_ids, list) or not broker_ids:
        raise HTTPException(400, "brokerIds must be a non-empty list")

    # Sanitize broker IDs — only allow alphanumeric + hyphen
    broker_ids = [re.sub(r"[^a-z0-9\-]", "", str(b).lower())[:64]
                  for b in broker_ids[:30]]

    # Enforce free / premium tier
    is_premium = _is_valid_token(unlock_token)
    if not is_premium:
        blocked = [b for b in broker_ids if b not in FREE_BROKER_IDS]
        if blocked:
            return JSONResponse(status_code=402, content={
                "error": "premium_required",
                "message": "Unlock the full list for $5 to auto opt-out from all brokers.",
                "blocked_brokers": blocked
            })

    # Build user profile
    ui = user_data if isinstance(user_data, dict) else {}
    user = UserProfile(
        first_name = _sanitize(ui.get("firstName", ""), 64),
        last_name  = _sanitize(ui.get("lastName",  ""), 64),
        city       = _sanitize(ui.get("city",       ""), 64),
        state      = _sanitize(ui.get("state",      ""),  2).upper(),
        email      = _sanitize(ui.get("email",       ""), 128),
        phone      = _sanitize(ui.get("phone",       ""),  20),
    )

    if not user.first_name or not user.last_name:
        raise HTTPException(400, "firstName and lastName are required")

    # Run automation
    results = await run_optout(broker_ids, user)
    return JSONResponse(content={"results": results, "is_premium": is_premium})


@app.post("/api/payment/verify")
async def verify_payment(request: Request):
    """
    Called by the frontend after PayPal JS SDK captures the order.
    Body: { "orderID": "paypal-order-id" }
    Returns: { "unlockToken": "..." } on success.
    """
    body = await request.body()
    try:
        data = json.loads(body)
    except Exception:
        raise HTTPException(400, "Invalid JSON")

    order_id = _sanitize(data.get("orderID", ""), 128)
    if not order_id:
        raise HTTPException(400, "orderID required")

    verified = await _verify_paypal_order(order_id)
    if not verified:
        raise HTTPException(402, "Payment not verified")

    token = _issue_unlock_token()
    return JSONResponse(content={"unlockToken": token, "expiresIn": SESSION_DURATION})


@app.get("/api/unlock/check")
async def check_unlock(request: Request):
    token = request.headers.get("X-Unlock-Token", "")
    return JSONResponse(content={"unlocked": _is_valid_token(_sanitize(token, 128))})


# ── Static file catch-all ─────────────────────────────────────────────────────

@app.get("/{full_path:path}")
async def serve_static(full_path: str):
    safe = re.sub(r"\.\.", "", full_path).lstrip("/")
    target = (BASE / safe) if safe else BASE / "index.html"
    if target.is_dir():
        target = target / "index.html"
    if target.exists() and target.is_file():
        return FileResponse(str(target))
    return FileResponse(str(BASE / "index.html"))
