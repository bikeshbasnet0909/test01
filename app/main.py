"""Internal phishing analysis API.

Development-only: endpoints are not authenticated yet. Bind to loopback and do not
expose this service to a network until Bank SSO/MFA, RBAC, audit, and controls exist.
"""
from __future__ import annotations

import logging
from fastapi import FastAPI, File, HTTPException, UploadFile
from pydantic import BaseModel, Field, field_validator

from app.analyzer import MAX_EMAIL_BYTES, analyze_email

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("phishing-analysis")

app = FastAPI(
    title="Internal Phishing Analysis API",
    version="0.1.0",
    description="Read-only local email triage. Development scaffold; not production-ready.",
    docs_url="/docs",
    redoc_url=None,
)

class PasteRequest(BaseModel):
    raw_email: str = Field(min_length=1, max_length=MAX_EMAIL_BYTES)
    @field_validator("raw_email")
    @classmethod
    def reject_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("raw_email must not be blank")
        return value

@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}

def _run_analysis(raw: bytes) -> dict:
    try:
        return analyze_email(raw)
    except ValueError as exc:
        raise HTTPException(status_code=413 if "exceeds" in str(exc) else 400, detail=str(exc)) from exc
    except Exception:
        logger.exception("Email analysis failed; content omitted from logs")
        raise HTTPException(status_code=400, detail="Unable to parse this email safely.") from None

@app.post("/api/v1/analyze/eml")
async def analyze_eml(file: UploadFile = File(...)) -> dict:
    filename = (file.filename or "").replace("\\", "/").split("/")[-1]
    if not filename.lower().endswith(".eml"):
        raise HTTPException(status_code=415, detail="Upload a .eml file.")
    raw = await file.read(MAX_EMAIL_BYTES + 1)
    await file.close()
    if len(raw) > MAX_EMAIL_BYTES:
        raise HTTPException(status_code=413, detail="Email exceeds the 2 MiB limit.")
    if not raw:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")
    return _run_analysis(raw)

@app.post("/api/v1/analyze/paste")
def analyze_paste(request: PasteRequest) -> dict:
    raw = request.raw_email.encode("utf-8", errors="strict")
    if len(raw) > MAX_EMAIL_BYTES:
        raise HTTPException(status_code=413, detail="Email exceeds the 2 MiB limit.")
    return _run_analysis(raw)
