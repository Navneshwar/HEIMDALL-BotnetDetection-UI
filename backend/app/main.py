from __future__ import annotations

import logging
import tempfile
from collections import Counter
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import pandas as pd
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware

from .feature_extraction import extract_flows
from .inference import HEIMDALLInference, missing_artifacts
from .settings import ATTRIBUTION_DIR, MAX_UPLOAD_BYTES, MODEL_DIR, RISK_LEVELS


class RuntimeState:
    engine: HEIMDALLInference | None = None
    model_error: str | None = None


runtime = RuntimeState()
logger = logging.getLogger("heimdall")


@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        runtime.engine = HEIMDALLInference(MODEL_DIR, ATTRIBUTION_DIR)
        runtime.model_error = None
    except Exception as exc:
        runtime.engine = None
        runtime.model_error = str(exc)
        logger.exception("HEIMDALL inference bundle could not be loaded")
    yield
    runtime.engine = None


app = FastAPI(
    title="HEIMDALL Capture Analysis API",
    version="1.0.0",
    description="Local PCAP analysis and model inference service.",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


@app.get("/api/health")
def health() -> dict[str, Any]:
    absent = missing_artifacts(MODEL_DIR, ATTRIBUTION_DIR)
    return {
        "service": "HEIMDALL",
        "status": "ready" if runtime.engine is not None else "model_unavailable",
        "model_ready": runtime.engine is not None,
        "model_message": (
            "The inference model is loaded and ready."
            if runtime.engine is not None
            else "The trained model bundle is not ready. Check backend logs and model deployment instructions."
        ),
        "missing_artifact_count": len(absent),
    }


@app.post("/api/analyze")
async def analyze_capture(file: UploadFile = File(...)) -> dict[str, Any]:
    if runtime.engine is None:
        raise HTTPException(
            status_code=503,
            detail=(
                "The trained model is not ready. Configure the approved model bundle "
                "and restart the backend. Check backend logs for configuration details."
            ).strip(),
        )

    filename = Path(file.filename or "capture.pcap").name
    suffix = Path(filename).suffix.lower()
    if suffix not in {".pcap", ".pcapng", ".cap"}:
        raise HTTPException(status_code=400, detail="Upload a .pcap, .pcapng, or .cap file.")

    content = await file.read(MAX_UPLOAD_BYTES + 1)
    if not content:
        raise HTTPException(status_code=400, detail="The uploaded capture is empty.")
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"The upload exceeds the {MAX_UPLOAD_BYTES // (1024 * 1024)} MiB limit.",
        )

    temp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(prefix="heimdall_", suffix=suffix, delete=False) as temp:
            temp.write(content)
            temp_path = Path(temp.name)

        extracted = extract_flows(temp_path)
        flows = extracted["flows"]
        if not flows:
            raise HTTPException(
                status_code=422,
                detail="No supported IPv4/IPv6 TCP or UDP flows were found in this capture.",
            )

        scored_flows = runtime.engine.predict_batch(pd.DataFrame(flows))
        risk_counts = Counter(item["risk_level"] for item in scored_flows)
        attribution_counts = Counter(item["attribution"] for item in scored_flows if item["is_anomalous"])
        flagged = sum(1 for item in scored_flows if item["is_anomalous"])
        total = len(scored_flows)

        # Transparent file-level rule: any flow above the configured model threshold
        # marks the capture for investigation. This is a triage verdict, not proof.
        verdict = "BOTNET_ACTIVITY_DETECTED" if flagged else "NO_BOTNET_INDICATORS_DETECTED"
        return {
            "file_name": filename,
            "file_size_bytes": len(content),
            "packets_seen": extracted["packets_seen"],
            "packets_used": extracted["packets_used"],
            "packets_ignored": extracted["packets_ignored"],
            "flow_count": total,
            "flagged_flow_count": flagged,
            "flagged_flow_percentage": round(flagged / total * 100, 2),
            "verdict": verdict,
            "verdict_rule": "At least one flow exceeded the configured anomaly threshold.",
            "risk_distribution": {level: risk_counts.get(level, 0) for level in RISK_LEVELS},
            "attribution_distribution": dict(attribution_counts),
            "flows": scored_flows,
        }
    except HTTPException:
        raise
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=422,
            detail="The capture could not be parsed. Confirm that it is a valid PCAP or PCAPNG file.",
        ) from exc
    finally:
        await file.close()
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)
