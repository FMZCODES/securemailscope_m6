from __future__ import annotations

import logging
import os
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, RedirectResponse

from app.database import (
    check_connection,
    get_analysis,
    save_analysis,
)

from app.analysis.pipeline import run_full_pipeline


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("securemailscope")

RESULT_CACHE: dict[str, dict[str, Any]] = {}

BASE_DIR = Path(__file__).resolve().parent.parent
UPLOAD_DIR = BASE_DIR / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

# The React dashboard is deployed as a Render static site. The API root
# redirects there so opening the main Render URL shows the actual frontend.
DASHBOARD_URL = os.getenv(
    "DASHBOARD_URL",
    "https://securemailscope-m6-dashboard.onrender.com",
).rstrip("/")

app = FastAPI(
    title="SecureMailScope M6 API",
    version="0.3.0",
    description=(
        "SecureMailScope M6 API - "
        "M2 PCAP parsing + M3 stream analysis + "
        "M4 TLS/certificate analysis + M5 AI/ML risk analysis."
    ),
)

# The frontend is deployed separately on Render. Allow local Vite,
# Render static sites, and other explicitly configured origins.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_origin_regex=r"https://.*\.onrender\.com",
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/", include_in_schema=False)
def root():
    return RedirectResponse(url=DASHBOARD_URL, status_code=307)


@app.get("/dashboard", include_in_schema=False)
def dashboard():
    return RedirectResponse(url=DASHBOARD_URL, status_code=307)


@app.get("/health")
def health():
    try:
        mongo_ok = check_connection()
    except Exception:
        mongo_ok = False

    return {
        "status": "healthy",
        "database": "connected" if mongo_ok else "unavailable",
        "pipeline": "M2 -> M3 -> M4 -> M5",
        "cached_results": len(RESULT_CACHE),
    }


def run_m2_parser(pcap_path: Path) -> dict[str, Any]:
    command = [
        sys.executable,
        "-m",
        "app.analysis.m2_parser.parser",
        str(pcap_path),
    ]

    logger.info("Starting M2 parser: %s", " ".join(command))

    try:
        process = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            stdin=subprocess.DEVNULL,
            timeout=300,
            cwd=str(BASE_DIR),
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError("M2 parser timed out after 300 seconds.")
    except Exception as exc:
        raise RuntimeError(f"Could not start M2 parser: {exc}")

    stdout = process.stdout or ""
    stderr = process.stderr or ""

    logger.info("M2 parser exit code: %s", process.returncode)

    if stderr:
        logger.info("M2 parser stderr:\n%s", stderr)

    if process.returncode != 0:
        raise RuntimeError(
            "M2 parser failed.\n"
            f"Exit code: {process.returncode}\n"
            f"STDOUT:\n{stdout}\n"
            f"STDERR:\n{stderr}"
        )

    return {
        "exit_code": process.returncode,
        "stdout": stdout,
        "stderr": stderr,
    }


def extract_m2_summary(output: str) -> dict[str, Any]:
    summary = {
        "total_packets": None,
        "smtp_packets": None,
        "imap_packets": None,
        "pop3_packets": None,
        "unknown_packets": None,
        "skipped_packets": None,
    }

    for line in output.splitlines():
        line = line.strip()
        if line.startswith("Packets:"):
            try:
                summary["total_packets"] = int(line.split(":", 1)[1].strip())
            except Exception:
                pass

    summary_start = output.find("ProtocolSummary(")
    if summary_start == -1:
        return summary

    summary_end = output.find(")", summary_start)
    if summary_end == -1:
        return summary

    summary_text = output[summary_start:summary_end + 1]

    for field in summary:
        marker = field + "="
        position = summary_text.find(marker)
        if position == -1:
            continue

        value_start = position + len(marker)
        value_end = summary_text.find(",", value_start)
        if value_end == -1:
            value_end = summary_text.find(")", value_start)
        if value_end == -1:
            continue

        try:
            summary[field] = int(summary_text[value_start:value_end].strip())
        except ValueError:
            pass

    return summary


def run_m3_m4_m5(pcap_path: Path) -> dict[str, Any]:
    logger.info("Starting M3 -> M4 -> M5 pipeline: %s", pcap_path)
    try:
        pipeline_result = run_full_pipeline(pcap_path)
    except Exception as exc:
        logger.exception("M3 -> M4 -> M5 pipeline failed.")
        raise RuntimeError(f"M3-M5 pipeline failed: {exc}")

    logger.info("M3 -> M4 -> M5 pipeline completed.")
    return pipeline_result


@app.post("/upload-pcap")
async def upload_pcap(file: UploadFile = File(...)):
    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename supplied.")

    original_filename = Path(file.filename).name
    extension = Path(original_filename).suffix.lower()

    if extension not in {".pcap", ".pcapng", ".cap"}:
        raise HTTPException(
            status_code=400,
            detail="Unsupported file type. Upload .pcap, .pcapng or .cap.",
        )

    analysis_id = str(uuid.uuid4())
    stored_filename = f"{analysis_id}_{original_filename}"
    pcap_path = UPLOAD_DIR / stored_filename

    try:
        with pcap_path.open("wb") as destination:
            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break
                destination.write(chunk)
    except Exception as exc:
        logger.exception("PCAP upload failed.")
        raise HTTPException(status_code=500, detail=f"PCAP upload failed: {exc}")
    finally:
        await file.close()

    logger.info("PCAP uploaded: %s", pcap_path)

    try:
        parser_result = run_m2_parser(pcap_path)
    except Exception as exc:
        logger.exception("M2 analysis failed.")
        raise HTTPException(status_code=500, detail=f"M2 PCAP analysis failed: {exc}")

    m2_summary = extract_m2_summary(parser_result["stdout"])
    logger.info("M2 summary: %s", m2_summary)

    try:
        pipeline_result = run_m3_m4_m5(pcap_path)
    except Exception as exc:
        logger.exception("M3-M5 analysis failed.")
        raise HTTPException(
            status_code=500,
            detail=f"M2 analysis succeeded, but M3-M5 pipeline failed: {exc}",
        )

    analysis = {
        "analysis_id": analysis_id,
        "filename": original_filename,
        "stored_filename": stored_filename,
        "pipeline": "M2 -> M3 -> M4 -> M5",
        "status": "completed",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "m2": {
            "module": "M2",
            "summary": m2_summary,
            "parser": {
                "exit_code": parser_result.get("exit_code"),
                "stdout": parser_result.get("stdout", ""),
                "stderr": parser_result.get("stderr", ""),
            },
        },
        "m3": pipeline_result.get("m3", {}),
        "m4": pipeline_result.get("m4", {}),
        "m5": pipeline_result.get("m5", {}),
        "mongodb_saved": False,
    }

    # Always cache the complete analysis before touching MongoDB.
    RESULT_CACHE[analysis_id] = analysis.copy()

    mongodb_saved = False
    try:
        mongodb_saved = bool(save_analysis(analysis))
    except Exception:
        logger.exception("MongoDB save failed.")

    analysis["mongodb_saved"] = mongodb_saved
    analysis["message"] = (
        "PCAP analyzed successfully and result persisted to MongoDB."
        if mongodb_saved
        else "PCAP analyzed successfully. MongoDB persistence is unavailable, "
        "but the complete analysis result is available from the API cache."
    )

    RESULT_CACHE[analysis_id] = analysis.copy()
    return analysis


@app.get("/results/{analysis_id}")
def get_results(analysis_id: str):
    try:
        analysis = get_analysis(analysis_id)
    except Exception:
        logger.exception("MongoDB lookup failed.")
        analysis = None

    if analysis is None:
        analysis = RESULT_CACHE.get(analysis_id)

    if analysis is None:
        raise HTTPException(
            status_code=404,
            detail="Analysis not found in MongoDB or temporary API cache.",
        )

    return analysis


@app.get("/report/{analysis_id}/json")
def json_report(analysis_id: str):
    try:
        analysis = get_analysis(analysis_id)
    except Exception:
        logger.exception("MongoDB JSON lookup failed.")
        analysis = None

    if analysis is None:
        analysis = RESULT_CACHE.get(analysis_id)

    if analysis is None:
        raise HTTPException(
            status_code=404,
            detail="Analysis not found in MongoDB or temporary API cache.",
        )

    return analysis


@app.get("/report/{analysis_id}/html")
def html_report(analysis_id: str):
    try:
        analysis = get_analysis(analysis_id)
    except Exception:
        logger.exception("MongoDB HTML lookup failed.")
        analysis = None

    if analysis is None:
        analysis = RESULT_CACHE.get(analysis_id)

    if analysis is None:
        raise HTTPException(
            status_code=404,
            detail="Analysis not found in MongoDB or temporary API cache.",
        )

    m2 = analysis.get("m2", {})
    summary = m2.get("summary", {})
    m3 = analysis.get("m3", {})
    m4 = analysis.get("m4", {})
    m5 = analysis.get("m5", {})

    html = f"""
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>SecureMailScope M2-M5 Report</title>
<style>
body {{ font-family: Arial, sans-serif; margin: 40px; background: #f4f6f8; color: #222; }}
.container {{ max-width: 1100px; margin: auto; background: white; padding: 30px; border-radius: 12px; }}
table {{ border-collapse: collapse; width: 100%; margin-bottom: 30px; }}
th, td {{ border: 1px solid #ccc; padding: 10px; text-align: left; }}
th {{ background: #f2f2f2; }}
pre {{ background: #f5f5f5; padding: 15px; overflow-x: auto; border-radius: 8px; }}
</style>
</head>
<body>
<div class="container">
<h1>SecureMailScope Security Report</h1>
<p><strong>Analysis ID:</strong> {analysis.get("analysis_id", "N/A")}</p>
<p><strong>Filename:</strong> {analysis.get("filename", "N/A")}</p>
<p><strong>Status:</strong> {analysis.get("status", "N/A")}</p>
<p><strong>Pipeline:</strong> M2 -&gt; M3 -&gt; M4 -&gt; M5</p>
<p><strong>MongoDB Saved:</strong> {analysis.get("mongodb_saved", False)}</p>
<h2>M2 - PCAP Analysis</h2>
<table>
<tr><th>Metric</th><th>Value</th></tr>
<tr><td>Total Packets</td><td>{summary.get("total_packets", 0)}</td></tr>
<tr><td>SMTP Packets</td><td>{summary.get("smtp_packets", 0)}</td></tr>
<tr><td>IMAP Packets</td><td>{summary.get("imap_packets", 0)}</td></tr>
<tr><td>POP3 Packets</td><td>{summary.get("pop3_packets", 0)}</td></tr>
<tr><td>Unknown Packets</td><td>{summary.get("unknown_packets", 0)}</td></tr>
<tr><td>Skipped Packets</td><td>{summary.get("skipped_packets", 0)}</td></tr>
</table>
<h2>M3 - Stream Analysis</h2>
<pre>{m3}</pre>
<h2>M4 - TLS / Certificate Analysis</h2>
<pre>{m4}</pre>
<h2>M5 - AI/ML Risk Analysis</h2>
<pre>{m5}</pre>
<h2>Complete JSON</h2>
<pre>{analysis}</pre>
</div>
</body>
</html>
"""

    return HTMLResponse(content=html)
