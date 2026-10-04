from __future__ import annotations

import logging
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse

from app.database import (
    check_connection,
    get_analysis,
    save_analysis,
)

from app.analysis.pipeline import run_full_pipeline


# ============================================================
# LOGGING
# ============================================================

logging.basicConfig(
    level=logging.INFO,
)

logger = logging.getLogger("securemailscope")


# ============================================================
# PATHS
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent

UPLOAD_DIR = BASE_DIR / "uploads"

UPLOAD_DIR.mkdir(
    parents=True,
    exist_ok=True,
)


# ============================================================
# FASTAPI
# ============================================================

app = FastAPI(
    title="SecureMailScope M6 API",
    version="0.2.0",
    description=(
        "SecureMailScope M6 API - "
        "M2 PCAP parsing + M3 stream analysis + "
        "M4 TLS/certificate analysis + "
        "M5 AI/ML risk analysis."
    ),
)


# ============================================================
# CORS
# ============================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# ROOT
# ============================================================

@app.get("/")
def root():
    return {
        "project": "SecureMailScope M6",
        "status": "running",
        "version": "0.2.0",
        "pipeline": "M2 -> M3 -> M4 -> M5",
    }


# ============================================================
# HEALTH
# ============================================================

@app.get("/health")
def health():
    """
    API and MongoDB health status.
    """

    mongo_ok = check_connection()

    return {
        "status": "healthy",
        "database": (
            "connected"
            if mongo_ok
            else "unavailable"
        ),
        "pipeline": "M2 -> M3 -> M4 -> M5",
    }


# ============================================================
# M2 PARSER
# ============================================================

def run_m2_parser(pcap_path: Path) -> dict[str, Any]:
    """
    Run M2 in a completely separate Python process.

    M2 uses PyShark/TShark and previously caused event-loop
    conflicts when executed directly inside FastAPI/Uvicorn.

    Therefore M2 continues to run using:

        python -m app.analysis.m2_parser.parser <pcap>
    """

    command = [
        sys.executable,
        "-m",
        "app.analysis.m2_parser.parser",
        str(pcap_path),
    ]

    logger.info(
        "Starting M2 parser: %s",
        " ".join(command),
    )

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
        raise RuntimeError(
            "M2 parser timed out after 300 seconds."
        )

    except Exception as exc:
        raise RuntimeError(
            f"Could not start M2 parser: {exc}"
        )

    stdout = process.stdout or ""
    stderr = process.stderr or ""

    logger.info(
        "M2 parser exit code: %s",
        process.returncode,
    )

    if stderr:
        logger.info(
            "M2 parser stderr:\n%s",
            stderr,
        )

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


# ============================================================
# EXTRACT M2 SUMMARY
# ============================================================

def extract_m2_summary(output: str) -> dict[str, Any]:
    """
    Extract ProtocolSummary values from M2 output.
    """

    summary = {
        "total_packets": None,
        "smtp_packets": None,
        "imap_packets": None,
        "pop3_packets": None,
        "unknown_packets": None,
        "skipped_packets": None,
    }

    lines = output.splitlines()

    for line in lines:

        line = line.strip()

        if line.startswith("Packets:"):

            try:
                value = line.split(
                    ":",
                    1,
                )[1].strip()

                summary["total_packets"] = int(value)

            except Exception:
                pass

    summary_start = output.find(
        "ProtocolSummary("
    )

    if summary_start == -1:
        return summary

    summary_end = output.find(
        ")",
        summary_start,
    )

    if summary_end == -1:
        return summary

    summary_text = output[
        summary_start:summary_end + 1
    ]

    fields = [
        "total_packets",
        "smtp_packets",
        "imap_packets",
        "pop3_packets",
        "unknown_packets",
        "skipped_packets",
    ]

    for field in fields:

        marker = field + "="

        position = summary_text.find(marker)

        if position == -1:
            continue

        value_start = position + len(marker)

        value_end = summary_text.find(
            ",",
            value_start,
        )

        if value_end == -1:
            value_end = summary_text.find(
                ")",
                value_start,
            )

        if value_end == -1:
            continue

        value = summary_text[
            value_start:value_end
        ].strip()

        try:
            summary[field] = int(value)

        except ValueError:
            pass

    return summary


# ============================================================
# RUN M3 -> M4 -> M5
# ============================================================

def run_m3_m4_m5(
    pcap_path: Path,
) -> dict[str, Any]:
    """
    Run the integrated M3 -> M4 -> M5 pipeline.

    M3:
        TCP stream and email analysis.

    M4:
        TLS and certificate analysis.

    M5:
        Feature extraction, ML prediction and risk engine.
    """

    logger.info(
        "Starting M3 -> M4 -> M5 pipeline: %s",
        pcap_path,
    )

    try:

        pipeline_result = run_full_pipeline(
            pcap_path
        )

    except Exception as exc:

        logger.exception(
            "M3 -> M4 -> M5 pipeline failed."
        )

        raise RuntimeError(
            f"M3-M5 pipeline failed: {exc}"
        )

    logger.info(
        "M3 -> M4 -> M5 pipeline completed."
    )

    return pipeline_result


# ============================================================
# UPLOAD PCAP
# ============================================================

@app.post("/upload-pcap")
async def upload_pcap(
    file: UploadFile = File(...),
):
    """
    Upload a PCAP and run:

        M2 -> M3 -> M4 -> M5

    MongoDB is optional.

    If MongoDB is unavailable:
        PCAP analysis still succeeds.
    """

    # --------------------------------------------------------
    # Validate filename
    # --------------------------------------------------------

    if not file.filename:

        raise HTTPException(
            status_code=400,
            detail="No filename supplied.",
        )

    original_filename = Path(
        file.filename
    ).name

    # --------------------------------------------------------
    # Validate extension
    # --------------------------------------------------------

    extension = Path(
        original_filename
    ).suffix.lower()

    allowed_extensions = {
        ".pcap",
        ".pcapng",
        ".cap",
    }

    if extension not in allowed_extensions:

        raise HTTPException(
            status_code=400,
            detail=(
                "Unsupported file type. "
                "Upload .pcap, .pcapng or .cap."
            ),
        )

    # --------------------------------------------------------
    # Generate analysis ID
    # --------------------------------------------------------

    analysis_id = str(
        uuid.uuid4()
    )

    stored_filename = (
        f"{analysis_id}_{original_filename}"
    )

    pcap_path = (
        UPLOAD_DIR / stored_filename
    )

    # --------------------------------------------------------
    # Save uploaded PCAP
    # --------------------------------------------------------

    try:

        with pcap_path.open("wb") as destination:

            while True:

                chunk = await file.read(
                    1024 * 1024
                )

                if not chunk:
                    break

                destination.write(chunk)

    except Exception as exc:

        logger.exception(
            "PCAP upload failed."
        )

        raise HTTPException(
            status_code=500,
            detail=f"PCAP upload failed: {exc}",
        )

    finally:

        await file.close()

    logger.info(
        "PCAP uploaded: %s",
        pcap_path,
    )

    # ========================================================
    # M2
    # ========================================================

    try:

        parser_result = run_m2_parser(
            pcap_path
        )

    except Exception as exc:

        logger.exception(
            "M2 analysis failed."
        )

        raise HTTPException(
            status_code=500,
            detail=f"M2 PCAP analysis failed: {exc}",
        )

    # --------------------------------------------------------
    # Extract M2 summary
    # --------------------------------------------------------

    m2_summary = extract_m2_summary(
        parser_result["stdout"]
    )

    logger.info(
        "M2 summary: %s",
        m2_summary,
    )

    # ========================================================
    # M3 -> M4 -> M5
    # ========================================================

    try:

        pipeline_result = run_m3_m4_m5(
            pcap_path
        )

    except Exception as exc:

        logger.exception(
            "M3-M5 analysis failed."
        )

        raise HTTPException(
            status_code=500,
            detail=(
                "M2 analysis succeeded, but "
                f"M3-M5 pipeline failed: {exc}"
            ),
        )

    # ========================================================
    # BUILD COMPLETE ANALYSIS
    # ========================================================

    analysis = {
        "analysis_id": analysis_id,

        "filename": original_filename,

        "stored_filename": stored_filename,

        "file_path": str(pcap_path),

        "pipeline": "M2 -> M3 -> M4 -> M5",

        "status": "completed",

        "created_at": datetime.now(
            timezone.utc
        ).isoformat(),

        # ----------------------------------------------------
        # M2
        # ----------------------------------------------------

        "m2": {
            "module": "M2",
            "summary": m2_summary,
            "parser": {
                "exit_code": parser_result[
                    "exit_code"
                ],
                "stdout": parser_result[
                    "stdout"
                ],
                "stderr": parser_result[
                    "stderr"
                ],
            },
        },

        # ----------------------------------------------------
        # M3
        # ----------------------------------------------------

        "m3": pipeline_result.get(
            "m3",
            {},
        ),

        # ----------------------------------------------------
        # M4
        # ----------------------------------------------------

        "m4": pipeline_result.get(
            "m4",
            {},
        ),

        # ----------------------------------------------------
        # M5
        # ----------------------------------------------------

        "m5": pipeline_result.get(
            "m5",
            {},
        ),

        "mongodb_saved": False,
    }

    # ========================================================
    # SAVE TO MONGODB
    # ========================================================

    try:

        mongodb_saved = save_analysis(
            analysis
        )

    except Exception as exc:

        logger.exception(
            "Unexpected MongoDB error."
        )

        mongodb_saved = False

    analysis["mongodb_saved"] = (
        mongodb_saved
    )

    # ========================================================
    # RESPONSE
    # ========================================================

    return {
        "analysis_id": analysis_id,

        "status": "completed",

        "pipeline": "M2 -> M3 -> M4 -> M5",

        "filename": original_filename,

        "mongodb_saved": mongodb_saved,

        "m2": {
            "summary": m2_summary,
        },

        "m3": {
            "streams_analyzed": (
                pipeline_result
                .get("m3", {})
                .get("streams_analyzed", 0)
            ),
        },

        "m4": {
            "streams_analyzed": (
                pipeline_result
                .get("m4", {})
                .get("streams_analyzed", 0)
            ),
        },

        "m5": {
            "streams_analyzed": (
                pipeline_result
                .get("m5", {})
                .get("streams_analyzed", 0)
            ),
        },

        "message": (
            "PCAP analyzed successfully."
            if mongodb_saved
            else
            "PCAP analyzed successfully, "
            "but MongoDB was unavailable. "
            "Result was not persisted."
        ),
    }


# ============================================================
# GET ANALYSIS
# ============================================================

@app.get("/results/{analysis_id}")
def get_results(
    analysis_id: str,
):
    """
    Retrieve a complete M2-M5 analysis from MongoDB.
    """

    analysis = get_analysis(
        analysis_id
    )

    if analysis is None:

        raise HTTPException(
            status_code=404,
            detail=(
                "Analysis not found in MongoDB. "
                "MongoDB may be unavailable or "
                "the analysis was not persisted."
            ),
        )

    return analysis


# ============================================================
# JSON REPORT
# ============================================================

@app.get("/report/{analysis_id}/json")
def json_report(
    analysis_id: str,
):
    """
    Return the complete M2-M5 analysis as JSON.
    """

    analysis = get_analysis(
        analysis_id
    )

    if analysis is None:

        raise HTTPException(
            status_code=404,
            detail="Analysis not found.",
        )

    return analysis


# ============================================================
# HTML REPORT
# ============================================================

@app.get("/report/{analysis_id}/html")
def html_report(
    analysis_id: str,
):
    """
    Generate a basic M2-M5 HTML report.
    """

    analysis = get_analysis(
        analysis_id
    )

    if analysis is None:

        raise HTTPException(
            status_code=404,
            detail="Analysis not found.",
        )

    m2 = analysis.get(
        "m2",
        {},
    )

    summary = m2.get(
        "summary",
        {},
    )

    m3 = analysis.get(
        "m3",
        {},
    )

    m4 = analysis.get(
        "m4",
        {},
    )

    m5 = analysis.get(
        "m5",
        {},
    )

    html = f"""
<!DOCTYPE html>

<html>

<head>

<meta charset="UTF-8">

<title>
SecureMailScope M2-M5 Report
</title>

<style>

body {{
    font-family: Arial, sans-serif;
    margin: 40px;
}}

h1 {{
    margin-bottom: 5px;
}}

table {{
    border-collapse: collapse;
    width: 700px;
    max-width: 100%;
    margin-bottom: 30px;
}}

th,
td {{
    border: 1px solid #ccc;
    padding: 10px;
    text-align: left;
}}

th {{
    background: #f2f2f2;
}}

pre {{
    background: #f5f5f5;
    padding: 15px;
    overflow-x: auto;
}}

</style>

</head>

<body>

<h1>
SecureMailScope M2-M5 Report
</h1>

<p>
<strong>Analysis ID:</strong>
{analysis.get("analysis_id")}
</p>

<p>
<strong>Filename:</strong>
{analysis.get("filename")}
</p>

<p>
<strong>Status:</strong>
{analysis.get("status")}
</p>

<p>
<strong>Pipeline:</strong>
M2 → M3 → M4 → M5
</p>


<h2>
M2 — PCAP Analysis
</h2>

<table>

<tr>
<th>Metric</th>
<th>Value</th>
</tr>

<tr>
<td>Total Packets</td>
<td>{summary.get("total_packets")}</td>
</tr>

<tr>
<td>SMTP Packets</td>
<td>{summary.get("smtp_packets")}</td>
</tr>

<tr>
<td>IMAP Packets</td>
<td>{summary.get("imap_packets")}</td>
</tr>

<tr>
<td>POP3 Packets</td>
<td>{summary.get("pop3_packets")}</td>
</tr>

<tr>
<td>Unknown Packets</td>
<td>{summary.get("unknown_packets")}</td>
</tr>

<tr>
<td>Skipped Packets</td>
<td>{summary.get("skipped_packets")}</td>
</tr>

</table>


<h2>
M3 — Stream Analysis
</h2>

<p>
<strong>Streams analyzed:</strong>
{m3.get("streams_analyzed", 0)}
</p>


<h2>
M4 — TLS / Certificate Analysis
</h2>

<p>
<strong>Streams analyzed:</strong>
{m4.get("streams_analyzed", 0)}
</p>


<h2>
M5 — AI/ML Risk Analysis
</h2>

<p>
<strong>Streams analyzed:</strong>
{m5.get("streams_analyzed", 0)}
</p>


<h2>
M2 Parser Output
</h2>

<pre>{m2.get("parser", {}).get("stdout", "")}</pre>


<h2>
M3 Output
</h2>

<pre>{m3}</pre>


<h2>
M4 Output
</h2>

<pre>{m4}</pre>


<h2>
M5 Output
</h2>

<pre>{m5}</pre>


</body>

</html>
"""

    return HTMLResponse(
        content=html
    )