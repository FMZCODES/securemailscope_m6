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
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles

from app.database import (
    check_connection,
    get_analysis,
    save_analysis,
)

from app.analysis.pipeline import run_full_pipeline


# ============================================================
# LOGGING
# ============================================================

logging.basicConfig(level=logging.INFO)

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

FRONTEND_DIR = BASE_DIR / "frontend" / "dist"
FRONTEND_INDEX = FRONTEND_DIR / "index.html"


# ============================================================
# FASTAPI
# ============================================================

app = FastAPI(
    title="SecureMailScope M6 API",
    version="0.4.0",
    description=(
        "SecureMailScope M6 API - "
        "M2 PCAP parsing + M3 stream analysis + "
        "M4 TLS/certificate analysis + "
        "M5 AI/ML risk analysis."
    ),
)


# ============================================================
# IN-MEMORY FALLBACK STORAGE
# ============================================================
#
# This is important.
#
# If MongoDB temporarily fails, the dashboard can STILL receive
# the analysis result from this process.
#
# MongoDB remains the persistent database when available.
#

ANALYSIS_CACHE: dict[str, dict[str, Any]] = {}


# ============================================================
# CORS
# ============================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",

        # Render production frontend/backend
        "https://securemailscope-m6-2.onrender.com",
        "https://securemailscope-m6-4.onrender.com",
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
    """
    Serve the React production frontend if it exists.
    Otherwise return API information.
    """

    if FRONTEND_INDEX.exists():
        return FileResponse(FRONTEND_INDEX)

    return {
        "project": "SecureMailScope M6",
        "status": "running",
        "version": "0.4.0",
        "pipeline": "M2 -> M3 -> M4 -> M5",
        "docs": "/docs",
    }


# ============================================================
# HEALTH
# ============================================================

@app.get("/health")
def health():
    """
    API and MongoDB health status.
    """

    try:
        mongo_ok = check_connection()
    except Exception as exc:
        logger.error(
            "MongoDB health check failed: %s",
            exc,
        )
        mongo_ok = False

    return {
        "status": "healthy",
        "database": (
            "connected"
            if mongo_ok
            else "unavailable"
        ),
        "pipeline": "M2 -> M3 -> M4 -> M5",
        "cached_results": len(ANALYSIS_CACHE),
    }


# ============================================================
# M2 PARSER
# ============================================================

def run_m2_parser(
    pcap_path: Path,
) -> dict[str, Any]:
    """
    Run M2 in a separate Python process.

    This avoids PyShark/TShark event-loop conflicts
    with FastAPI/Uvicorn.
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

def extract_m2_summary(
    output: str,
) -> dict[str, Any]:
    """
    Extract ProtocolSummary values from M2 output.
    """

    summary = {
        "total_packets": 0,
        "smtp_packets": 0,
        "imap_packets": 0,
        "pop3_packets": 0,
        "unknown_packets": 0,
        "skipped_packets": 0,
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

        position = summary_text.find(
            marker
        )

        if position == -1:
            continue

        value_start = (
            position + len(marker)
        )

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
# SAFE INTEGER
# ============================================================

def safe_int(
    value: Any,
    default: int = 0,
) -> int:

    try:
        return int(value)

    except Exception:
        return default


# ============================================================
# BUILD DASHBOARD DATA
# ============================================================

def build_dashboard_data(
    analysis: dict[str, Any],
) -> dict[str, Any]:
    """
    Convert the raw M2-M5 pipeline output into a structure
    that the React dashboard can consume directly.
    """

    m2 = analysis.get(
        "m2",
        {},
    )

    m2_summary = m2.get(
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

    # --------------------------------------------------------
    # M5 RESULTS
    # --------------------------------------------------------

    m5_results = m5.get(
        "results",
        [],
    )

    if not isinstance(
        m5_results,
        list,
    ):
        m5_results = []

    # --------------------------------------------------------
    # M4 RESULTS
    # --------------------------------------------------------

    m4_results = m4.get(
        "results",
        [],
    )

    if not isinstance(
        m4_results,
        list,
    ):
        m4_results = []

    # --------------------------------------------------------
    # FINDINGS
    # --------------------------------------------------------

    findings: list[dict[str, Any]] = []

    for item in m5_results:

        if not isinstance(
            item,
            dict,
        ):
            continue

        item_findings = item.get(
            "findings",
            [],
        )

        if isinstance(
            item_findings,
            list,
        ):
            for finding in item_findings:

                if isinstance(
                    finding,
                    dict,
                ):
                    finding_copy = dict(
                        finding
                    )

                    finding_copy.setdefault(
                        "stream_id",
                        item.get(
                            "stream_id"
                        ),
                    )

                    finding_copy.setdefault(
                        "protocol",
                        item.get(
                            "protocol"
                        ),
                    )

                    findings.append(
                        finding_copy
                    )

    # --------------------------------------------------------
    # ALSO CHECK M4 FINDINGS
    # --------------------------------------------------------

    for item in m4_results:

        if not isinstance(
            item,
            dict,
        ):
            continue

        item_findings = item.get(
            "findings",
            [],
        )

        if isinstance(
            item_findings,
            list,
        ):
            for finding in item_findings:

                if not isinstance(
                    finding,
                    dict,
                ):
                    continue

                # Avoid duplicates
                if finding not in findings:
                    finding_copy = dict(
                        finding
                    )

                    finding_copy.setdefault(
                        "stream_id",
                        item.get(
                            "stream_id"
                        ),
                    )

                    finding_copy.setdefault(
                        "protocol",
                        item.get(
                            "protocol"
                        ),
                    )

                    findings.append(
                        finding_copy
                    )

    # --------------------------------------------------------
    # RISK SCORES
    # --------------------------------------------------------

    risk_scores: list[int] = []

    risk_levels: list[str] = []

    for item in m5_results:

        if not isinstance(
            item,
            dict,
        ):
            continue

        risk = item.get(
            "risk",
            {},
        )

        if not isinstance(
            risk,
            dict,
        ):
            continue

        score = safe_int(
            risk.get(
                "score",
                0,
            )
        )

        score = max(
            0,
            min(
                100,
                score,
            ),
        )

        risk_scores.append(
            score
        )

        level = risk.get(
            "risk_level"
        )

        if level:
            risk_levels.append(
                str(level).upper()
            )

    # --------------------------------------------------------
    # SECURITY SCORE
    # --------------------------------------------------------
    #
    # M5 risk score:
    #   0 = LOW risk
    #   higher = more risk
    #
    # Dashboard score:
    #   100 = best
    #   0 = worst
    #
    # If M5 returns scores, convert risk -> security score.
    #

    if risk_scores:
        max_risk = max(
            risk_scores
        )

        average_risk = sum(
            risk_scores
        ) / len(
            risk_scores
        )

        combined_risk = max(
            max_risk,
            round(average_risk),
        )

        security_score = max(
            0,
            min(
                100,
                100 - combined_risk,
            ),
        )

    else:
        # If no M5 risk score exists yet,
        # do not pretend the security score is 0.
        security_score = None

    # --------------------------------------------------------
    # RISK LEVEL
    # --------------------------------------------------------

    if risk_levels:

        priority = {
            "CRITICAL": 4,
            "HIGH": 3,
            "MEDIUM": 2,
            "LOW": 1,
        }

        risk_level = max(
            risk_levels,
            key=lambda x: priority.get(
                x,
                0,
            ),
        )

    else:

        if security_score is None:
            risk_level = "UNKNOWN"

        elif security_score >= 80:
            risk_level = "LOW"

        elif security_score >= 60:
            risk_level = "MEDIUM"

        elif security_score >= 40:
            risk_level = "HIGH"

        else:
            risk_level = "CRITICAL"

    # --------------------------------------------------------
    # PROTOCOLS
    # --------------------------------------------------------

    protocols: set[str] = set()

    for item in m3.get(
        "results",
        [],
    ) if isinstance(
        m3.get("results", []),
        list,
    ) else []:

        if isinstance(
            item,
            dict,
        ):

            protocol = item.get(
                "protocol"
            )

            if protocol:
                protocols.add(
                    str(protocol).upper()
                )

    for item in m4_results:

        if isinstance(
            item,
            dict,
        ):

            protocol = item.get(
                "protocol"
            )

            if protocol:
                protocols.add(
                    str(protocol).upper()
                )

    for item in m5_results:

        if isinstance(
            item,
            dict,
        ):

            protocol = item.get(
                "protocol"
            )

            if protocol:
                protocols.add(
                    str(protocol).upper()
                )

    # Also use M2 counts
    if safe_int(
        m2_summary.get(
            "smtp_packets",
            0,
        )
    ) > 0:
        protocols.add("SMTP")

    if safe_int(
        m2_summary.get(
            "imap_packets",
            0,
        )
    ) > 0:
        protocols.add("IMAP")

    if safe_int(
        m2_summary.get(
            "pop3_packets",
            0,
        )
    ) > 0:
        protocols.add("POP3")

    protocols_detected = sorted(
        protocols
    )

    # --------------------------------------------------------
    # TLS INFORMATION
    # --------------------------------------------------------

    tls_versions: list[str] = []
    cipher_suites: list[str] = []
    key_exchanges: list[str] = []

    starttls_detected = False
    forward_secrecy_values: list[bool] = []

    for item in m4_results:

        if not isinstance(
            item,
            dict,
        ):
            continue

        if item.get(
            "starttls_detected"
        ):
            starttls_detected = True

        tls = item.get(
            "tls",
            {},
        )

        if not isinstance(
            tls,
            dict,
        ):
            tls = {}

        tls_version = tls.get(
            "tls_version"
        )

        if tls_version:
            tls_versions.append(
                str(tls_version)
            )

        cipher = tls.get(
            "cipher_suite"
        )

        if cipher:
            cipher_suites.append(
                str(cipher)
            )

        key_exchange = tls.get(
            "key_exchange"
        )

        if key_exchange:
            key_exchanges.append(
                str(key_exchange)
            )

        forward_secrecy = tls.get(
            "forward_secrecy"
        )

        if isinstance(
            forward_secrecy,
            bool,
        ):
            forward_secrecy_values.append(
                forward_secrecy
            )

    # --------------------------------------------------------
    # REMOVE DUPLICATES
    # --------------------------------------------------------

    tls_versions = list(
        dict.fromkeys(
            tls_versions
        )
    )

    cipher_suites = list(
        dict.fromkeys(
            cipher_suites
        )
    )

    key_exchanges = list(
        dict.fromkeys(
            key_exchanges
        )
    )

    # --------------------------------------------------------
    # DASHBOARD TLS VALUES
    # --------------------------------------------------------

    tls_version_value = (
        ", ".join(
            tls_versions
        )
        if tls_versions
        else "Not observed"
    )

    cipher_value = (
        ", ".join(
            cipher_suites
        )
        if cipher_suites
        else "Not observed"
    )

    key_exchange_value = (
        ", ".join(
            key_exchanges
        )
        if key_exchanges
        else "Not observed"
    )

    if forward_secrecy_values:

        forward_secrecy_value = (
            "Yes"
            if all(
                forward_secrecy_values
            )
            else "No"
        )

    else:

        forward_secrecy_value = (
            "Not observed"
        )

    # --------------------------------------------------------
    # DASHBOARD OBJECT
    # --------------------------------------------------------

    dashboard = {
        "security_score": security_score,
        "risk_level": risk_level,
        "protocols_detected": protocols_detected,
        "total_sessions": max(
            safe_int(
                m3.get(
                    "streams_analyzed",
                    0,
                )
            ),
            safe_int(
                m4.get(
                    "streams_analyzed",
                    0,
                )
            ),
            safe_int(
                m5.get(
                    "streams_analyzed",
                    0,
                )
            ),
        ),
        "total_findings": len(
            findings
        ),
        "email_protocols": (
            ", ".join(
                protocols_detected
            )
            if protocols_detected
            else "Not observed"
        ),
        "starttls": (
            "Detected"
            if starttls_detected
            else "Not detected"
        ),
        "starttls_detected": starttls_detected,
        "tls_version": tls_version_value,
        "cipher_suite": cipher_value,
        "key_exchange": key_exchange_value,
        "forward_secrecy": forward_secrecy_value,
        "findings": findings,
    }

    return dashboard


# ============================================================
# BUILD COMPLETE ANALYSIS
# ============================================================

def build_complete_analysis(
    analysis_id: str,
    filename: str,
    stored_filename: str,
    pcap_path: Path,
    m2_summary: dict[str, Any],
    parser_result: dict[str, Any],
    pipeline_result: dict[str, Any],
) -> dict[str, Any]:

    analysis = {
        "analysis_id": analysis_id,
        "filename": filename,
        "stored_filename": stored_filename,
        "file_path": str(pcap_path),
        "pipeline": "M2 -> M3 -> M4 -> M5",
        "status": "completed",
        "created_at": datetime.now(
            timezone.utc
        ).isoformat(),

        "m2": {
            "module": "M2",
            "summary": m2_summary,
            "parser": {
                "exit_code": parser_result.get(
                    "exit_code"
                ),
                "stdout": parser_result.get(
                    "stdout",
                    "",
                ),
                "stderr": parser_result.get(
                    "stderr",
                    "",
                ),
            },
        },

        "m3": pipeline_result.get(
            "m3",
            {},
        ),

        "m4": pipeline_result.get(
            "m4",
            {},
        ),

        "m5": pipeline_result.get(
            "m5",
            {},
        ),

        "mongodb_saved": False,
    }

    # --------------------------------------------------------
    # Build dashboard representation
    # --------------------------------------------------------

    analysis["dashboard"] = (
        build_dashboard_data(
            analysis
        )
    )

    # --------------------------------------------------------
    # Compatibility summary
    # --------------------------------------------------------

    dashboard = analysis[
        "dashboard"
    ]

    analysis["summary"] = {
        "security_score": dashboard.get(
            "security_score"
        ),
        "risk_level": dashboard.get(
            "risk_level"
        ),
        "protocols_detected": dashboard.get(
            "protocols_detected",
            [],
        ),
        "total_sessions": dashboard.get(
            "total_sessions",
            0,
        ),
        "total_findings": dashboard.get(
            "total_findings",
            0,
        ),
    }

    return analysis


# ============================================================
# SAVE RESULT
# ============================================================

def persist_analysis(
    analysis: dict[str, Any],
) -> bool:

    # Always cache first.
    #
    # This means the dashboard can still work if MongoDB
    # is temporarily unavailable.
    #

    analysis_id = analysis.get(
        "analysis_id"
    )

    if analysis_id:
        ANALYSIS_CACHE[
            str(analysis_id)
        ] = analysis

    # Try MongoDB
    try:

        saved = save_analysis(
            analysis
        )

        return bool(saved)

    except Exception as exc:

        logger.exception(
            "MongoDB save failed: %s",
            exc,
        )

        return False


# ============================================================
# UPLOAD / ANALYZE PCAP
# ============================================================

@app.post("/upload-pcap")
@app.post("/analyze")
async def upload_pcap(
    file: UploadFile = File(...),
):

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

        with pcap_path.open(
            "wb"
        ) as destination:

            while True:

                chunk = await file.read(
                    1024 * 1024
                )

                if not chunk:
                    break

                destination.write(
                    chunk
                )

    except Exception as exc:

        logger.exception(
            "PCAP upload failed."
        )

        raise HTTPException(
            status_code=500,
            detail=(
                f"PCAP upload failed: {exc}"
            ),
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
            detail=(
                f"M2 PCAP analysis failed: {exc}"
            ),
        )

    # --------------------------------------------------------
    # M2 summary
    # --------------------------------------------------------

    m2_summary = extract_m2_summary(
        parser_result.get(
            "stdout",
            "",
        )
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
                "M2 analysis succeeded, "
                f"but M3-M5 pipeline failed: {exc}"
            ),
        )

    # ========================================================
    # BUILD COMPLETE ANALYSIS
    # ========================================================

    analysis = build_complete_analysis(
        analysis_id=analysis_id,
        filename=original_filename,
        stored_filename=stored_filename,
        pcap_path=pcap_path,
        m2_summary=m2_summary,
        parser_result=parser_result,
        pipeline_result=pipeline_result,
    )

    # ========================================================
    # SAVE
    # ========================================================

    mongodb_saved = persist_analysis(
        analysis
    )

    analysis[
        "mongodb_saved"
    ] = mongodb_saved

    # Update cache after MongoDB status
    ANALYSIS_CACHE[
        analysis_id
    ] = analysis

    # ========================================================
    # RESPONSE
    # ========================================================
    #
    # IMPORTANT:
    #
    # We return the COMPLETE analysis here.
    #
    # Previously only:
    #   analysis_id
    #   m2
    #   m3
    #   m4
    #   m5
    #
    # were returned.
    #
    # Now the frontend receives dashboard data directly.
    #

    return {
        **analysis,

        "message": (
            "PCAP analyzed successfully."
            if mongodb_saved
            else
            "PCAP analyzed successfully. "
            "MongoDB is unavailable, but the result "
            "is available from the current API session."
        ),
    }


# ============================================================
# GET ANALYSIS
# ============================================================

@app.get("/results/{analysis_id}")
def get_results(
    analysis_id: str,
):

    # --------------------------------------------------------
    # 1. Try MongoDB
    # --------------------------------------------------------

    try:

        analysis = get_analysis(
            analysis_id
        )

        if analysis is not None:

            # Make sure dashboard exists even for
            # older MongoDB records.

            if "dashboard" not in analysis:

                analysis[
                    "dashboard"
                ] = build_dashboard_data(
                    analysis
                )

            if "summary" not in analysis:

                dashboard = analysis[
                    "dashboard"
                ]

                analysis[
                    "summary"
                ] = {
                    "security_score": dashboard.get(
                        "security_score"
                    ),
                    "risk_level": dashboard.get(
                        "risk_level"
                    ),
                    "protocols_detected": dashboard.get(
                        "protocols_detected",
                        [],
                    ),
                    "total_sessions": dashboard.get(
                        "total_sessions",
                        0,
                    ),
                    "total_findings": dashboard.get(
                        "total_findings",
                        0,
                    ),
                }

            return analysis

    except Exception as exc:

        logger.error(
            "MongoDB result lookup failed: %s",
            exc,
        )

    # --------------------------------------------------------
    # 2. Fallback to memory
    # --------------------------------------------------------

    cached = ANALYSIS_CACHE.get(
        analysis_id
    )

    if cached is not None:
        return cached

    # --------------------------------------------------------
    # 3. Not found
    # --------------------------------------------------------

    raise HTTPException(
        status_code=404,
        detail=(
            "Analysis not found. "
            "It may have expired from the "
            "temporary cache and MongoDB is unavailable."
        ),
    )


# ============================================================
# LIST ANALYSES
# ============================================================

@app.get("/analyses")
def list_analyses():

    results = []

    # Try MongoDB first
    try:

        from app.database import analyses_collection

        mongo_results = list(
            analyses_collection.find(
                {},
                {
                    "_id": 0,
                },
            ).sort(
                "created_at",
                -1,
            )
        )

        results.extend(
            mongo_results
        )

    except Exception as exc:

        logger.error(
            "Could not list MongoDB analyses: %s",
            exc,
        )

    # Add cached results that aren't already there
    existing_ids = {
        item.get(
            "analysis_id"
        )
        for item in results
        if isinstance(
            item,
            dict,
        )
    }

    for analysis in ANALYSIS_CACHE.values():

        analysis_id = analysis.get(
            "analysis_id"
        )

        if analysis_id not in existing_ids:

            results.append(
                analysis
            )

    # Sort newest first
    results.sort(
        key=lambda item: item.get(
            "created_at",
            "",
        ),
        reverse=True,
    )

    return {
        "total": len(
            results
        ),
        "analyses": results,
    }


# ============================================================
# JSON REPORT
# ============================================================

@app.get(
    "/report/{analysis_id}/json"
)
def json_report(
    analysis_id: str,
):

    return get_results(
        analysis_id
    )


# ============================================================
# HTML REPORT
# ============================================================

@app.get(
    "/report/{analysis_id}/html"
)
def html_report(
    analysis_id: str,
):

    analysis = get_results(
        analysis_id
    )

    dashboard = analysis.get(
        "dashboard",
        {},
    )

    m2 = analysis.get(
        "m2",
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

    m2_summary = m2.get(
        "summary",
        {},
    )

    findings = dashboard.get(
        "findings",
        [],
    )

    findings_html = ""

    for finding in findings:

        findings_html += f"""
        <tr>
            <td>{finding.get("severity", "UNKNOWN")}</td>
            <td>{finding.get("type", "")}</td>
            <td>{finding.get("message", finding.get("description", ""))}</td>
            <td>{finding.get("recommendation", "")}</td>
        </tr>
        """

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
    line-height: 1.5;
}}

h1 {{
    margin-bottom: 5px;
}}

.card {{
    border: 1px solid #ddd;
    border-radius: 8px;
    padding: 20px;
    margin-bottom: 20px;
}}

.score {{
    font-size: 48px;
    font-weight: bold;
}}

table {{
    border-collapse: collapse;
    width: 100%;
    margin-top: 20px;
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
SecureMailScope Security Report
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

<div class="card">

<h2>
Security Score
</h2>

<div class="score">
{dashboard.get("security_score", "N/A")}/100
</div>

<p>
Risk level:
<strong>
{dashboard.get("risk_level", "UNKNOWN")}
</strong>
</p>

</div>

<div class="card">

<h2>
Protocol & TLS
</h2>

<p>
<strong>Email protocols:</strong>
{dashboard.get("email_protocols", "Not observed")}
</p>

<p>
<strong>STARTTLS:</strong>
{dashboard.get("starttls", "Not observed")}
</p>

<p>
<strong>TLS version:</strong>
{dashboard.get("tls_version", "Not observed")}
</p>

<p>
<strong>Cipher suite:</strong>
{dashboard.get("cipher_suite", "Not observed")}
</p>

<p>
<strong>Key exchange:</strong>
{dashboard.get("key_exchange", "Not observed")}
</p>

<p>
<strong>Forward secrecy:</strong>
{dashboard.get("forward_secrecy", "Not observed")}
</p>

</div>

<div class="card">

<h2>
Security Findings
</h2>

<p>
<strong>
{len(findings)}
</strong>
finding(s)
</p>

<table>

<tr>
<th>Severity</th>
<th>Type</th>
<th>Message</th>
<th>Recommendation</th>
</tr>

{findings_html}

</table>

</div>

<div class="card">

<h2>
M2 Summary
</h2>

<table>

<tr>
<th>Metric</th>
<th>Value</th>
</tr>

<tr>
<td>Total packets</td>
<td>{m2_summary.get("total_packets", 0)}</td>
</tr>

<tr>
<td>SMTP packets</td>
<td>{m2_summary.get("smtp_packets", 0)}</td>
</tr>

<tr>
<td>IMAP packets</td>
<td>{m2_summary.get("imap_packets", 0)}</td>
</tr>

<tr>
<td>POP3 packets</td>
<td>{m2_summary.get("pop3_packets", 0)}</td>
</tr>

<tr>
<td>Unknown packets</td>
<td>{m2_summary.get("unknown_packets", 0)}</td>
</tr>

<tr>
<td>Skipped packets</td>
<td>{m2_summary.get("skipped_packets", 0)}</td>
</tr>

</table>

</div>

<div class="card">

<h2>
M3
</h2>

<pre>
{m3}
</pre>

</div>

<div class="card">

<h2>
M4
</h2>

<pre>
{m4}
</pre>

</div>

<div class="card">

<h2>
M5
</h2>

<pre>
{m5}
</pre>

</div>

</body>
</html>
"""

    return HTMLResponse(
        content=html
    )


# ============================================================
# FRONTEND STATIC FILES
# ============================================================

if FRONTEND_DIR.exists():

    app.mount(
        "/assets",
        StaticFiles(
            directory=FRONTEND_DIR / "assets"
        ),
        name="assets",
    )