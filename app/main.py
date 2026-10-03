from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse

from app.database import analyses_collection, check_connection
from app.analysis.m2_parser.parser import parse_pcap


app = FastAPI(
    title="SecureMailScope M6 API",
    version="0.4.0",
    description="SecureMailScope integration API with M2 PCAP parsing and MongoDB storage.",
)


# ============================================================
# CONFIGURATION
# ============================================================

UPLOAD_DIR = Path("uploads")
UPLOAD_DIR.mkdir(exist_ok=True)


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def build_m2_data(m2_summary):
    """
    Convert the M2 ProtocolSummary object into a normal
    Python dictionary that can safely be stored in MongoDB.
    """

    return {
        "total_packets": getattr(m2_summary, "total_packets", 0),
        "smtp_packets": getattr(m2_summary, "smtp_packets", 0),
        "imap_packets": getattr(m2_summary, "imap_packets", 0),
        "pop3_packets": getattr(m2_summary, "pop3_packets", 0),
        "unknown_packets": getattr(m2_summary, "unknown_packets", 0),
        "skipped_packets": getattr(m2_summary, "skipped_packets", 0),
    }


def detect_protocols(m2_data):
    """
    Convert M2 protocol counts into a simple list.
    """

    protocols = []

    if m2_data["smtp_packets"] > 0:
        protocols.append("SMTP")

    if m2_data["imap_packets"] > 0:
        protocols.append("IMAP")

    if m2_data["pop3_packets"] > 0:
        protocols.append("POP3")

    if not protocols:
        protocols.append("UNKNOWN")

    return protocols


def create_analysis_result(
    analysis_id: str,
    filename: str,
    packets,
    m2_summary,
):
    """
    Build the M6 analysis document.

    M2 is real.
    M3/M4/M5 fields are currently placeholders and will
    be replaced/enriched when those modules are integrated.
    """

    m2_data = build_m2_data(m2_summary)

    protocols_detected = detect_protocols(m2_data)

    packet_count = len(packets)

    return {
        # ----------------------------------------------------
        # Basic analysis information
        # ----------------------------------------------------

        "analysis_id": analysis_id,
        "filename": filename,
        "status": "completed",
        "created_at": datetime.now(timezone.utc).isoformat(),

        # ----------------------------------------------------
        # M2 - PCAP Parser + Protocol Identification
        # ----------------------------------------------------

        "m2": {
            "status": "completed",
            "packet_count": packet_count,
            "summary": m2_data,
            "protocols_detected": protocols_detected,
        },

        # ----------------------------------------------------
        # M3 - Session / Mail Analysis
        # Placeholder until M3 is integrated
        # ----------------------------------------------------

        "m3": {
            "status": "pending",
            "message": "M3 module not integrated yet.",
        },

        # ----------------------------------------------------
        # M4 - TLS / Certificate Analysis
        # Placeholder until M4 is integrated
        # ----------------------------------------------------

        "m4": {
            "status": "pending",
            "message": "M4 module not integrated yet.",
        },

        # ----------------------------------------------------
        # M5 - Risk Engine
        # Placeholder until M5 is integrated
        # ----------------------------------------------------

        "m5": {
            "status": "pending",
            "message": "M5 risk engine not integrated yet.",
        },

        # ----------------------------------------------------
        # M6 - Current integration summary
        # ----------------------------------------------------

        "summary": {
            "security_score": 82,
            "risk_level": "MEDIUM",
            "protocols_detected": protocols_detected,
            "total_sessions": 0,
            "total_findings": 1,
        },

        # ----------------------------------------------------
        # Temporary finding
        # ----------------------------------------------------

        "findings": [
            {
                "finding_id": "F-001",
                "title": "TLS analysis not yet integrated",
                "severity": "MEDIUM",
                "protocol": (
                    protocols_detected[0]
                    if protocols_detected
                    else "UNKNOWN"
                ),
                "description": (
                    "M2 PCAP parsing is completed, but TLS and "
                    "certificate analysis from M4 has not yet "
                    "been connected to the M6 pipeline."
                ),
                "recommendation": (
                    "Integrate the M4 TLS and certificate analysis "
                    "results into the M6 analysis document."
                ),
                "source": "M6-integration",
            }
        ],

        # ----------------------------------------------------
        # Recommendations
        # ----------------------------------------------------

        "recommendations": [
            "M2 PCAP parsing and protocol identification completed.",
            "Integrate M3 session and mail-content analysis.",
            "Integrate M4 TLS and certificate analysis.",
            "Integrate M5 risk scoring and recommendation engine.",
        ],
    }


# ============================================================
# ROOT
# ============================================================

@app.get("/")
def root():
    return {
        "service": "SecureMailScope M6 API",
        "version": "0.4.0",
        "status": "running",
        "docs": "/docs",
    }


# ============================================================
# UPLOAD PCAP
# ============================================================

@app.post("/upload-pcap")
async def upload_pcap(file: UploadFile = File(...)):

    # --------------------------------------------------------
    # Validate filename
    # --------------------------------------------------------

    if not file.filename:
        raise HTTPException(
            status_code=400,
            detail="Filename is missing.",
        )

    safe_filename = Path(file.filename).name

    # --------------------------------------------------------
    # Validate extension
    # --------------------------------------------------------

    allowed_extensions = (
        ".pcap",
        ".pcapng",
        ".cap",
    )

    if not safe_filename.lower().endswith(allowed_extensions):
        raise HTTPException(
            status_code=400,
            detail="Upload a .pcap, .pcapng, or .cap file.",
        )

    # --------------------------------------------------------
    # Generate analysis ID
    # --------------------------------------------------------

    analysis_id = str(uuid4())

    destination = (
        UPLOAD_DIR
        / f"{analysis_id}_{safe_filename}"
    )

    # --------------------------------------------------------
    # Save uploaded file
    # --------------------------------------------------------

    try:
        file_content = await file.read()
        destination.write_bytes(file_content)

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Could not save uploaded PCAP: {exc}",
        )

    # --------------------------------------------------------
    # M2 PCAP PARSER
    # --------------------------------------------------------

    try:
        packets, m2_summary = parse_pcap(
            str(destination)
        )

    except Exception as exc:
        # Keep the uploaded file for debugging.
        raise HTTPException(
            status_code=500,
            detail=f"M2 PCAP analysis failed: {exc}",
        )

    # --------------------------------------------------------
    # Build integrated M6 result
    # --------------------------------------------------------

    result = create_analysis_result(
        analysis_id=analysis_id,
        filename=safe_filename,
        packets=packets,
        m2_summary=m2_summary,
    )

    # --------------------------------------------------------
    # Save result in MongoDB
    # --------------------------------------------------------

    try:
        analyses_collection.insert_one(result)

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"MongoDB save failed: {exc}",
        )

    # --------------------------------------------------------
    # Return response
    # --------------------------------------------------------

    return {
        "analysis_id": analysis_id,
        "filename": safe_filename,
        "status": "completed",
        "message": "PCAP uploaded, M2 analysis completed, and result saved to MongoDB.",
        "m2": {
            "packet_count": len(packets),
            "summary": build_m2_data(m2_summary),
            "protocols_detected": detect_protocols(
                build_m2_data(m2_summary)
            ),
        },
    }


# ============================================================
# LIST ALL ANALYSES
# ============================================================

@app.get("/analyses")
def list_analyses():

    analyses = list(
        analyses_collection.find(
            {},
            {"_id": 0},
        ).sort(
            "created_at",
            -1,
        )
    )

    return {
        "total": len(analyses),
        "analyses": analyses,
    }


# ============================================================
# GET ONE ANALYSIS
# ============================================================

@app.get("/results/{analysis_id}")
def get_results(analysis_id: str):

    result = analyses_collection.find_one(
        {
            "analysis_id": analysis_id
        },
        {
            "_id": 0
        },
    )

    if result is None:
        raise HTTPException(
            status_code=404,
            detail="Analysis not found.",
        )

    return result


# ============================================================
# DELETE ANALYSIS
# ============================================================

@app.delete("/analyses/{analysis_id}")
def delete_analysis(analysis_id: str):

    result = analyses_collection.delete_one(
        {
            "analysis_id": analysis_id
        }
    )

    if result.deleted_count == 0:
        raise HTTPException(
            status_code=404,
            detail="Analysis not found.",
        )

    return {
        "analysis_id": analysis_id,
        "status": "deleted",
        "message": "Analysis deleted successfully.",
    }


# ============================================================
# JSON REPORT
# ============================================================

@app.get("/report/{analysis_id}/json")
def get_json_report(analysis_id: str):

    result = analyses_collection.find_one(
        {
            "analysis_id": analysis_id
        },
        {
            "_id": 0
        },
    )

    if result is None:
        raise HTTPException(
            status_code=404,
            detail="Analysis not found.",
        )

    return JSONResponse(
        content=result
    )


# ============================================================
# HTML REPORT
# ============================================================

@app.get(
    "/report/{analysis_id}/html",
    response_class=HTMLResponse,
)
def get_html_report(analysis_id: str):

    result = analyses_collection.find_one(
        {
            "analysis_id": analysis_id
        },
        {
            "_id": 0
        },
    )

    if result is None:
        raise HTTPException(
            status_code=404,
            detail="Analysis not found.",
        )

    summary = result.get(
        "summary",
        {}
    )

    protocols = ", ".join(
        summary.get(
            "protocols_detected",
            []
        )
    )

    m2 = result.get(
        "m2",
        {}
    )

    m2_summary = m2.get(
        "summary",
        {}
    )

    # --------------------------------------------------------
    # Findings HTML
    # --------------------------------------------------------

    findings_html = ""

    for finding in result.get(
        "findings",
        []
    ):

        findings_html += f"""
        <li>
            <b>Finding ID:</b>
            {finding.get("finding_id", "N/A")}
            <br>

            <b>Severity:</b>
            {finding.get("severity", "N/A")}
            <br>

            <b>Title:</b>
            {finding.get("title", "N/A")}
            <br>

            <b>Protocol:</b>
            {finding.get("protocol", "N/A")}
            <br>

            <b>Description:</b>
            {finding.get("description", "N/A")}
            <br>

            <b>Recommendation:</b>
            {finding.get("recommendation", "N/A")}
        </li>

        <br>
        """

    # --------------------------------------------------------
    # Recommendations HTML
    # --------------------------------------------------------

    recommendations_html = ""

    for recommendation in result.get(
        "recommendations",
        []
    ):

        recommendations_html += (
            f"<li>{recommendation}</li>"
        )

    # --------------------------------------------------------
    # HTML
    # --------------------------------------------------------

    html_report = f"""
    <!DOCTYPE html>

    <html lang="en">

    <head>

        <meta charset="UTF-8">

        <meta
            name="viewport"
            content="width=device-width, initial-scale=1.0"
        >

        <title>
            SecureMailScope Security Report
        </title>

        <style>

            body {{
                font-family: Arial, sans-serif;
                margin: 40px;
                line-height: 1.6;
                background-color: #f4f6f8;
                color: #222;
            }}

            .container {{
                max-width: 1000px;
                margin: auto;
                background: white;
                padding: 30px;
                border-radius: 10px;
                box-shadow:
                    0 2px 10px
                    rgba(0, 0, 0, 0.1);
            }}

            .score {{
                font-size: 36px;
                font-weight: bold;
            }}

            .risk {{
                font-size: 22px;
                font-weight: bold;
            }}

            .section {{
                margin-top: 30px;
            }}

            .m2-box {{
                background: #eef4ff;
                padding: 20px;
                border-radius: 8px;
            }}

            .module {{
                padding: 12px;
                margin: 8px 0;
                background: #f5f5f5;
                border-radius: 6px;
            }}

            li {{
                margin-bottom: 15px;
            }}

        </style>

    </head>

    <body>

        <div class="container">

            <h1>
                SecureMailScope Security Report
            </h1>

            <p>
                <b>Analysis ID:</b>
                {result.get("analysis_id", "N/A")}
            </p>

            <p>
                <b>Filename:</b>
                {result.get("filename", "N/A")}
            </p>

            <p>
                <b>Status:</b>
                {result.get("status", "N/A")}
            </p>

            <p>
                <b>Created At:</b>
                {result.get("created_at", "N/A")}
            </p>

            <div class="section">

                <h2>
                    M2 PCAP Analysis
                </h2>

                <div class="m2-box">

                    <p>
                        <b>Total Packets:</b>
                        {m2_summary.get("total_packets", 0)}
                    </p>

                    <p>
                        <b>Packets Parsed:</b>
                        {m2.get("packet_count", 0)}
                    </p>

                    <p>
                        <b>SMTP Packets:</b>
                        {m2_summary.get("smtp_packets", 0)}
                    </p>

                    <p>
                        <b>IMAP Packets:</b>
                        {m2_summary.get("imap_packets", 0)}
                    </p>

                    <p>
                        <b>POP3 Packets:</b>
                        {m2_summary.get("pop3_packets", 0)}
                    </p>

                    <p>
                        <b>Unknown Packets:</b>
                        {m2_summary.get("unknown_packets", 0)}
                    </p>

                    <p>
                        <b>Skipped Packets:</b>
                        {m2_summary.get("skipped_packets", 0)}
                    </p>

                    <p>
                        <b>Protocols Detected:</b>
                        {", ".join(
                            m2.get(
                                "protocols_detected",
                                []
                            )
                        )}
                    </p>

                </div>

            </div>

            <div class="section">

                <h2>
                    Overall Security Summary
                </h2>

                <p class="score">
                    Security Score:
                    {summary.get("security_score", 0)}/100
                </p>

                <p class="risk">
                    Risk Level:
                    {summary.get("risk_level", "UNKNOWN")}
                </p>

                <p>
                    <b>Detected Protocols:</b>
                    {protocols}
                </p>

                <p>
                    <b>Total Sessions:</b>
                    {summary.get("total_sessions", 0)}
                </p>

                <p>
                    <b>Total Findings:</b>
                    {summary.get("total_findings", 0)}
                </p>

            </div>

            <div class="section">

                <h2>
                    Module Status
                </h2>

                <div class="module">
                    <b>M2:</b>
                    {result.get("m2", {}).get("status", "unknown")}
                </div>

                <div class="module">
                    <b>M3:</b>
                    {result.get("m3", {}).get("status", "unknown")}
                </div>

                <div class="module">
                    <b>M4:</b>
                    {result.get("m4", {}).get("status", "unknown")}
                </div>

                <div class="module">
                    <b>M5:</b>
                    {result.get("m5", {}).get("status", "unknown")}
                </div>

            </div>

            <div class="section">

                <h2>
                    Security Findings
                </h2>

                <ul>
                    {findings_html}
                </ul>

            </div>

            <div class="section">

                <h2>
                    Recommendations
                </h2>

                <ul>
                    {recommendations_html}
                </ul>

            </div>

        </div>

    </body>

    </html>
    """

    return HTMLResponse(
        content=html_report
    )


# ============================================================
# HEALTH CHECK
# ============================================================

@app.get("/health")
def health_check():

    try:

        check_connection()

        return {
            "status": "healthy",
            "database": "connected",
        }

    except Exception:

        return {
            "status": "unhealthy",
            "database": "disconnected",
        }