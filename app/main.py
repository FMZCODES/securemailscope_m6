from __future__ import annotations

import html
import json
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

from app.analysis.pipeline import run_full_pipeline
from app.database import check_connection, get_analysis, save_analysis

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("securemailscope")

BASE_DIR = Path(__file__).resolve().parent.parent
UPLOAD_DIR = BASE_DIR / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

# Temporary process cache. MongoDB is the persistent store when available.
RESULT_CACHE: dict[str, dict[str, Any]] = {}

app = FastAPI(
    title="SecureMailScope M6 API",
    version="0.4.0",
    description="M2 PCAP parsing + M3 stream analysis + M4 TLS/certificate analysis + M5 risk analysis.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_origin_regex=r"https://.*\\.onrender\\.com",
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


def dashboard_html() -> str:
    return r'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>SecureMailScope M6</title>
<style>
*{box-sizing:border-box}body{margin:0;font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#f4f7fb;color:#14213d}button,input{font:inherit}.wrap{max-width:1450px;margin:0 auto;padding:28px}.top{display:flex;justify-content:space-between;align-items:center;margin-bottom:22px}.brand{font-size:25px;font-weight:800}.sub{color:#63708a;margin-top:5px}.status{padding:9px 15px;border-radius:999px;background:#e8eef8;font-weight:700}.upload{background:#fff;border:1px solid #e1e7f0;border-radius:18px;padding:22px;box-shadow:0 5px 20px rgba(20,33,61,.05);display:flex;gap:14px;align-items:center;flex-wrap:wrap}.file{background:#eef3f9;padding:12px 16px;border-radius:10px}.btn{border:0;border-radius:10px;padding:12px 20px;background:#17243f;color:#fff;font-weight:750;cursor:pointer}.btn:disabled{opacity:.5;cursor:not-allowed}.msg{margin:16px 0;color:#5b6880}.grid2{display:grid;grid-template-columns:1fr 2fr;gap:22px;margin-top:22px}.card{background:#fff;border:1px solid #e1e7f0;border-radius:18px;padding:26px;box-shadow:0 5px 20px rgba(20,33,61,.04);margin-top:22px}.label{font-size:14px;letter-spacing:1px;text-transform:uppercase;font-weight:800;color:#64728b}.score{font-size:70px;font-weight:850;line-height:1;margin-top:20px}.score span{font-size:25px;color:#8390a7}.muted{color:#66748e;line-height:1.5}.rows{margin-top:15px}.row{display:flex;justify-content:space-between;gap:20px;padding:16px 0;border-bottom:1px solid #e7ebf2}.row:last-child{border-bottom:0}.row span{color:#5e6c85}.row strong{text-align:right;word-break:break-word}.metrics{display:grid;grid-template-columns:repeat(6,1fr);gap:12px;margin-top:18px}.metric{background:#f7f9fc;border:1px solid #e5eaf2;border-radius:12px;padding:15px}.metric small{display:block;color:#65738c;margin-bottom:7px}.metric b{font-size:22px}.table-wrap{overflow:auto;border:1px solid #e3e8f0;border-radius:12px;margin-top:15px}table{border-collapse:collapse;width:100%;min-width:750px}th,td{text-align:left;padding:13px 14px;border-bottom:1px solid #e8edf3;white-space:nowrap}th{background:#f7f9fc;color:#596780;font-size:13px;text-transform:uppercase;letter-spacing:.4px}pre{background:#101827;color:#e7edf7;border-radius:12px;padding:18px;overflow:auto;max-height:600px;font-size:12px;line-height:1.5}.actions{display:flex;gap:10px;flex-wrap:wrap;margin-top:18px}.hidden{display:none}.finding{border:1px solid #e5e9ef;border-left:5px solid #e35b5b;border-radius:10px;padding:15px;margin-top:10px}.finding b{display:block;margin-bottom:5px}.empty{color:#68758d;padding:15px 0}@media(max-width:900px){.grid2{grid-template-columns:1fr}.metrics{grid-template-columns:repeat(2,1fr)}.wrap{padding:15px}.score{font-size:55px}}
</style>
</head>
<body>
<div class="wrap">
  <div class="top">
    <div><div class="brand">SecureMailScope M6</div><div class="sub">M2 → M3 → M4 → M5 security assessment</div></div>
    <div id="status" class="status">Ready</div>
  </div>

  <div class="upload">
    <input id="pcap" class="file" type="file" accept=".pcap,.pcapng,.cap" />
    <button id="analyze" class="btn">Analyze PCAP</button>
    <span id="filename" class="sub">Choose a PCAP / PCAPNG file</span>
  </div>
  <div id="message" class="msg"></div>

  <section id="results" class="hidden">
    <div class="grid2">
      <div class="card">
        <div class="label">Security posture score</div>
        <div id="score" class="score">—<span>/100</span></div>
        <p id="scoreText" class="muted">Run an assessment to see the M5 risk result.</p>
      </div>
      <div class="card">
        <div class="label">Protocol &amp; TLS summary</div>
        <div class="rows">
          <div class="row"><span>Email protocols</span><strong id="protocols">—</strong></div>
          <div class="row"><span>STARTTLS</span><strong id="starttls">—</strong></div>
          <div class="row"><span>TLS version</span><strong id="tlsVersion">—</strong></div>
          <div class="row"><span>Cipher suite</span><strong id="cipher">—</strong></div>
          <div class="row"><span>Key exchange</span><strong id="keyExchange">—</strong></div>
          <div class="row"><span>Forward Secrecy</span><strong id="forwardSecrecy">—</strong></div>
        </div>
      </div>
    </div>

    <div class="card">
      <div class="label">M2 — PCAP analysis</div>
      <div class="sub">Packet and protocol summary</div>
      <div class="metrics">
        <div class="metric"><small>Total packets</small><b id="totalPackets">0</b></div>
        <div class="metric"><small>SMTP packets</small><b id="smtpPackets">0</b></div>
        <div class="metric"><small>IMAP packets</small><b id="imapPackets">0</b></div>
        <div class="metric"><small>POP3 packets</small><b id="pop3Packets">0</b></div>
        <div class="metric"><small>Unknown packets</small><b id="unknownPackets">0</b></div>
        <div class="metric"><small>Skipped packets</small><b id="skippedPackets">0</b></div>
      </div>
    </div>

    <div class="card">
      <div class="label">M3 — stream analysis</div>
      <div id="m3Count" class="sub">0 stream(s) analyzed</div>
      <div class="table-wrap"><table><thead><tr><th>Protocol</th><th>Source</th><th>Destination</th><th>Packets</th><th>Stream</th></tr></thead><tbody id="m3Body"></tbody></table></div>
    </div>

    <div class="card">
      <div class="label">M4 — TLS / certificate analysis</div>
      <div id="m4Count" class="sub">0 stream(s) analyzed</div>
      <div class="table-wrap"><table><thead><tr><th>Protocol</th><th>STARTTLS</th><th>TLS version</th><th>Cipher</th><th>Key exchange</th><th>Forward secrecy</th><th>Certificate</th></tr></thead><tbody id="m4Body"></tbody></table></div>
    </div>

    <div class="card">
      <div class="label">M5 — AI / ML risk analysis</div>
      <div id="m5Count" class="sub">0 stream(s) analyzed</div>
      <div class="table-wrap"><table><thead><tr><th>Protocol</th><th>Risk score</th><th>Risk level</th><th>ML status</th><th>Stream</th></tr></thead><tbody id="m5Body"></tbody></table></div>
    </div>

    <div class="card">
      <div class="label">Security findings</div>
      <div id="findingsCount" class="sub">0 finding(s)</div>
      <div id="findings"></div>
    </div>

    <div class="card">
      <div class="label">Assessment details</div>
      <div class="rows">
        <div class="row"><span>Analysis ID</span><strong id="analysisId">—</strong></div>
        <div class="row"><span>Filename</span><strong id="analysisFilename">—</strong></div>
        <div class="row"><span>Status</span><strong id="analysisStatus">—</strong></div>
        <div class="row"><span>MongoDB saved</span><strong id="mongoSaved">—</strong></div>
      </div>
      <div class="actions"><button id="rawBtn" class="btn">View raw JSON</button><button id="downloadBtn" class="btn">Download JSON</button></div>
      <pre id="raw" class="hidden"></pre>
    </div>
  </section>
</div>
<script>
const $ = id => document.getElementById(id);
let latest = null;
const text = (v, fallback='—') => v === null || v === undefined || v === '' ? fallback : String(v);
const list = (v, fallback='—') => Array.isArray(v) && v.length ? v.filter(Boolean).join(', ') : fallback;
const unique = arr => [...new Set(arr.filter(v => v !== null && v !== undefined && v !== ''))];

function m3Results(data){
  return Array.isArray(data?.m3?.results) ? data.m3.results : [];
}
function m4Results(data){
  return Array.isArray(data?.m4?.results) ? data.m4.results : [];
}
function m5Results(data){
  return Array.isArray(data?.m5?.results) ? data.m5.results : [];
}
function riskScore(item){
  const n = Number(item?.risk?.score);
  return Number.isFinite(n) ? n : null;
}
function allFindings(data){
  const out=[];
  for(const x of m4Results(data)) for(const f of (x.findings||[])) out.push(f);
  for(const x of m5Results(data)) for(const f of (x.findings||[])) out.push(f);
  return out;
}
function overallRisk(data){
  const values=m5Results(data).map(riskScore).filter(v=>v!==null);
  if(!values.length) return null;
  return Math.round(values.reduce((a,b)=>a+b,0)/values.length);
}
function protocolList(data){
  const m2=data?.m2?.summary||{};
  const fromM4=m4Results(data).map(x=>x?.protocol);
  const fromM3=m3Results(data).map(x=>x?.protocol);
  const p=unique([...fromM4,...fromM3]);
  if(p.length) return p;
  const fallback=[];
  if(Number(m2.smtp_packets)>0) fallback.push('SMTP');
  if(Number(m2.imap_packets)>0) fallback.push('IMAP');
  if(Number(m2.pop3_packets)>0) fallback.push('POP3');
  return fallback;
}
function boolSummary(values, fallback='Not observed'){
  const v=values.filter(x=>typeof x==='boolean');
  if(!v.length) return fallback;
  if(v.every(x=>x===true)) return 'Enabled';
  if(v.every(x=>x===false)) return 'Disabled';
  return 'Mixed';
}
function esc(v){return String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
function render(data){
  latest=data;
  $('results').classList.remove('hidden');
  $('status').textContent='completed';
  $('status').style.background='#e6f5ea';
  const risk=overallRisk(data);
  const score=risk===null?null:Math.max(0,100-risk);
  $('score').innerHTML=(score===null?'—':score)+'<span>/100</span>';
  $('scoreText').textContent=risk===null?'M5 risk score was not available in this analysis.':`Overall risk: ${risk}/100 across ${m5Results(data).length} stream(s).`;
  $('protocols').textContent=list(protocolList(data),'Not detected');
  const m4=m4Results(data);
  $('starttls').textContent=m4.length?`${m4.filter(x=>x.starttls_detected===true).length}/${m4.length} stream(s) detected`:'Not detected';
  $('tlsVersion').textContent=list(unique(m4.map(x=>x?.tls?.tls_version)),'Not observed in capture');
  $('cipher').textContent=list(unique(m4.map(x=>x?.tls?.cipher_suite)),'Not observed in capture');
  $('keyExchange').textContent=list(unique(m4.map(x=>x?.tls?.key_exchange)),'Not observed in capture');
  $('forwardSecrecy').textContent=boolSummary(m4.map(x=>x?.tls?.forward_secrecy),'Not observed in capture');
  const s=data?.m2?.summary||{};
  $('totalPackets').textContent=text(s.total_packets,0);$('smtpPackets').textContent=text(s.smtp_packets,0);$('imapPackets').textContent=text(s.imap_packets,0);$('pop3Packets').textContent=text(s.pop3_packets,0);$('unknownPackets').textContent=text(s.unknown_packets,0);$('skippedPackets').textContent=text(s.skipped_packets,0);
  const m3=m3Results(data); $('m3Count').textContent=`${m3.length} stream(s) analyzed`;
  $('m3Body').innerHTML=m3.length?m3.map(x=>`<tr><td>${esc(x.protocol)}</td><td>${esc(x.source||x.src)}</td><td>${esc(x.destination||x.dst)}</td><td>${esc(x.packet_count??x.packets??'—')}</td><td>${esc(x.stream_id)}</td></tr>`).join(''):'<tr><td colspan="5" class="empty">No M3 stream results.</td></tr>';
  $('m4Count').textContent=`${m4.length} stream(s) analyzed`;
  $('m4Body').innerHTML=m4.length?m4.map(x=>{const t=x.tls||{};const c=x.certificate||{};return `<tr><td>${esc(x.protocol)}</td><td>${x.starttls_detected?'Enabled':'Not detected'}</td><td>${esc(t.tls_version||'Not observed')}</td><td>${esc(t.cipher_suite||'Not observed')}</td><td>${esc(t.key_exchange||'Not observed')}</td><td>${esc(typeof t.forward_secrecy==='boolean'?(t.forward_secrecy?'Enabled':'Disabled'):'Not observed')}</td><td>${c.observed?'Observed':'Not observed'}</td></tr>`}).join(''):'<tr><td colspan="7" class="empty">No M4 results.</td></tr>';
  const m5=m5Results(data); $('m5Count').textContent=`${m5.length} stream(s) analyzed`;
  $('m5Body').innerHTML=m5.length?m5.map(x=>`<tr><td>${esc(x.protocol)}</td><td>${esc(x.risk?.score??'—')}</td><td>${esc(x.risk?.risk_level??'—')}</td><td>${esc(x.ml_model_status??'—')}</td><td>${esc(x.stream_id)}</td></tr>`).join(''):'<tr><td colspan="5" class="empty">No M5 results.</td></tr>';
  const findings=allFindings(data);$('findingsCount').textContent=`${findings.length} finding(s)`;$('findings').innerHTML=findings.length?findings.map(f=>`<div class="finding"><b>${esc(f.severity||'INFO')} — ${esc(f.type||'Finding')}</b><div>${esc(f.message||'')}</div>${f.recommendation?`<div class="muted"><b>Recommendation:</b> ${esc(f.recommendation)}</div>`:''}</div>`).join(''):'<div class="empty">No security findings reported.</div>';
  $('analysisId').textContent=text(data.analysis_id);$('analysisFilename').textContent=text(data.filename);$('analysisStatus').textContent=text(data.status);$('mongoSaved').textContent=data.mongodb_saved?'Yes':'No — temporary API cache';
  $('raw').textContent=JSON.stringify(data,null,2);
}

$('pcap').addEventListener('change',()=>{$('filename').textContent=$('pcap').files[0]?.name||'Choose a PCAP / PCAPNG file';});
$('analyze').addEventListener('click',async()=>{
  const file=$('pcap').files[0]; if(!file){$('message').textContent='Select a PCAP file first.';return;}
  const fd=new FormData();fd.append('file',file);$('analyze').disabled=true;$('status').textContent='analyzing…';$('message').textContent='Running M2 → M3 → M4 → M5. This can take a moment.';
  try{const r=await fetch('/upload-pcap',{method:'POST',body:fd});const data=await r.json();if(!r.ok)throw new Error(data.detail||data.message||`HTTP ${r.status}`);$('message').textContent=data.message||'Analysis completed.';render(data);window.scrollTo({top:0,behavior:'smooth'});}catch(e){$('status').textContent='error';$('message').textContent=e.message||String(e);}finally{$('analyze').disabled=false;}
});
$('rawBtn').addEventListener('click',()=>{$('raw').classList.toggle('hidden');$('rawBtn').textContent=$('raw').classList.contains('hidden')?'View raw JSON':'Hide raw JSON';});
$('downloadBtn').addEventListener('click',()=>{if(!latest)return;const blob=new Blob([JSON.stringify(latest,null,2)],{type:'application/json'});const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download=`securemailscope-${latest.analysis_id||'assessment'}.json`;a.click();URL.revokeObjectURL(a.href);});
</script>
</body>
</html>'''


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def root():
    return HTMLResponse(dashboard_html())


@app.get("/dashboard", response_class=HTMLResponse, include_in_schema=False)
def dashboard():
    return HTMLResponse(dashboard_html())


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
    command = [sys.executable, "-m", "app.analysis.m2_parser.parser", str(pcap_path)]
    process = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        stdin=subprocess.DEVNULL,
        timeout=300,
        cwd=str(BASE_DIR),
    )
    if process.returncode != 0:
        raise RuntimeError(
            f"M2 parser failed. Exit code: {process.returncode}\n"
            f"STDOUT:\n{process.stdout}\nSTDERR:\n{process.stderr}"
        )
    return {"exit_code": process.returncode, "stdout": process.stdout or "", "stderr": process.stderr or ""}


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
    start = output.find("ProtocolSummary(")
    if start == -1:
        return summary
    end = output.find(")", start)
    if end == -1:
        return summary
    text = output[start:end + 1]
    for field in summary:
        marker = field + "="
        pos = text.find(marker)
        if pos == -1:
            continue
        value_start = pos + len(marker)
        value_end = text.find(",", value_start)
        if value_end == -1:
            value_end = text.find(")", value_start)
        try:
            summary[field] = int(text[value_start:value_end].strip())
        except Exception:
            pass
    return summary


@app.post("/upload-pcap")
async def upload_pcap(file: UploadFile = File(...)):
    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename supplied.")

    original_filename = Path(file.filename).name
    if Path(original_filename).suffix.lower() not in {".pcap", ".pcapng", ".cap"}:
        raise HTTPException(status_code=400, detail="Unsupported file type. Upload .pcap, .pcapng or .cap.")

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
        raise HTTPException(status_code=500, detail=f"PCAP upload failed: {exc}")
    finally:
        await file.close()

    try:
        parser_result = run_m2_parser(pcap_path)
        pipeline_result = run_full_pipeline(pcap_path)
    except Exception as exc:
        logger.exception("Analysis failed")
        raise HTTPException(status_code=500, detail=f"PCAP analysis failed: {exc}")

    analysis = {
        "analysis_id": analysis_id,
        "filename": original_filename,
        "stored_filename": stored_filename,
        "pipeline": "M2 -> M3 -> M4 -> M5",
        "status": "completed",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "m2": {
            "module": "M2",
            "summary": extract_m2_summary(parser_result["stdout"]),
            "parser": parser_result,
        },
        "m3": pipeline_result.get("m3", {}),
        "m4": pipeline_result.get("m4", {}),
        "m5": pipeline_result.get("m5", {}),
        "mongodb_saved": False,
    }

    RESULT_CACHE[analysis_id] = analysis.copy()
    mongodb_saved = False
    try:
        mongodb_saved = bool(save_analysis(analysis))
    except Exception:
        logger.exception("MongoDB save failed")

    analysis["mongodb_saved"] = mongodb_saved
    analysis["message"] = (
        "PCAP analyzed successfully and result persisted to MongoDB."
        if mongodb_saved
        else "PCAP analyzed successfully. MongoDB persistence is unavailable, but the complete assessment result is available in this response and the temporary API cache."
    )
    RESULT_CACHE[analysis_id] = analysis.copy()
    return analysis


@app.get("/results/{analysis_id}")
def get_results(analysis_id: str):
    try:
        analysis = get_analysis(analysis_id)
    except Exception:
        analysis = None
    if analysis is None:
        analysis = RESULT_CACHE.get(analysis_id)
    if analysis is None:
        raise HTTPException(status_code=404, detail="Analysis not found in MongoDB or temporary API cache.")
    return analysis


@app.get("/report/{analysis_id}/json")
def json_report(analysis_id: str):
    return get_results(analysis_id)


@app.get("/report/{analysis_id}/html", response_class=HTMLResponse)
def html_report(analysis_id: str):
    analysis = get_results(analysis_id)
    return HTMLResponse(
        "<html><body><h1>SecureMailScope Assessment</h1><pre>" +
        html.escape(json.dumps(analysis, indent=2, default=str)) +
        "</pre></body></html>"
    )
