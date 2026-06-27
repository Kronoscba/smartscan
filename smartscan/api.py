import asyncio
import json
import os
import uuid
from pathlib import Path
from typing import Dict, Any, Optional

from fastapi import FastAPI, Form, HTTPException, Query
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.requests import Request

from smartscan.runner import run_scan, list_scans_scans_dir, load_scan
from smartscan.reporter import generate_html_report, generate_markdown_report

GUI_DIR = Path(__file__).parent / "gui"
SCANS_DIR = os.environ.get("SMARTSCAN_SCANS_DIR", "scans")

app = FastAPI(title="SmartScan Web", version="0.2.0")
app.mount("/static", StaticFiles(directory=str(GUI_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(GUI_DIR / "templates"))

scan_state: Dict[str, Dict[str, Any]] = {}


def _summary(result: dict) -> dict:
    open_ports = result.get("scan", {}).get("open_ports", [])
    web = result.get("web", {})
    risks = len(web.get("risks", [])) + sum(1 for p in open_ports if p.get("possible_cves"))
    return {
        "ports": len(open_ports),
        "risks": risks,
        "subdomains": len(result.get("subdomains", [])),
        "paths": len(result.get("discovered_paths", [])),
    }


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse(request, "index.html", {"request": request})


@app.post("/scan", response_class=HTMLResponse)
async def start_scan(
    request: Request,
    host: str = Form(...),
    ports: Optional[str] = Form(None),
    timeout: float = Form(1.0),
    dns: bool = Form(False),
    subdomains: bool = Form(False),
    cve: bool = Form(False),
    shodan: Optional[str] = Form(None),
    greynoise: bool = Form(False),
    stealth: bool = Form(False),
):
    scan_id = uuid.uuid4().hex[:12]
    ports_list = None
    if ports:
        ports_list = []
        for part in ports.replace(" ", "").split(","):
            if "-" in part:
                a, b = map(int, part.split("-"))
                ports_list.extend(range(a, b + 1))
            else:
                ports_list.append(int(part))
        ports_list = sorted(set(p for p in ports_list if 1 <= p <= 65535))

    scan_state[scan_id] = {"progress": 0, "step": "Encolado...", "status": "pending"}

    async def progress(pct: int, step: str):
        scan_state[scan_id] = {"progress": pct, "step": step, "status": "running"}

    async def task():
        try:
            result = await run_scan(
                host=host, ports=ports_list, timeout=timeout,
                dns=dns, subdomains=subdomains, cve=cve,
                shodan=shodan or None, greynoise=greynoise, stealth=stealth,
                progress=progress,
            )
            result["scan_id"] = scan_id
            os.makedirs(SCANS_DIR, exist_ok=True)
            with open(os.path.join(SCANS_DIR, f"{scan_id}.json"), "w") as f:
                json.dump(result, f, indent=2)
            scan_state[scan_id] = {"progress": 100, "step": "Completado", "status": "done", "result": result}
        except Exception as e:
            scan_state[scan_id] = {"progress": 0, "step": str(e), "status": "error", "error": str(e)}

    asyncio.create_task(task())
    return templates.TemplateResponse(request, "progress.html", {
        "scan_id": scan_id, "progress": 0, "step": "Encolado...",
    })


@app.get("/scan/{scan_id}/status", response_class=HTMLResponse)
async def scan_status(request: Request, scan_id: str):
    state = scan_state.get(scan_id)
    if state is None:
        result = load_scan(scan_id, SCANS_DIR)
        if result:
            return templates.TemplateResponse(request, "results.html", {
                "result": result, "summary": _summary(result),
            })
        return HTMLResponse('<div class="error">Escaneo no encontrado</div>')

    if state["status"] == "done":
        return templates.TemplateResponse(request, "results.html", {
            "result": state["result"], "summary": _summary(state["result"]),
        })
    if state["status"] == "error":
        return HTMLResponse(f'<div class="error">Error: {state.get("error", "desconocido")}</div>')

    return templates.TemplateResponse(request, "progress.html", {
        "scan_id": scan_id, "progress": state["progress"], "step": state["step"],
    })


@app.get("/scan/{scan_id}", response_class=HTMLResponse)
async def view_scan(request: Request, scan_id: str):
    result = load_scan(scan_id, SCANS_DIR)
    if not result:
        raise HTTPException(404, "Escaneo no encontrado")
    return templates.TemplateResponse(request, "results.html", {
        "result": result, "summary": _summary(result),
    })


@app.get("/history", response_class=HTMLResponse)
async def history(request: Request):
    scans = list_scans_scans_dir(SCANS_DIR)
    return templates.TemplateResponse(request, "history.html", {
        "scans": scans,
    })


@app.get("/scan/{scan_id}/export/{fmt}")
async def export_scan(scan_id: str, fmt: str):
    result = load_scan(scan_id, SCANS_DIR)
    if not result:
        raise HTTPException(404, "Escaneo no encontrado")

    if fmt == "json":
        return FileResponse(
            path=os.path.join(SCANS_DIR, f"{scan_id}.json"),
            media_type="application/json",
            filename=f"smartscan_{scan_id}.json",
        )
    elif fmt == "html":
        path = os.path.join(SCANS_DIR, f"{scan_id}.html")
        generate_html_report(result, path)
        return FileResponse(path=path, media_type="text/html", filename=f"smartscan_{scan_id}.html")
    elif fmt == "md":
        path = os.path.join(SCANS_DIR, f"{scan_id}.md")
        generate_markdown_report(result, path)
        return FileResponse(path=path, media_type="text/markdown", filename=f"smartscan_{scan_id}.md")
    raise HTTPException(400, "Formato no soportado. Usa: json, html, md")


def serve():
    import uvicorn
    uvicorn.run("smartscan.api:app", host="0.0.0.0", port=8500, reload=True)
