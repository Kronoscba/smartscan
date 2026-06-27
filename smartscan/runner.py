import asyncio
import json
import os
import socket
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

from smartscan.scanner import scan_ports, COMMON_PORTS
from smartscan.dns import get_dns_records, get_subdomains
from smartscan.cve import check_cves_for_ports
from smartscan.intel import query_shodan, query_greynoise
from smartscan.web import fingerprint_web, scan_common_paths

ProgressCb = Callable[[int, str], None]

async def run_scan(
    host: str,
    ports: Optional[List[int]] = None,
    timeout: float = 1.0,
    dns: bool = False,
    subdomains: bool = False,
    cve: bool = False,
    shodan: Optional[str] = None,
    greynoise: bool = False,
    stealth: bool = False,
    progress: Optional[ProgressCb] = None,
) -> Dict[str, Any]:
    async def update(pct: int, step: str):
        if progress:
            await progress(pct, step)

    await update(0, "Inicializando...")

    ip = socket.gethostbyname(host)
    await update(5, f"IP resuelta: {ip}")

    if ports is None:
        ports = COMMON_PORTS

    await update(10, "Escaneando puertos...")
    open_ports = await scan_ports(ip, ports, timeout, quiet=True, stealth=stealth)
    await update(30, f"Puertos: {len(open_ports)} abiertos")

    web_info = None
    discovered_paths = None
    if any(p["port"] in (80, 443) for p in open_ports):
        await update(40, "Fingerprinting web...")
        web_info = await fingerprint_web(host, timeout)
        await update(50, "Escaneando rutas...")
        discovered_paths = await scan_common_paths(host, timeout)
    await update(55, "Web analizado")

    if cve:
        await update(60, "Buscando CVEs...")
        await check_cves_for_ports(open_ports)
    await update(70, "CVEs procesados")

    external_data: Dict[str, Any] = {}
    if shodan:
        await update(75, "Consultando Shodan...")
        external_data["shodan"] = await query_shodan(ip, shodan)
    if greynoise:
        await update(80, "Consultando GreyNoise...")
        external_data["greynoise"] = await query_greynoise(ip)
    await update(85, "Inteligencia externa completada")

    dns_data = None
    scan_subdomains = None
    is_ip = all(c in "0123456789.:[]" for c in host)
    if not is_ip:
        if dns:
            await update(87, "Consultando DNS...")
            dns_data = get_dns_records(host)
        if subdomains:
            await update(90, "Buscando subdominios...")
            scan_subdomains = await get_subdomains(host)

    result: Dict[str, Any] = {
        "target": {"host": host, "ip": ip},
        "scan": {
            "ports_scanned": len(ports),
            "open_ports": open_ports,
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        },
        "external": external_data,
    }
    if dns_data is not None:
        result["dns"] = dns_data
    if scan_subdomains is not None:
        result["subdomains"] = scan_subdomains
    if web_info is not None:
        result["web"] = web_info
    if discovered_paths:
        result["discovered_paths"] = discovered_paths

    await update(100, "Completado")
    return result


def save_scan_scans_dir(result: Dict[str, Any], scans_dir: str = "scans"):
    os.makedirs(scans_dir, exist_ok=True)
    scan_id = result.get("scan_id") or result["scan"]["timestamp"]
    path = os.path.join(scans_dir, f"{scan_id}.json")
    with open(path, "w") as f:
        json.dump(result, f, indent=2)
    return path


def list_scans_scans_dir(scans_dir: str = "scans") -> List[Dict[str, Any]]:
    if not os.path.isdir(scans_dir):
        return []
    scans = []
    for fname in sorted(os.listdir(scans_dir), reverse=True):
        if fname.endswith(".json"):
            try:
                with open(os.path.join(scans_dir, fname)) as f:
                    data = json.load(f)
                    scans.append({
                        "id": fname[:-5],
                        "host": data.get("target", {}).get("host", "?"),
                        "ip": data.get("target", {}).get("ip", "?"),
                        "timestamp": data.get("scan", {}).get("timestamp", "?"),
                        "ports": len(data.get("scan", {}).get("open_ports", [])),
                        "risks": sum(1 for p in data.get("scan", {}).get("open_ports", []) if p.get("possible_cves")),
                    })
            except (json.JSONDecodeError, KeyError):
                continue
    return scans


def load_scan(scan_id: str, scans_dir: str = "scans") -> Optional[Dict[str, Any]]:
    path = os.path.join(scans_dir, f"{scan_id}.json")
    if not os.path.isfile(path):
        return None
    with open(path) as f:
        return json.load(f)
