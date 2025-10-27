import asyncio
import aiohttp
from typing import List, Dict

async def check_cves(service: str, version: str) -> List[str]:
    try:
        url = f"https://cve.circl.lu/api/search/{service}/{version}"
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return [cve["id"] for cve in data.get("results", [])[:3]]
    except: pass
    return []

async def check_cves_for_ports(open_ports: List[Dict]):
    for port_info in open_ports:
        if "version" in port_info:
            cves = await check_cves(port_info["detected_service"], port_info["version"])
            if cves:
                port_info["possible_cves"] = cves
                port_info["confidence"] = "medium"
                port_info["note"] = "Requiere validación manual"
