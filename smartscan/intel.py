import asyncio
import aiohttp
from shodan import Shodan

async def query_shodan(ip: str, api_key: str):
    if not api_key: return None
    try:
        api = Shodan(api_key)
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, api.host, ip)
        return {
            "org": result.get("org", "N/A"),
            "ports": result.get("ports", []),
            "vulns": result.get("vulns", [])
        }
    except Exception as e:
        return {"error": str(e)}

async def query_greynoise(ip: str):
    try:
        url = f"https://api.greynoise.io/v3/community/{ip}"
        headers = {"Accept": "application/json"}
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=3)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return {
                        "classification": data.get("classification", "unknown"),
                        "name": data.get("name", "N/A")
                    }
    except: pass
    return None
