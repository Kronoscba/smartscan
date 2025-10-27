import asyncio
import aiohttp
import dns.resolver
from typing import Dict, List

def get_dns_records(domain: str) -> Dict[str, List[str]]:
    records = {}
    for rtype in ["A", "AAAA", "MX", "TXT", "NS"]:
        try:
            if rtype == "MX":
                answers = dns.resolver.resolve(domain, rtype)
                records[rtype] = [str(r.exchange) for r in answers]
            else:
                answers = dns.resolver.resolve(domain, rtype)
                records[rtype] = [str(r) for r in answers]
        except:
            records[rtype] = []
    return records

async def get_subdomains(domain: str) -> List[str]:
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    subs = set()
                    for entry in data:
                        name = entry.get("name_value", "")
                        if name:
                            for part in name.split("\n"):
                                part = part.strip().lower()
                                if part and part.endswith(domain) and "." in part and not part.startswith("*"):
                                    subs.add(part)
                    return sorted(subs)
    except: pass
    return []
