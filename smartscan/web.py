# smartscan/web.py
import random
import asyncio
import aiohttp
from typing import Dict, List

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1"
]

async def fingerprint_web(host: str, timeout: float = 5.0) -> Dict:
    """Detecta CMS, backend, tecnologías, WAF y riesgos conocidos."""
    results = {
        "cms": None,
        "backend": None,
        "technologies": [],
        "waf": None,
        "server": None,
        "security_headers": {},
        "risks": [],
        "status_codes": {}
    }

    user_agent = random.choice(USER_AGENTS)
    headers = {"User-Agent": user_agent}
    urls = [f"http://{host}", f"https://{host}"]

    async with aiohttp.ClientSession() as session:
        for url in urls:
            try:
                async with session.get(url, headers=headers, timeout=timeout, ssl=False) as resp:
                    results["status_codes"][url] = resp.status
                    resp_headers = dict(resp.headers)
                    content = (await resp.text()).lower()

                    # === Servidor ===
                    server_val = resp_headers.get("Server", "")
                    if server_val:
                        results["server"] = server_val
                        server_lower = server_val.lower()
                        if "nginx" in server_lower:
                            results["technologies"].append("nginx")
                        elif "apache" in server_lower:
                            results["technologies"].append("Apache")

                    # === Backend desde X-Powered-By ===
                    powered_by = resp_headers.get("X-Powered-By", "")
                    if powered_by:
                        powered_lower = powered_by.lower()
                        if "php" in powered_lower:
                            results["backend"] = "PHP"
                        elif "asp.net" in powered_lower:
                            results["backend"] = "ASP.NET"
                        elif "express" in powered_lower:
                            results["backend"] = "Node.js (Express)"
                        elif "django" in powered_lower:
                            results["backend"] = "Python (Django)"

                    # === CMS ===
                    if "wp-content" in content or "wordpress" in content:
                        results["cms"] = "WordPress"
                    elif "joomla" in content:
                        results["cms"] = "Joomla"
                    elif "drupal" in content:
                        results["cms"] = "Drupal"

                    # === Frontend ===
                    frontend = []
                    if "react" in content:
                        frontend.append("React")
                    if "vue" in content:
                        frontend.append("Vue.js")
                    if "angular" in content:
                        frontend.append("Angular")
                    results["technologies"].extend(frontend)

                    # === WAF ===
                    if "cloudflare" in server_lower or "cf-ray" in resp_headers:
                        results["waf"] = "Cloudflare"
                    elif "sucuri" in server_lower or "x-sucuri" in resp_headers:
                        results["waf"] = "Sucuri"
                    elif "akamai" in server_lower:
                        results["waf"] = "Akamai"

                    # === Riesgos ===
                    if results["backend"] == "PHP" and results["server"] and "nginx" in results["server"].lower():
                        results["risks"].append("Posible CVE-2019-11043 (RCE en PHP+Nginx)")

                    # === Cabeceras de seguridad ===
                    sec_headers = ["Strict-Transport-Security", "Content-Security-Policy", 
                                   "X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy"]
                    for h in sec_headers:
                        if h in resp_headers:
                            results["security_headers"][h] = resp_headers[h]

            except:
                continue

    results["technologies"] = list(set(results["technologies"]))
    return results

async def scan_common_paths(host: str, timeout: float = 3.0) -> List[str]:
    """Escanea rutas comunes (ligero, solo las más críticas)."""
    common_paths = ["/robots.txt", "/admin", "/login", "/wp-login.php", "/.git/", "/backup/"]
    found = []
    headers = {"User-Agent": random.choice(USER_AGENTS)}
    async with aiohttp.ClientSession() as session:
        for path in common_paths:
            for scheme in ["https", "http"]:
                url = f"{scheme}://{host}{path}"
                try:
                    async with session.get(url, headers=headers, timeout=timeout, ssl=False) as resp:
                        if resp.status == 200:
                            found.append(url)
                            break
                except:
                    continue
    return found
