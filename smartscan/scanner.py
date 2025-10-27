import random
import asyncio
import re
from typing import List, Dict, Tuple

COMMON_PORTS = [21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5432,5900,6379,8000,8080,8443,8888,27017,1080,1433,1521,5000,11211,9200,9300,5601,8081,10000,137,138,500,4500,161,162,123,1701,1723,1194,5060,5061,389,636,3268,3269,1025,1026,1027,1028,1029,1030,1031,1032,1033,1034,1035,1036,1037,1038,1039,1040,1041,1042,1043,1044,1045,1046,1047,1048,1049,1050,1051,1052,1053,1054,1055,1056,1057,1058,1059,1060,1061,1062,1063,1064,1065,1066,1067,1068]

PORT_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 6379: "Redis",
    27017: "MongoDB", 9200: "Elasticsearch"
}

async def scan_ports(ip: str, ports: List[int], timeout: float, quiet: bool = False, stealth: bool = False):
            scan_order = ports[:]
            if stealth:
                random.shuffle(scan_order)
        
            # Usar la nueva función con jitter
            tasks = [scan_port_with_jitter(ip, port, timeout, stealth) for port in scan_order]
            results = await asyncio.gather(*tasks)
        
            open_ports = []
            port_result_map = {port: (is_open, banner) for port, is_open, banner in results}
        
            for port in ports:
                if port in port_result_map:
                    is_open, banner = port_result_map[port]
                    if is_open:
                        service_info = {"port": port, "banner": banner or "N/A", "service_guess": PORT_SERVICES.get(port, "Unknown")}
                        version_info = extract_version(banner) if banner else None
                        if version_info:
                            service_info["detected_service"] = version_info[0]
                            service_info["version"] = version_info[1]
                        open_ports.append(service_info)
                        if not quiet:
                            status = f"[+] {port}/tcp ABIERTO"
                            if version_info:
                                status += f" → {version_info[0]} {version_info[1]}"
                            elif banner and len(banner) > 10:
                                status += f" → {banner[:50]}..."
                            else:
                                status += f" → {service_info['service_guess']}"
                            print(status)
            return open_ports

def extract_version(banner: str):
    patterns = [
        r'(Apache|nginx|OpenSSH|vsftpd|MySQL|PostgreSQL|Redis|MongoDB|Elasticsearch)[/ ]?v?([0-9][0-9a-z._-]*)',
        r'Server:\s*([a-zA-Z]+)[/ ]?([0-9][0-9a-z._-]*)',
        r'SSH-2.0-([a-zA-Z0-9._-]+)',
    ]
    for pattern in patterns:
        match = re.search(pattern, banner, re.IGNORECASE)
        if match:
            groups = match.groups()
            if len(groups) >= 2 and groups[0] and groups[1] and groups[1][0].isdigit():
                return groups[0].strip(), groups[1].strip()
            elif len(groups) == 1:
                full = groups[0].strip()
                if "_" in full:
                    parts = full.split("_", 1)
                    if len(parts) == 2 and parts[1] and parts[1][0].isdigit():
                        return parts[0], parts[1]
    return None
    
async def scan_port_with_jitter(host: str, port: int, timeout: float, stealth: bool = False):
    """Escanea un puerto con delay aleatorio si está en modo stealth."""
    if stealth:
        # Delay aleatorio entre 0 y 0.5 segundos
        await asyncio.sleep(random.uniform(0, 0.5))
    
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        banner = ""
        try:
            banner_data = await asyncio.wait_for(reader.read(1024), timeout=1.0)
            banner = banner_data.decode('utf-8', errors='ignore').strip()
            if not banner and port in (80, 8080, 8888, 8000, 8443):
                writer.write(b"HEAD / HTTP/1.1\r\nHost: " + host.encode() + b"\r\n\r\n")
                await writer.drain()
                banner_data = await asyncio.wait_for(reader.read(1024), timeout=1.0)
                banner = banner_data.decode('utf-8', errors='ignore').strip()
        except:
            pass
        writer.close()
        await writer.wait_closed()
        return port, True, banner[:200]
    except:
        return port, False, ""
