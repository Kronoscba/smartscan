#!/usr/bin/env python3
import argparse
import asyncio
import json
import os
import socket
import sys
from datetime import datetime, timezone
from smartscan.scanner import scan_ports, COMMON_PORTS, PORT_SERVICES
from smartscan.dns import get_dns_records, get_subdomains
from smartscan.cve import check_cves_for_ports
from smartscan.intel import query_shodan, query_greynoise
from smartscan.web import fingerprint_web, scan_common_paths
from smartscan.reporter import generate_html_report, generate_markdown_report

async def main():
    parser = argparse.ArgumentParser(
        description="smartscan - Escáner inteligente",
        epilog="Ej: smartscan -H example.com -d -c -r reporte.html"
    )
    parser.add_argument("-H", "--host", required=True)
    parser.add_argument("-p", "--ports")
    parser.add_argument("-t", "--timeout", type=float, default=1.0)
    parser.add_argument("-d", "--dns", action="store_true")
    parser.add_argument("-s", "--subdomains", action="store_true")
    parser.add_argument("-c", "--cve", action="store_true")
    parser.add_argument("-S", "--shodan")
    parser.add_argument("-g", "--greynoise", action="store_true")
    parser.add_argument("-o", "--output")
    parser.add_argument("-j", "--json", action="store_true")
    parser.add_argument("-w", "--web", action="store_true", help="Fingerprinting web avanzado")
    parser.add_argument("-e", "--stealth", action="store_true", help="Modo sigiloso: aleatoriza puertos y añade delays")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-r", "--html", help="Guardar reporte en HTML")
    group.add_argument("-m", "--md", help="Guardar reporte en Markdown")
    group.add_argument("--report", metavar="BASE", help="Generar reporte en HTML y Markdown (ej: --report scan_example)")

    args = parser.parse_args()

    try:
        ip = socket.gethostbyname(args.host)
    except socket.gaierror:
        print(f"[-] Error: No se pudo resolver '{args.host}'", file=sys.stderr)
        sys.exit(1)

    # Determinar puertos
    if args.ports:
        ports = []
        for part in args.ports.split(','):
            if '-' in part:
                start, end = map(int, part.split('-'))
                ports.extend(range(start, end + 1))
            else:
                ports.append(int(part))
        ports = sorted(set(p for p in ports if 1 <= p <= 65535))
    else:
        ports = COMMON_PORTS
        if not args.json:
            print(f"[i] Usando top {len(COMMON_PORTS)} puertos.")

    if not args.json:
        print(f"[i] Objetivo: {args.host} ({ip}) | Puertos: {len(ports)}")
        print("-" * 70)

    # Escaneo principal
    open_ports = await scan_ports(ip, ports, args.timeout, args.json)

    # Análisis web (si hay puertos 80/443 abiertos)
    web_info = None
    discovered_paths = None
    if any(p["port"] in (80, 443) for p in open_ports):
        if not args.json:
            print("[i] Realizando fingerprinting web...")
        web_info = await fingerprint_web(args.host, args.timeout)
        if not args.json:
            print("[i] Escaneando rutas comunes...")
        discovered_paths = await scan_common_paths(args.host, args.timeout)
        

    # Procesar CVEs
    if args.cve:
        await check_cves_for_ports(open_ports)

    # Datos externos
    external_data = {}
    if args.shodan:
        if not args.json: print("[i] Consultando Shodan...")
        external_data["shodan"] = await query_shodan(ip, args.shodan)
    if args.greynoise:
        if not args.json: print("[i] Consultando GreyNoise...")
        external_data["greynoise"] = await query_greynoise(ip)

    # DNS y subdominios (solo si es dominio)
    dns_data = None
    subdomains = None
    is_ip = args.host.replace(".", "").replace(":", "").replace("[", "").replace("]", "").isdigit()
    if not is_ip:
        if args.dns:
            if not args.json: print("[i] Consultando DNS...")
            dns_data = get_dns_records(args.host)
        if args.subdomains:
            if not args.json: print("[i] Buscando subdominios...")
            subdomains = await get_subdomains(args.host)

    # Resultado
    result = {
        "target": {"host": args.host, "ip": ip},
        "scan": {
            "ports_scanned": len(ports),
            "open_ports": open_ports,
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        },
        "external": external_data,
    }
    if dns_data is not None:
        result["dns"] = dns_data
    if subdomains is not None:
        result["subdomains"] = subdomains
    if web_info is not None:
        result["web"] = web_info
    if discovered_paths:
        result["discovered_paths"] = discovered_paths
    if not args.json and web_info:
            print("\n[🔍] Análisis Web:")
            if web_info.get("cms"):
                print(f"  🖥️  CMS: {web_info['cms']}")
            if web_info.get("backend"):
                print(f"  ⚙️  Backend: {web_info['backend']}")
            if web_info.get("server"):
                print(f"  🌐 Server: {web_info['server']}")
            if web_info.get("risks"):
                print(f"  ⚠️  Riesgos: {', '.join(web_info['risks'])}")
            if discovered_paths:
                print(f"  📁 Rutas encontradas: {len(discovered_paths)}")
    # Generar reportes
    if args.report:
        html_file = f"{args.report}.html"
        md_file = f"{args.report}.md"
        generate_html_report(result, html_file)
        generate_markdown_report(result, md_file)
        if not args.json:
            print(f"\n[✓] Reporte HTML guardado en: {os.path.abspath(html_file)}")
            print(f"[✓] Reporte Markdown guardado en: {os.path.abspath(md_file)}")
    elif args.html:
        generate_html_report(result, args.html)
        if not args.json:
            print(f"\n[✓] Reporte HTML guardado en: {os.path.abspath(args.html)}")
    elif args.md:
        generate_markdown_report(result, args.md)
        if not args.json:
            print(f"\n[✓] Reporte Markdown guardado en: {os.path.abspath(args.md)}")

    # Salida
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(result, f, indent=2)
        if not args.json:
            print(f"\n[✓] Guardado en: {os.path.abspath(args.output)}")

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print("-" * 70)
        print(f"✅ Puertos abiertos: {len(open_ports)}")
        # (Agrega resúmenes como antes)

def cli():
            """Wrapper sincrónico para el entry point."""
            try:
                if sys.platform == "win32":
                    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
                asyncio.run(main())
            except KeyboardInterrupt:
                print("\n[!] Cancelado.", file=sys.stderr)
                sys.exit(1)
        
if __name__ == "__main__":
    cli()
