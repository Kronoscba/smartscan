#!/usr/bin/env python3
import argparse
import asyncio
import json
import os
import sys

from smartscan.runner import run_scan
from smartscan.scanner import COMMON_PORTS
from smartscan.reporter import generate_html_report, generate_markdown_report


async def main():
    parser = argparse.ArgumentParser(
        description="smartscan - Escáner inteligente",
        epilog="Ej: smartscan -H example.com -d -c -r reporte.html",
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
    parser.add_argument("-w", "--web", action="store_true")
    parser.add_argument("-e", "--stealth", action="store_true")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-r", "--html", help="Guardar reporte en HTML")
    group.add_argument("-m", "--md", help="Guardar reporte en Markdown")
    group.add_argument(
        "--report",
        metavar="BASE",
        help="Generar reporte en HTML y Markdown (ej: --report scan_example)",
    )

    args = parser.parse_args()

    ports = None
    if args.ports:
        ports = []
        for part in args.ports.split(","):
            if "-" in part:
                start, end = map(int, part.split("-"))
                ports.extend(range(start, end + 1))
            else:
                ports.append(int(part))
        ports = sorted(set(p for p in ports if 1 <= p <= 65535))

    if not args.json:
        print(f"[i] Objetivo: {args.host} | Puertos: {len(ports or COMMON_PORTS)}")
        print("-" * 70)

    async def print_progress(pct: int, step: str):
        if not args.json:
            print(f"  [{pct:>3}%] {step}")

    result = await run_scan(
        host=args.host,
        ports=ports,
        timeout=args.timeout,
        dns=args.dns,
        subdomains=args.subdomains,
        cve=args.cve,
        shodan=args.shodan,
        greynoise=args.greynoise,
        stealth=args.stealth,
        progress=print_progress,
    )

    if not args.json:
        open_ports = result["scan"]["open_ports"]
        web_info = result.get("web")
        discovered_paths = result.get("discovered_paths")
        if web_info:
            print("\n[🔍] Análisis Web:")
            for k, label in [("cms", "CMS"), ("backend", "Backend"), ("server", "Server")]:
                if web_info.get(k):
                    print(f"  {label}: {web_info[k]}")
            if web_info.get("risks"):
                print(f"  ⚠️  Riesgos: {', '.join(web_info['risks'])}")
            if web_info.get("security_headers"):
                print(f"  🛡️  Security Headers: {len(web_info['security_headers'])} presentes")
            if discovered_paths:
                print(f"  📁 Rutas encontradas: {len(discovered_paths)}")

    if args.report:
        html_file = f"{args.report}.html"
        md_file = f"{args.report}.md"
        generate_html_report(result, html_file)
        generate_markdown_report(result, md_file)
        if not args.json:
            print(f"\n[✓] Reportes guardados: {html_file}, {md_file}")
    elif args.html:
        generate_html_report(result, args.html)
        if not args.json:
            print(f"\n[✓] Reporte HTML: {os.path.abspath(args.html)}")
    elif args.md:
        generate_markdown_report(result, args.md)
        if not args.json:
            print(f"\n[✓] Reporte Markdown: {os.path.abspath(args.md)}")

    if args.output:
        with open(args.output, "w") as f:
            json.dump(result, f, indent=2)
        if not args.json:
            print(f"\n[✓] Guardado: {os.path.abspath(args.output)}")

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print("-" * 70)
        print(f"✅ Puertos abiertos: {len(result['scan']['open_ports'])}")


def cli():
    try:
        if sys.platform == "win32":
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Cancelado.", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    cli()
