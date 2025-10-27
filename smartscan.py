#!/usr/bin/env python3
import argparse
import dns.resolver
import httpx
import sys

def dns_scan(domain):
    """Escaneo DNS básico"""
    print(f"[*] Realizando escaneo DNS de: {domain}")
    
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']
    
    for record in record_types:
        try:
            answers = dns.resolver.resolve(domain, record)
            for rdata in answers:
                print(f"  {record}: {rdata}")
        except Exception as e:
            print(f"  {record}: No encontrado o error")

def http_scan(domain):
    """Escaneo HTTP básico"""
    print(f"[*] Realizando escaneo HTTP de: {domain}")
    
    try:
        # Probar HTTP y HTTPS
        for scheme in ['https', 'http']:
            url = f"{scheme}://{domain}"
            try:
                with httpx.Client(timeout=10) as client:
                    response = client.get(url)
                    print(f"  {scheme.upper()}: {response.status_code} - {url}")
                    
                    # Mostrar headers interesantes
                    security_headers = ['server', 'x-powered-by', 'x-frame-options']
                    for header in security_headers:
                        if header in response.headers:
                            print(f"    {header}: {response.headers[header]}")
                            
            except Exception as e:
                print(f"  {scheme.upper()}: Error - {e}")
    except Exception as e:
        print(f"  Error en escaneo HTTP: {e}")

def cve_scan(domain):
    """Escaneo básico de tecnologías (para detectar CVEs potenciales)"""
    print(f"[*] Buscando tecnologías vulnerables en: {domain}")
    
    try:
        with httpx.Client(timeout=10) as client:
            response = client.get(f"https://{domain}")
            
            # Detectar tecnologías por headers
            server = response.headers.get('server', 'Desconocido')
            powered_by = response.headers.get('x-powered-by', 'Desconocido')
            
            print(f"  Servidor: {server}")
            print(f"  Tecnología: {powered_by}")
            print("  [INFO] Para análisis CVE avanzado necesitarías integración con bases de datos CVE")
            
    except Exception as e:
        print(f"  Error en escaneo CVE: {e}")

def main():
    parser = argparse.ArgumentParser(description='SmartScan - Herramienta de escaneo de seguridad')
    parser.add_argument('-H', '--host', required=True, help='Dominio a escanear')
    parser.add_argument('--dns', action='store_true', help='Realizar escaneo DNS')
    parser.add_argument('--http','--web', action='store_true', help='Realizar escaneo HTTP/Web')
    parser.add_argument('--cve', action='store_true', help='Buscar CVEs potenciales')
    
    args = parser.parse_args()
    
    print(f"[+] Iniciando SmartScan para: {args.host}")
    print("=" * 50)
    
    if args.dns:
        dns_scan(args.host)
        print()
    
    if args.http or not (args.dns or args.http or args.cve):
        http_scan(args.host)
        print()
    
    if args.cve:
        cve_scan(args.host)
        print()
    
    print("[+] Escaneo completado")

if __name__ == "__main__":
    main()
