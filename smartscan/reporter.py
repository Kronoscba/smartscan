from datetime import datetime
from pathlib import Path
from jinja2 import Environment, FileSystemLoader, select_autoescape

# === Recomendaciones globales (usadas en ambos formatos) ===
RECOMMENDATIONS = {
    "wordpress_outdated": "Actualizar WordPress a la última versión estable.",
    "exposed_admin": "Restringir el acceso al panel de administración por IP o autenticación adicional.",
    "exposed_git": "Eliminar el directorio .git del servidor web para evitar filtración de código fuente.",
    "default_cms": "Cambiar credenciales por defecto y ocultar la versión del CMS.",
    "outdated_server": "Actualizar el servidor web (nginx/apache) a la última versión segura.",
    "open_port": "Evaluar si el servicio es necesario; de lo contrario, cerrar el puerto o filtrar por IP.",
    "cve_found": "Aplicar parches de seguridad o mitigaciones recomendadas por el fabricante.",
    "sensitive_path": "Proteger o eliminar esta ruta sensible del servidor."
}

def classify_risk(risk_str: str):
    """Devuelve (emoji, etiqueta, clase_css, recomendación) según el riesgo."""
    risk_lower = risk_str.lower()
    if "wordpress" in risk_lower and ("outdated" in risk_lower or "desactualizado" in risk_lower):
        return "⚠️", "[ALTO]", "severity-high", RECOMMENDATIONS["wordpress_outdated"]
    elif "admin" in risk_lower or "panel" in risk_lower:
        return "⚠️", "[ALTO]", "severity-high", RECOMMENDATIONS["exposed_admin"]
    elif ".git" in risk_lower or "git" in risk_lower:
        return "⚠️", "[ALTO]", "severity-high", RECOMMENDATIONS["exposed_git"]
    elif "default" in risk_lower or "por defecto" in risk_lower:
        return "🔍", "[MEDIO]", "severity-medium", RECOMMENDATIONS["default_cms"]
    elif "outdated server" in risk_lower or "servidor desactualizado" in risk_lower:
        return "🔍", "[MEDIO]", "severity-medium", RECOMMENDATIONS["outdated_server"]
    elif "cve" in risk_lower:
        return "⚠️", "[ALTO]", "severity-high", RECOMMENDATIONS["cve_found"]
    elif any(kw in risk_lower for kw in ["backup", "config", "db", "env"]):
        return "⚠️", "[ALTO]", "severity-high", RECOMMENDATIONS["sensitive_path"]
    else:
        return "ℹ️", "[BAJO]", "severity-low", "Revisar manualmente para descartar falsos positivos."

def is_sensitive_path(path: str) -> bool:
    """Detecta si una ruta es potencialmente sensible."""
    sensitive_keywords = [".git", "backup", "admin", "config", "wp-", "db", "env", "sql", "log"]
    return any(kw in path.lower() for kw in sensitive_keywords)

def generate_html_report(data: dict, output_file: str):
    """Genera un reporte HTML profesional con recomendaciones y severidad."""
    target = data["target"]["host"]
    ip = data["target"]["ip"]
    open_ports = data["scan"]["open_ports"]
    dns_data = data.get("dns", {})
    subdomains = data.get("subdomains", [])
    web_info = data.get("web", {})
    discovered_paths = data.get("discovered_paths", [])
    shodan = data.get("external", {}).get("shodan", {})
    greynoise = data.get("external", {}).get("greynoise", {})

    # Clasificar riesgos
    web_risks = []
    for risk in web_info.get("risks", []):
        emoji, label, css_class, rec = classify_risk(risk)
        web_risks.append({
            "text": risk,
            "emoji": emoji,
            "label": label,
            "css_class": css_class,
            "recommendation": rec
        })

    cve_risks = []
    for p in open_ports:
        if p.get("possible_cves"):
            cve_risks.append({
                "port": p["port"],
                "cves": ", ".join(p["possible_cves"]),
                "recommendation": RECOMMENDATIONS["cve_found"]
            })

    total_risks = len(web_risks) + len(cve_risks)

    # Clasificar rutas descubiertas
    classified_paths = []
    for path in discovered_paths:
        is_sensitive = is_sensitive_path(path)
        classified_paths.append({
            "path": path,
            "is_sensitive": is_sensitive,
            "emoji": "⚠️" if is_sensitive else "✅",
            "label": "[ALTO]" if is_sensitive else "[INFO]"
        })

    context = {
        "target": target,
        "ip": ip,
        "report_date": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        "open_ports": open_ports,
        "dns_data": dns_data,
        "subdomains": subdomains,
        "web_info": web_info,
        "classified_paths": classified_paths,
        "shodan": shodan,
        "greynoise": greynoise,
        "web_risks": web_risks,
        "cve_risks": cve_risks,
        "total_risks": total_risks,
        "has_executive_summary": total_risks > 0,
        "RECOMMENDATIONS": RECOMMENDATIONS,
        "is_sensitive_path": is_sensitive_path
    }

    template_dir = Path(__file__).parent / "templates"
    env = Environment(
        loader=FileSystemLoader(template_dir),
        autoescape=select_autoescape(['html', 'xml'])
    )
    template = env.get_template("report_template.html")
    html_output = template.render(**context)

    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html_output)


def generate_markdown_report(data: dict, output_file: str):
    """Genera un reporte en Markdown profesional con emojis y recomendaciones."""
    target = data["target"]["host"]
    ip = data["target"]["ip"]
    open_ports = data["scan"]["open_ports"]
    dns_data = data.get("dns", {})
    subdomains = data.get("subdomains", [])
    web_info = data.get("web", {})
    discovered_paths = data.get("discovered_paths", [])
    shodan = data.get("external", {}).get("shodan", {})
    greynoise = data.get("external", {}).get("greynoise", {})

    def escape_md(text):
        if not isinstance(text, str):
            text = str(text)
        return text.replace("_", "\\_").replace("*", "\\*").replace("[", "\\[").replace("]", "\\]")

    lines = []

    # Frontmatter YAML
    lines.append("---")
    lines.append(f"title: \"SmartScan - {escape_md(target)}\"")
    lines.append(f"date: {datetime.now().strftime('%Y-%m-%d')}")
    lines.append("tags: [smartscan, reconnaissance, security]")
    lines.append(f"target: {escape_md(target)}")
    lines.append(f"ip: {ip}")
    lines.append("---")
    lines.append("")

    lines.append(f"# 🔍 SmartScan Report: `{target}`")
    lines.append("")
    lines.append(f"- **IP**: `{ip}`")
    lines.append(f"- **Fecha**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("")

    # Resumen ejecutivo
    web_risks = web_info.get("risks", [])
    cve_risks = [p for p in open_ports if p.get("possible_cves")]
    total_risks = len(web_risks) + len(cve_risks)

    if total_risks > 0:
        lines.append("## 🚨 Resumen Ejecutivo")
        lines.append("")
        lines.append("Se detectaron hallazgos de seguridad que requieren atención. "
                     "Se recomienda revisar las secciones de **Riesgos Detectados** y **Recomendaciones**.")
        lines.append("")

    # Métricas
    lines.append("## 📊 Resumen")
    lines.append("")
    lines.append("| Puertos Abiertos | Riesgos Detectados | Subdominios | Rutas Descubiertas |")
    lines.append("|------------------|--------------------|-------------|---------------------|")
    lines.append(f"| {len(open_ports)} | {total_risks} | {len(subdomains)} | {len(discovered_paths)} |")
    lines.append("")

    # Puertos
    lines.append("## 📡 Puertos Abiertos")
    lines.append("")
    if open_ports:
        lines.append("| Puerto | Servicio | Versión | Banner | Estado |")
        lines.append("|--------|----------|---------|--------|--------|")
        for p in open_ports:
            port = p['port']
            service = p.get('detected_service') or p.get('service_guess', 'Unknown')
            version = p.get('version', 'N/A')
            banner = (p.get('banner', 'N/A') or 'N/A')[:50]
            estado = "✅ [INFO]" if not p.get('possible_cves') else "⚠️ [ALTO]"
            lines.append(f"| {port}/tcp | {escape_md(service)} | {escape_md(version)} | `{escape_md(banner)}` | {estado} |")
    else:
        lines.append("✅ [INFO] Ningún puerto abierto detectado.")
    lines.append("")

    # Web
    if web_info:
        lines.append("## 🌐 Análisis Web")
        lines.append("")
        lines.append(f"- **Servidor**: `{web_info.get('server', 'N/A')}`")
        lines.append(f"- **Backend**: `{web_info.get('backend', 'N/A')}`")
        lines.append(f"- **CMS**: `{web_info.get('cms', 'N/A')}`")
        techs = ", ".join(web_info.get("technologies", [])) or "N/A"
        lines.append(f"- **Tecnologías**: {techs}")
        lines.append(f"- **WAF**: `{web_info.get('waf', 'N/A')}`")
        lines.append("")

    # Riesgos
    if total_risks > 0:
        lines.append("## ⚠️ Riesgos Detectados")
        lines.append("")
        for risk in web_risks:
            emoji, label, _, rec = classify_risk(risk)
            lines.append(f"- {emoji} {label} **{escape_md(risk)}**")
            lines.append(f"  > 💡 _Recomendación_: {rec}")
            lines.append("")
        for p in cve_risks:
            cves = ", ".join(p["possible_cves"])
            lines.append(f"- ⚠️ [ALTO] **Puerto {p['port']}**: {escape_md(cves)}")
            lines.append(f"  > 💡 _Recomendación_: {RECOMMENDATIONS['cve_found']}")
            lines.append("")

    # Rutas
    if discovered_paths:
        lines.append("## 📁 Rutas Descubiertas")
        lines.append("")
        for path in discovered_paths:
            sensitive = is_sensitive_path(path)
            emoji = "⚠️" if sensitive else "✅"
            label = "[ALTO]" if sensitive else "[INFO]"
            lines.append(f"- {emoji} {label} `{escape_md(path)}`")
        lines.append("")

    # DNS
    if dns_data:
        lines.append("## 📡 Registros DNS")
        lines.append("")
        for rtype, values in dns_data.items():
            if values:
                values_str = ", ".join(values)
                lines.append(f"- **{rtype}**: `{escape_md(values_str)}`")
        lines.append("")

    # Subdominios
    if subdomains:
        lines.append("## 🌍 Subdominios")
        lines.append("")
        for sub in subdomains:
            lines.append(f"- ✅ [INFO] `{escape_md(sub)}`")
        lines.append("")

    # Inteligencia externa
    if shodan or greynoise:
        lines.append("## 🧠 Inteligencia Externa")
        lines.append("")
        if shodan:
            org = shodan.get("org", "N/A")
            ports_count = len(shodan.get("ports", []))
            vulns_count = len(shodan.get("vulns", []))
            lines.append(f"- 🌐 **Shodan**: `{org}` | Puertos: {ports_count} | Vulnerabilidades: {vulns_count}")
        if greynoise:
            classification = greynoise.get("classification", "unknown").title()
            name = greynoise.get("name", "N/A")
            emoji = "✅" if classification.lower() == "benign" else "⚠️"
            lines.append(f"- {emoji} **GreyNoise**: `{classification}` - `{name}`")
        lines.append("")

    lines.append("---")
    lines.append("📝 Reporte generado por **SmartScan** - Herramienta de reconocimiento ético.")
    lines.append("> ⚠️ Este reporte debe ser validado manualmente antes de su uso en decisiones de seguridad. No garantizamos precisión al 100%.")

    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("\n".join(lines))
