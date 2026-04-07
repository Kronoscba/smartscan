# 🔍 SmartScan

> **Escáner inteligente de reconocimiento ético**\
> Descubre puertos abiertos, subdominios, rutas sensibles, CVEs, huellas web y
> más — todo en un solo comando.

## ![Python](https://img.shields.io/badge/Python-3.9+-blue.svg) ![uv](https://img.shields.io/badge/aiohttp-3.9.0-pink) ![aiodns](https://img.shields.io/badge/aiodns-3.1.1-camel) ![Shodan](https://img.shields.io/badge/shodan-1.30.0-brown.svg) ![Greynoise](https://img.shields.io/badge/greynoise-2.0.0-5f50c7.svg) ![Version](https://img.shields.io/badge/dnspython-2.8.0-c76d50.svg) ![httpx](https://img.shields.io/badge/httpx-0.28.1-234f10.svg) ![jinja2](https://img.shields.io/badge/jinja2-3.1.6-26030b.svg) ![Security](https://img.shields.io/badge/Security-Penetration_Security-8A2BE2) ![License](https://img.shields.io/badge/License-MIT-green.svg)

## 🚀 Ejemplo rápido

```
smartscan -H example.com --report escaneo_example
```

🛠️ Características

- **Puertos inteligentes**: Escaneo asíncrono rápido con detección de servicio
- **Web Fingerprinting**: CMS, servidor, backend, WAF, tecnologías
- **Rutas sensibles**: Detección de `.git`, `admin`, `backup`, etc.
- **CVEs automáticos**: Búsqueda de vulnerabilidades conocidas
- **Inteligencia externa**: Integración con **Shodan** y **GreyNoise**
- **DNS + Subdominios**: Registros A, MX, TXT y enumeración
- **Reportes duales**:
  - 📄 **HTML**: Profesional, con colores por severidad
  - 📝 **Markdown**: Con frontmatter YAML para Obsidian

---

📦 Instalación

```
git clone https://github.com/Kronoscba/smartscan.git
cd smartscan
uv sync --all-extras
```

> Requiere [uv](https://docs.astral.sh/uv/) y Python 3.10+.

---

 🎯 Uso

# Escaneo completo
```
smartscan -H example.com -d -s -c --shodan TU_API_KEY --report resultado
```
# Solo web y rutas
```
 smartscan -H example.com --web --report web
```

# Ayuda
```
smartscan --help
```

---

⚖️ Ética

Este software es para **pruebas de seguridad autorizadas**.\
⚠️ **Nunca lo uses sin permiso explícito.**

---

## 🧑‍💻 ¿Te gusta?

¡Dale una ⭐ si te resulta útil!
