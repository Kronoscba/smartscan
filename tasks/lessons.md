# Lecciones aprendidas

## Sesión 1 — Limpieza pre-GitHub

- **Nunca commitear reportes de escaneo reales** — aunque el target sea de prueba (`testphp.vulnweb.com`), quedan IPs, banners, rutas y tokens en el historial para siempre. Purgarlos requiere reescribir git history.
- **`.gitignore` primero** — antes del primer commit, asegurarse de que `*.html`, `*.md`, `.obsidian/`, `reportes/` estén ignorados.
- **Código muerto** — `utils.py` vacío se cuela fácil. Revisar que cada archivo en el repo tenga razón de existir.
- **Stash + amend** funciona para purgar archivos de un commit inicial sin perder cambios en curso.
- **Dos entry points (smartscan.py + smartscan/cli.py)** — legacy que confunde. Decidir pronto si se elimina o se mantiene como referencia.
- **Flags de CLI que no conectan con la función** — `--stealth` existía en argparse pero nunca se pasaba a `scan_ports`. Revisar que cada flag realmente haga algo.
- **Datos recolectados vs mostrados** — `security_headers` se recolectaba en `web.py` pero no se renderizaba en ningún reporte. Siempre verificar el pipeline completo: recolección → salida.

## Sesión 2 — Interfaz web + refactor

- **Runner pattern** — extraer la lógica de escaneo a un `runner.py` permite que CLI y Web compartan el mismo código sin duplicar. El CLI queda como una capa fina de parseo + presentación.
- **FastAPI + HTMX** — para una herramienta de seguridad, HTMX evita cargar un framework JS pesado. La interactividad sale del backend, que ya tiene toda la lógica.
- **`TemplateResponse(request, name, context)`** — Starlette espera `request` como primer argumento, no el nombre del template. Pasar el orden incorrecto da `TypeError: unhashable type: 'dict'` porque el dict termina siendo usado como key del cache de Jinja2.
- **Polling con HTMX** — `hx-trigger="every 1s"` + `hx-swap="outerHTML"` permite reemplazar un fragmento completo en cada tick, lo que da progreso en vivo sin escribir una línea de JS.
- **Historial en archivos** — guardar scans como JSON en `scans/` permite persistencia sin base de datos. Para un MVP alcanza, pero escalando habría que migrar a SQLite.
- **Sitios de prueba caídos** — `testphp.vulnweb.com` puede estar offline. Siempre tener un plan B (`scanme.nmap.org`) para validar el scanner.
