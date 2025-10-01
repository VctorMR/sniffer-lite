# 📡 sniffer-lite — Analizador de Tráfico de Red

**Resumen:**  
`sniffer-lite` es una aplicación en **Python** que captura paquetes de red desde una interfaz especificada, almacena los registros en **SQLite** y muestra estadísticas básicas en consola. Está preparada para ejecutarse dentro de **Docker** y fue diseñada para ser simple, entendible y fácil de entregar en un reto técnico.

---

## Contenido
- `app.py` — código principal (captura, buffer, almacenamiento y estadísticas).  
- `Dockerfile` — imagen base `python:3.11-slim` con Scapy.  
- `run.sh` — script Linux/macOS para generar `iface.txt`, crear `data/` y ejecutar Docker.  
- `run.ps1` — script PowerShell (Windows) equivalente.  
- `data/` — carpeta montada (persistencia de `packets.db`).  
- `iface_sample.txt` — Ejemplo de archivo generado que lista interfaces del host (alias,ip).

---

## Requisitos
- Docker instalado (Linux, macOS, Windows).  
- (Opcional para pruebas local) Python 3.9+ y `scapy` si vas a ejecutar `app.py` sin Docker.

---

## Construir la imagen Docker
Desde la carpeta del proyecto (donde está el `Dockerfile`):

```bash
docker build -t sniffer-lite .