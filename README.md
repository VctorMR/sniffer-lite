# 📡 sniffer-lite — Analizador de Tráfico de Red

`sniffer-lite` captura **solo el tráfico TCP/UDP del puerto 8080** en una interfaz de red, lo guarda en **SQLite** y muestra estadísticas en consola. Está pensado para correr en una **Raspberry Pi** (nativo o en Docker).

El puerto por defecto es **8080**. Se cambia con `MONITOR_PORT` sin tocar el código. La interfaz se elige sola entre `eth0`, `end0` y `wlan0`, o se fuerza con `IFACE`.

Solo ve el tráfico de la propia Raspberry. Para observar otros equipos, la Pi tiene que ser la puerta de enlace o recibir una copia del puerto (mirror) en el switch.

---

## Contenido

- `app.py` — captura, filtro del puerto 8080, buffer, SQLite y estadísticas.
- `requirements.txt` — Scapy.
- `Dockerfile` — `python:3.11-slim` (arm64/armv7) con libpcap.
- `run.sh` — genera `iface.txt` y arranca en nativo o en Docker.
- `sniffer-lite.service` — unidad de systemd para dejarlo corriendo en la Pi.
- `run.ps1` — el mismo arranque Docker desde Windows.
- `data/` — se crea al vuelo; ahí queda `packets.db`.
- `iface_sample.txt` — ejemplo del listado de interfaces.

---

## Raspberry Pi (recomendado)

Raspberry Pi OS trae Python y, si hace falta, Scapy por apt (en Bookworm `pip` suele estar bloqueado):

```bash
sudo apt update
sudo apt install -y python3-scapy tcpdump
sudo ./run.sh --native
```

Forzar el cable de una Pi con Raspberry Pi OS Bookworm, que nombra la interfaz `end0`:

```bash
sudo IFACE=end0 MONITOR_PORT=8080 ./run.sh --native
```

`eth0` es el nombre en imágenes anteriores. `wlan0` es el wifi. Si no defines `IFACE` y hay varias interfaces, en una consola el programa pregunta; sin TTY (o con una sola) elige `end0`, `eth0` o `wlan0` en ese orden de preferencia.

La captura pide root. Sin `sudo` Scapy no puede abrir la interfaz.

### Dejarlo como servicio

```bash
sudo mkdir -p /opt/sniffer-lite
sudo cp app.py /opt/sniffer-lite/
sudo cp sniffer-lite.service /etc/systemd/system/
# edita WorkingDirectory e IFACE si la ruta o la interfaz no coinciden
sudo systemctl daemon-reload
sudo systemctl enable --now sniffer-lite
journalctl -u sniffer-lite -f
```

Cada 30 segundos escribe una línea con el total y cuántos paquetes entran o salen del puerto 8080. La base queda en `/opt/sniffer-lite/data/packets.db`.

---

## Docker

La imagen oficial sirve en una Raspberry Pi 3 o superior (64 bits, o 32 bits armhf). El Pi Zero original es ARMv6 y no puede construir `python:3.11-slim`; en ese modelo usa el modo nativo.

```bash
docker build -t sniffer-lite .
sudo ./run.sh
```

`run.sh` publica la red del host (`--net=host`) y añade `NET_RAW` y `NET_ADMIN`, que hacen falta para capturar. `libpcap` dentro de la imagen aplica el filtro `port 8080` en el kernel.

---

## Qué se guarda

Cada paquete del puerto 8080 entra en `data/packets.db`, tabla `packets`: fecha, IPs, protocolo, tamaño, interfaz, puerto de origen y puerto de destino. Una base creada con una versión anterior del programa se migra sola (se agregan `src_port` y `dst_port`).

En consola se separan:

- **Entrantes** — alguien se conecta al puerto 8080 de la Pi.
- **Salientes** — la Pi abre una conexión desde el puerto 8080.
- **Locales** — origen y destino son 8080.

El resto del tráfico no se cuenta ni se escribe.

---

## Variables

| Variable | Defecto | Uso |
| --- | --- | --- |
| `MONITOR_PORT` | `8080` | Puerto TCP/UDP a vigilar (origen o destino). |
| `IFACE` | automática | `eth0`, `end0`, `wlan0`, etc. |

---

## Windows

`run.ps1` genera `iface.txt` y lanza el mismo contenedor, también filtrando el puerto 8080.
