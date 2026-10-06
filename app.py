"""Captura tráfico TCP/UDP del puerto 8080 y lo guarda en SQLite.

Orientado a una Raspberry Pi: prioriza las interfaces eth0, end0 y wlan0,
y puede correr sin interacción (systemd) o en consola.
El puerto se cambia con la variable de entorno MONITOR_PORT; el valor
por defecto es 8080. La interfaz se fuerza con IFACE.
"""

from collections import Counter
import os
import sqlite3
import sys
import time
from datetime import datetime
import threading
from scapy.all import sniff, IP, IPv6, TCP, UDP, get_if_list

DB_FOLDER = "data"
DB_PATH = f"{DB_FOLDER}/packets.db"
IFACE_PATH = "iface.txt"
DEFAULT_PORT = 8080
# eth0 en Raspberry Pi OS antiguo; end0 con nombres predecibles (Bookworm); wlan0 es el wifi.
PI_IFACES = ("eth0", "end0", "wlan0")
BUFFER_SIZE = 100
STATS_INTERVAL = 2

try:
    sys.stdout.reconfigure(line_buffering=True)
except Exception:
    pass


def read_monitor_port():
    raw = os.environ.get("MONITOR_PORT", str(DEFAULT_PORT)).strip()
    try:
        port = int(raw)
    except ValueError:
        print(f"❌ MONITOR_PORT inválido: {raw}")
        sys.exit(1)
    if not 1 <= port <= 65535:
        print(f"❌ MONITOR_PORT fuera de rango: {port}")
        sys.exit(1)
    return port


MONITOR_PORT = read_monitor_port()

total_packets = 0
inbound = 0
outbound = 0
local = 0
protocols = Counter()
ips_src = Counter()
ips_dst = Counter()
peers = Counter()
buffer = []
stop_sniffing_flag = False
sniff_error = None
iface_id = None
state_lock = threading.Lock()

os.makedirs(DB_FOLDER, exist_ok=True)
conn = sqlite3.connect(DB_PATH, check_same_thread=False)
cursor = conn.cursor()
cursor.execute('''
CREATE TABLE IF NOT EXISTS packets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    date TEXT,
    src_ip TEXT,
    dst_ip TEXT,
    protocol TEXT,
    length INTEGER,
    interface TEXT,
    src_port INTEGER,
    dst_port INTEGER
)
''')
existing_cols = {row[1] for row in cursor.execute("PRAGMA table_info(packets)")}
for col in ("src_port", "dst_port"):
    if col not in existing_cols:
        cursor.execute(f"ALTER TABLE packets ADD COLUMN {col} INTEGER")
conn.commit()


def direction_of(sport, dport):
    to_port = dport == MONITOR_PORT
    from_port = sport == MONITOR_PORT
    if to_port and from_port:
        return "LOCAL"
    if to_port:
        return "ENTRANTE"
    if from_port:
        return "SALIENTE"
    return None


def snapshot():
    return {
        "total": total_packets,
        "inbound": inbound,
        "outbound": outbound,
        "local": local,
        "protocols": protocols.most_common(),
        "ips_src": ips_src.most_common(5),
        "ips_dst": ips_dst.most_common(5),
        "peers": peers.most_common(5),
        "iface": iface_id,
    }


def render(snap):
    if sys.stdout.isatty():
        os.system("clear")
    print("=" * 60)
    print(f"          📊 Tráfico del puerto {MONITOR_PORT} 📊")
    print("=" * 60)
    print(f"Interfaz: {snap['iface'] or '-'}")
    print(f"Filtro:   port {MONITOR_PORT} (TCP/UDP, origen o destino)")
    print(f"Total de paquetes capturados: {snap['total']}")
    print(f"Entrantes (destino {MONITOR_PORT}): {snap['inbound']}")
    print(f"Salientes (origen  {MONITOR_PORT}): {snap['outbound']}")
    print(f"Locales   (ambos puertos):        {snap['local']}\n")

    print("Paquetes por protocolo")
    print("-" * 30)
    if snap["protocols"]:
        for proto, count in snap["protocols"]:
            print(f"{proto:<10} | {count:>5}")
    else:
        print("(sin paquetes todavía)")
    print()

    print("Top 5 equipos remotos")
    print("-" * 30)
    if snap["peers"]:
        for ip, count in snap["peers"]:
            print(f"{ip:<20} | {count:>5}")
    else:
        print("(sin paquetes todavía)")
    print()

    print("Top 5 IPs origen")
    print("-" * 30)
    for ip, count in snap["ips_src"]:
        print(f"{ip:<20} | {count:>5}")
    print()

    print("Top 5 IPs destino")
    print("-" * 30)
    for ip, count in snap["ips_dst"]:
        print(f"{ip:<20} | {count:>5}")
    print("=" * 60)
    if sys.stdout.isatty():
        print("\nPresione Ctrl+C para detener la captura y salir.")


def log_line(snap):
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(
        f"[{stamp}] puerto {MONITOR_PORT} iface={snap['iface']} "
        f"total={snap['total']} entrantes={snap['inbound']} "
        f"salientes={snap['outbound']} locales={snap['local']}"
    )


def flush_buffer():
    global buffer
    if buffer:
        cursor.executemany('''
            INSERT INTO packets (
                date, src_ip, dst_ip, protocol, length, interface, src_port, dst_port
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', buffer)
        conn.commit()
        buffer.clear()


def packet_meta(packet):
    if packet.haslayer(IP):
        src = packet[IP].src
        dst = packet[IP].dst
    elif packet.haslayer(IPv6):
        src = packet[IPv6].src
        dst = packet[IPv6].dst
    else:
        return None

    sport = dport = None
    proto = "OTRO"
    if packet.haslayer(TCP):
        proto = "TCP"
        sport = int(packet[TCP].sport)
        dport = int(packet[TCP].dport)
    elif packet.haslayer(UDP):
        proto = "UDP"
        sport = int(packet[UDP].sport)
        dport = int(packet[UDP].dport)
    else:
        return None

    direction = direction_of(sport, dport)
    if direction is None:
        return None

    if direction == "SALIENTE":
        remote = dst
    else:
        remote = src

    return {
        "proto": proto,
        "sport": sport,
        "dport": dport,
        "direction": direction,
        "src": src,
        "dst": dst,
        "remote": remote,
        "length": len(packet),
    }


def packet_callback(packet):
    global total_packets, inbound, outbound, local
    meta = packet_meta(packet)
    if meta is None:
        return

    with state_lock:
        total_packets += 1
        if meta["direction"] == "ENTRANTE":
            inbound += 1
        elif meta["direction"] == "SALIENTE":
            outbound += 1
        else:
            local += 1

        protocols[meta["proto"]] += 1
        ips_src[meta["src"]] += 1
        ips_dst[meta["dst"]] += 1
        peers[meta["remote"]] += 1

        buffer.append((
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            meta["src"],
            meta["dst"],
            meta["proto"],
            meta["length"],
            iface_id,
            meta["sport"],
            meta["dport"],
        ))

        if len(buffer) >= BUFFER_SIZE:
            flush_buffer()


def load_interfaces(file_path=IFACE_PATH):
    interfaces = []
    seen = set()
    if not os.path.exists(file_path):
        return interfaces
    with open(file_path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "," not in line:
                continue
            iface, ip = line.split(",", 1)
            iface = iface.strip()
            ip = ip.strip()
            if not iface or iface in seen:
                continue
            seen.add(iface)
            interfaces.append((iface, ip))
    return interfaces


def iface_usable(name):
    if not name or name == "lo":
        return False
    return not name.startswith(("docker", "br-", "veth", "virbr"))


def first_available(preferred=None):
    available = list(get_if_list())
    available_set = set(available)
    ordered = []
    if preferred:
        ordered.append(preferred)
    ordered.extend(PI_IFACES)
    for candidate in ordered:
        if candidate in available_set:
            return candidate
    for candidate in available:
        if iface_usable(candidate):
            return candidate
    return None


def select_interface(file_path=IFACE_PATH):
    env_iface = os.environ.get("IFACE", "").strip()
    if env_iface:
        chosen = first_available(env_iface)
        if chosen != env_iface:
            print(f"⚠️ La interfaz '{env_iface}' no está disponible.")
        if chosen is None:
            print("❌ No hay una interfaz de red utilizable.")
            sys.exit(1)
        print(f"📡 Interfaz seleccionada: {chosen}")
        return chosen

    interfaces = [(iface, ip) for iface, ip in load_interfaces(file_path) if iface_usable(iface)]

    def pick_preferred():
        for pref in PI_IFACES:
            for iface, ip in interfaces:
                if iface == pref:
                    return iface, ip
        return interfaces[0]

    if not interfaces:
        print(f"❌ No se encontró {file_path} con interfaces utilizables.")
        print("Se busca una interfaz de la Raspberry (eth0, end0 o wlan0).")
        chosen = first_available("eth0")
        if chosen is None:
            print("❌ No hay una interfaz de red utilizable.")
            sys.exit(1)
        print(f"📡 Interfaz seleccionada: {chosen}")
        return chosen

    # Sin TTY (systemd) o con una sola interfaz no hay nada que preguntar.
    if len(interfaces) == 1 or not sys.stdin.isatty():
        iface, ip = pick_preferred()
        print(f"📡 Interfaz automática: {iface} ({ip})")
        chosen = first_available(iface)
        if chosen is None:
            print("❌ No hay una interfaz de red utilizable.")
            sys.exit(1)
        if chosen != iface:
            print(f"⚠️ '{iface}' no está en esta máquina. Usando '{chosen}'.")
        return chosen

    print("=== Interfaces de red disponibles ===")
    for i, (iface, ip) in enumerate(interfaces):
        print(f"[{i}] {iface} ({ip})")
    try:
        selection = int(input("Seleccione el número de la interfaz: ").strip())
        iface, _ip = interfaces[selection]
    except (ValueError, IndexError, EOFError):
        iface, _ip = pick_preferred()
        print(f"❌ Selección inválida. Usando '{iface}'.")

    chosen = first_available(iface)
    if chosen is None:
        print("❌ No hay una interfaz de red utilizable.")
        sys.exit(1)
    if chosen != iface:
        print(f"⚠️ La interfaz '{iface}' no está disponible. Usando '{chosen}'.")
    else:
        print(f"📡 Interfaz seleccionada: {chosen}")
    return chosen


def sniff_thread(iface):
    global stop_sniffing_flag, sniff_error
    bpf = f"port {MONITOR_PORT}"
    try:
        while not stop_sniffing_flag:
            sniff(
                iface=iface,
                filter=bpf,
                prn=packet_callback,
                store=False,
                timeout=1,
            )
    except Exception as exc:
        sniff_error = str(exc)
        stop_sniffing_flag = True


def main():
    global iface_id, stop_sniffing_flag

    if hasattr(os, "geteuid") and os.geteuid() != 0:
        print("⚠️ La captura en la Raspberry requiere root (sudo) o CAP_NET_RAW.")

    iface_id = str(select_interface())
    print(f"📡 Capturando tráfico del puerto {MONITOR_PORT} en {iface_id}")
    print("   Solo TCP/UDP con origen o destino en ese puerto. Ctrl+C para detener.")

    thread = threading.Thread(target=sniff_thread, args=(iface_id,), daemon=True)
    thread.start()
    last_log = 0.0

    try:
        while thread.is_alive():
            with state_lock:
                snap = snapshot()
            if sys.stdout.isatty():
                render(snap)
            else:
                now = time.time()
                if now - last_log >= 30:
                    log_line(snap)
                    last_log = now
            thread.join(timeout=STATS_INTERVAL)
    except KeyboardInterrupt:
        stop_sniffing_flag = True

    thread.join(timeout=2)
    with state_lock:
        flush_buffer()
        snap = snapshot()

    if sys.stdout.isatty():
        render(snap)
    else:
        log_line(snap)

    if sniff_error:
        print(f"❌ No se pudo capturar en {iface_id}: {sniff_error}")
        print("   En la Raspberry: sudo ./run.sh --native")
        print("   En Docker: --net=host y --cap-add=NET_RAW --cap-add=NET_ADMIN")
        sys.exit(1)

    print("\n--- Captura finalizada ---\n")


if __name__ == "__main__":
    main()
