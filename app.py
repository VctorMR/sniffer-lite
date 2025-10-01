from collections import Counter
import os
import sqlite3
from datetime import datetime
import threading
from scapy.all import sniff, IP, TCP, UDP, ICMP, get_if_list

DB_FOLDER = "data"
DB_PATH = f"{DB_FOLDER}/packets.db"
IFACE_PATH="iface.txt"

total_packets = 0
protocols = Counter()
ips_src = Counter()
ips_dst = Counter()
BUFFER_SIZE = 100
buffer = []
stop_sniffing_flag = False
iface_id = None

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
    interface TEXT
)
''')
conn.commit()

def print_stats():
    os.system("clear")
    print("=" * 60)
    print("               📊 Estadisticas de trafico 📊               ")
    print("=" * 60)
    print(f"Total de paquetes capturados: {total_packets}\n")

    #Protocolos
    print("Paquetes por Protocolo")
    print("-" * 30)
    for proto, count in protocols.items():
        print(f"{proto:<10} | {count:>5}")
    print()

    #Top 5 IPs origen
    print("Top 5 IPs Origen")
    print("-" * 30)
    for ip, count in ips_src.most_common(5):
        print(f"{ip:<20} | {count:>5}")
    print()

    #Top 5 IPs destino
    print("Top 5 IPs Destino")
    print("-" * 30)
    for ip, count in ips_dst.most_common(5):
        print(f"{ip:<20} | {count:>5}")
    print("=" * 60)
    #Mensaje de salida
    print("\nPresione Ctrl+C para detener la captura y salir.")

def flush_buffer():
    global buffer
    if buffer:
        cursor.executemany('''
            INSERT INTO packets (date, src_ip, dst_ip, protocol, length, interface)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', buffer)
        conn.commit()
        buffer.clear()

def packet_callback(packet):
    global total_packets

    if packet.haslayer(IP):
        total_packets += 1

        #Identificar protocolo
        proto = "OTRO"
        if packet.haslayer(TCP):
            proto = "TCP"
        elif packet.haslayer(UDP):
            proto = "UDP"
        elif packet.haslayer(ICMP):
            proto = "ICMP"

        protocols[proto] += 1
        ips_src[packet[IP].src] += 1
        ips_dst[packet[IP].dst] += 1

        buffer.append((
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            packet[IP].src,
            packet[IP].dst,
            proto,
            len(packet),
            iface_id
        ))

        if len(buffer) >= BUFFER_SIZE:
            flush_buffer()
        if total_packets % 25 == 0:
            print_stats()

def select_interface(file_path=IFACE_PATH):
    if not os.path.exists(file_path):
        print(f"❌ No se encontro {file_path}.")
        print("Se ejecuta en interfaz por defecto.")
        return "eth0"

    #Almacenar en lista iface.txt
    interfaces = []
    with open(file_path) as f:
        for line in f:
            iface, ip = line.strip().split(",")
            interfaces.append((iface, ip))

    print("=== Interfaces de red disponibles ===")
    for i, (iface, ip) in enumerate(interfaces):
        print(f"[{i}] {iface} ({ip})")
    try:
        selection = int(input("Seleccione el número de la interfaz: ").strip())
        iface_selected = interfaces[selection]

    except (ValueError, IndexError):
        print("❌ Selección inválida. Usando 'eth0' por defecto.")
        iface_selected = "eth0"
    #Ajuste de tipo de variable
    iface_name = iface_selected[0]
    # Validar que la interfaz exista dentro del contenedor
    if iface_name not in get_if_list():
        print(f"⚠️ La interfaz '{iface_name}' no está disponible. Usando 'eth0'.")
        iface_name = "eth0"

    print(f"📡 Interfaz seleccionada: {iface_name}")
    return iface_name

def sniff_thread(iface):
    global stop_sniffing_flag
    while not stop_sniffing_flag:
        sniff(iface=iface,
              prn=packet_callback,
              store=False,
              timeout=1  # timeout corto para revisar flag
              )

def main():
    iface_name = select_interface()
    global iface_id
    iface_id = str(iface_name)
    print(f"\n📡 Capturando paquetes en la interfaz: {iface_id} (Ctrl+C para detener)\n")

    # Crear y arrancar hilo de proceso sniff
    thread = threading.Thread(target=sniff_thread, args=(iface_id,), daemon=True)
    thread.start()

    try:
        while True:
            while thread.is_alive():
                thread.join(timeout=1)  # espera, pero permite capturar Ctrl+C
    except KeyboardInterrupt:
        flush_buffer()
        print_stats()
        print("\n\n--- Captura finalizada ---\n\n")
        exit(0)
if __name__ == "__main__":
    main()
