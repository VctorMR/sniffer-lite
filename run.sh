#!/bin/bash
# En la Raspberry (recomendado):
#   sudo ./run.sh --native
# Con Docker (Pi 3+ / 64 bits, o cualquier PC):
#   docker build -t sniffer-lite .
#   sudo ./run.sh
# Puerto (por defecto 8080) e interfaz:
#   sudo MONITOR_PORT=8080 IFACE=end0 ./run.sh --native

set -euo pipefail

cd "$(dirname "$0")"

MONITOR_PORT="${MONITOR_PORT:-8080}"
export MONITOR_PORT

: > iface.txt
if command -v ip >/dev/null 2>&1; then
    # iproute2 viene en Raspberry Pi OS. ifconfig (net-tools) a menudo no.
    ip -4 -o addr show | awk '{
        iface = $2
        split($4, a, "/")
        ipaddr = a[1]
        if (ipaddr != "" && iface != "lo") print iface "," ipaddr
    }' >> iface.txt
elif command -v ifconfig >/dev/null 2>&1; then
    for iface in $(ifconfig -a | grep -E '^[a-z0-9]' | awk '{print $1}' | sed 's/://'); do
        # awk y no grep: con 'set -e' grep sin coincidencia abortaría el script
        # en interfaces sin IPv4 (gif0, bridges, etc.).
        ipaddr=$(ifconfig "$iface" | awk '/inet / {print $2; exit}')
        if [ -n "$ipaddr" ] && [ "$ipaddr" != "127.0.0.1" ]; then
            echo "$iface,$ipaddr" >> iface.txt
        fi
    done
else
    echo "❌ No se encontró 'ip' ni 'ifconfig'." >&2
    exit 1
fi

echo "✅ iface.txt generado (puerto a monitorear: ${MONITOR_PORT})"

mkdir -p data
chmod 777 data

mode="${1:-}"

if [ "$mode" = "--native" ]; then
    if ! python3 -c "import scapy" >/dev/null 2>&1; then
        echo "❌ Falta scapy. En la Raspberry:" >&2
        echo "   sudo apt update && sudo apt install -y python3-scapy tcpdump" >&2
        exit 1
    fi
    echo "📡 Modo nativo. Solo se captura TCP/UDP del puerto ${MONITOR_PORT}."
    if [ "$(id -u)" -eq 0 ]; then
        exec python3 app.py
    fi
    exec sudo -E python3 app.py
fi

if [ -n "$mode" ] && [ "$mode" != "--docker" ]; then
    echo "Uso: $0 [--native | --docker]" >&2
    exit 1
fi

echo "📡 Modo Docker. Solo se captura TCP/UDP del puerto ${MONITOR_PORT}."
echo "   En la Raspberry hace falta sudo si tu usuario no está en el grupo docker."

docker_args=(
    run -it
    --net=host
    --cap-add=NET_ADMIN
    --cap-add=NET_RAW
    -e "MONITOR_PORT=${MONITOR_PORT}"
    -v "$(pwd)/iface.txt:/app/iface.txt"
    -v "$(pwd)/data:/app/data"
)
if [ -n "${IFACE:-}" ]; then
    docker_args+=(-e "IFACE=${IFACE}")
fi
docker_args+=(sniffer-lite)

docker "${docker_args[@]}"
