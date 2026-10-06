# python:3.11-slim publica manifiestos arm64 y armv7: se construye en una
# Raspberry Pi 3 o superior con Raspberry Pi OS de 64 bits (o 32 bits armhf).
# El Pi Zero original (ARMv6) no puede usar esta imagen; ahí corre en nativo.
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    MONITOR_PORT=8080

WORKDIR /app

# libpcap aplica el filtro BPF "port 8080" en el kernel. Sin esto Scapy
# no puede filtrar y la captura falla o ve todo el tráfico.
RUN apt-get update \
    && apt-get install -y --no-install-recommends libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY . /app

CMD ["python", "app.py"]
