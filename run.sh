#!/bin/bash

#Generar lista de interfaces con IP valida
> iface.txt
for iface in $(ifconfig -a | grep -E '^[a-z0-9]' | awk '{print $1}' | sed 's/://'); do
    ip=$(ifconfig $iface | grep "inet " | awk '{print $2}')
    if [ ! -z "$ip" ]; then
        echo "$iface,$ip" >> iface.txt
    fi
done

echo "✅ iface.txt generado"

#Crear carpeta para almacenar base de datos
mkdir -p data
chmod 777 data

#Ejecutar el contenedor y montar iface.txt
docker run -it \
    --net=host \
    --cap-add=NET_ADMIN \
    -v "$(pwd)/iface.txt:/app/iface.txt" \
    -v "$(pwd)/data:/app/data" \
    sniffer-lite