#Imagen oficial de Python 3.11 slim
FROM python:3.11-slim

#Evitamos buffers de Python para que prints aparezcan en tiempo real
ENV PYTHONUNBUFFERED=1

#Directorio de trabajo en el contenedor
WORKDIR /app

#Copiamos los archivos de tu proyecto al contenedor
COPY . /app

#Instalamos dependencias necesarias
RUN pip install --no-cache-dir scapy

#CMD ejecuta tu script al iniciar el contenedor
CMD ["python", "app.py"]
