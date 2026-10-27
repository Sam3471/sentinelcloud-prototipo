# Usamos una imagen oficial de Python ligera y estable
FROM python:3.10-slim

# Directorio de trabajo dentro del contenedor
WORKDIR /app

# Instalamos dependencias del sistema esenciales (por si alguna librería de Python requiere compilación)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copiamos e instalamos las dependencias de Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiamos todo el código fuente del proyecto al contenedor
COPY . .

# El comando por defecto ejecutará el main pasándole el JSON de escaneo
ENTRYPOINT ["python", "main.py"]