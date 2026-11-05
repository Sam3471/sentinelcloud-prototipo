FROM python:3.10-slim

WORKDIR /app

# Instalar dependencias del sistema operativo (incluyendo nmap)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    nmap \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV PYTHONUNBUFFERED=1

EXPOSE 5000

CMD ["python", "api.py"]