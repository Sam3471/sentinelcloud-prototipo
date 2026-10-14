FROM python:3.11-slim
RUN apt-get update && apt-get install -y nmap && rm -rf /var/lib/apt/lists/*
WORKDIR /app
RUN pip install --no-cache-dir flask requests reportlab
COPY . /app
EXPOSE 5000
CMD ["python", "api.py"]