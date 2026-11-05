from flask import Flask, request, jsonify, render_template
import subprocess, json
import xml.etree.ElementTree as ET
import requests

app = Flask(__name__)

# Cache simple para evitar muchas llamadas a la API de CVE
cache_cve = {}

# ---------------------------
# HOME (interfaz web)
# ---------------------------
@app.route('/')
def home():
    return render_template("index.html")


# ---------------------------
# EJECUTAR NMAP
# ---------------------------
def ejecutar_nmap(ip):
    try:
        comando = ["nmap", "-sV", "-oX", "-", ip]
        resultado = subprocess.run(comando, capture_output=True, text=True)

        root = ET.fromstring(resultado.stdout)

        puertos = []

        for port in root.findall(".//port"):
            estado = port.find("state").get("state")

            if estado == "open":
                servicio = port.find("service")

                nombre = servicio.get("name") if servicio is not None else "unknown"
                version = servicio.get("version") if servicio is not None else "unknown"

                puertos.append({
                    "puerto": port.get("portid"),
                    "servicio": nombre,
                    "version": version
                })

        return {
            "status": "ok",
            "ip": ip,
            "puertos_abiertos": puertos
        }

    except Exception as e:
        import traceback
        error_detallado = traceback.format_exc()
        print("--- ERROR DETALLADO EN NMAP ---")
        print(error_detallado)
        return {
            "status": "error",
            "mensaje": str(e),
            "detalle": error_detallado
        }


# ---------------------------
# BUSCAR CVE (NVD API)
# ---------------------------
def buscar_cve(servicio, version):
    try:
        if version == "unknown":
            return "N/A", 4.0

        clave = f"{servicio}-{version}"

        # CACHE
        if clave in cache_cve:
            return cache_cve[clave]

        query = f"{servicio} {version}"
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={query}"

        response = requests.get(url, timeout=5)
        data = response.json()

        if "vulnerabilities" in data and data["vulnerabilities"]:
            item = data["vulnerabilities"][0]["cve"]

            cve = item["id"]

            metrics = item.get("metrics", {})
            cvss = 5.0

            if "cvssMetricV31" in metrics:
                cvss = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]

            cache_cve[clave] = (cve, cvss)
            return cve, cvss

        cache_cve[clave] = ("N/A", 4.0)
        return "N/A", 4.0

    except Exception as e:
        print("Error CVE:", e)
        return "N/A", 4.0


# ---------------------------
# CONVERTIR AL FORMATO
# ---------------------------
def convertir_a_vulnerabilidades(ip, puertos):
    vulnerabilidades = []

    for p in puertos:
        puerto = p["puerto"]
        servicio = p["servicio"]
        version = p.get("version", "unknown")

        cve, cvss = buscar_cve(servicio, version)

        vulnerabilidades.append({
            "host": ip,
            "servicio": servicio,
            "version": version,
            "puerto": int(puerto),
            "cve": cve,
            "cvss": cvss,
            "descripcion": f"Servicio {servicio} expuesto en puerto {puerto}"
        })

    return {"vulnerabilidades": vulnerabilidades}


# ---------------------------
# ENDPOINT PRINCIPAL
# ---------------------------
@app.route('/scan', methods=['GET'])
def scan():
    print("--- [DEBUG] 1. Entrando a /scan ---")
    ip = request.args.get('ip')
    print(f"--- [DEBUG] 2. IP recibida: {ip} ---")

    if not ip:
        return jsonify({"status": "error", "mensaje": "Falta parámetro ip"}), 400

    # 1. Ejecutar Nmap
    print("--- [DEBUG] 3. A punto de ejecutar ejecutar_nmap() ---")
    resultado = ejecutar_nmap(ip)
    print(f"--- [DEBUG] 4. Resultado de Nmap: {resultado} ---")

    if resultado["status"] == "error":
        return jsonify(resultado), 500

    # 2. Convertir al formato
    print("--- [DEBUG] 5. A punto de convertir a vulnerabilidades ---")
    data_ecem = convertir_a_vulnerabilidades(ip, resultado["puertos_abiertos"])

    # 3. Guardar JSON
    print("--- [DEBUG] 6. Guardando input_ecem.json ---")
    with open("input_ecem.json", "w") as f:
        json.dump(data_ecem, f, indent=4)

    # 4. Ejecutar motor en segundo plano
    print("--- [DEBUG] 7. Lanzando subprocess para main.py ---")
    subprocess.Popen(
        ["python", "main.py", "input_ecem.json"],
        stdout=open("log.txt", "a"),
        stderr=open("error.txt", "a")
    ) 

    print("--- [DEBUG] 8. Todo OK, respondiendo al frontend ---")
    return jsonify({
        "status": "ok",
        "mensaje": "Escaneo iniciado. Recibirás el reporte por correo.",
        "puertos_detectados": resultado["puertos_abiertos"]
    })


# ---------------------------
# RUN
# ---------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)