from reporte import generar_reporte

# Datos de prueba simulando un escaneo real de Nmap
vulnerabilidades_ejemplo = [
    {
        "host": "192.168.1.50",
        "servicio": "microsoft-ds",
        "puerto": 445,
        "causa": "Exposición de SMB Direct/CIFS",
        "cve": "CVE-2020-0796",
        "cvss": 9.8,
        "riesgo": "Crítico"
    },
    {
        "host": "192.168.1.50",
        "servicio": "msrpc",
        "puerto": 135,
        "causa": "Exposición de Microsoft RPC",
        "cve": "CVE-2019-0708",
        "cvss": 8.8,
        "riesgo": "Alto"
    }
]

resumen_ejemplo = {"critico": 1, "alto": 1, "medio": 0, "bajo": 0}
iee_ejemplo = 75
proyeccion_ejemplo = {"1": 45, "2": 65, "3": 80, "5": 95}

# Ejecutar el orquestador completo
if __name__ == "__main__":
    print("🚀 Iniciando generación de reportes y consultas a Supabase...")
    generar_reporte(
        vulnerabilidades_ejemplo, 
        resumen_ejemplo, 
        iee_ejemplo, 
        proyeccion_ejemplo, 
        1500000, 
        8500000
    )