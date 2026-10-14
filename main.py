# main.py

import json
import sys
sys.stdout.reconfigure(encoding='utf-8')

from motor_ecem import analizar_vulnerabilidades
from motor_ecem import generar_estadisticas
from reporte import generar_reporte
from motor_ecem import calcular_iee
from enviar_reporte import enviar_reporte
from motor_ecem import calcular_riesgo_empresarial
from motor_ecem import proyeccion_incidentes
from reporte import generar_glosario

# leer archivo desde CLI
archivo = sys.argv[1]

# abrir archivo JSON
with open(archivo) as f:
    data = json.load(f)

# obtener lista de vulnerabilidades
vulnerabilidades = data["vulnerabilidades"]

# mostrar vulnerabilidades cargadas
print("Vulnerabilidades detectadas:\n")

for v in vulnerabilidades:
    print(v["host"], v["servicio"], v["cve"], v["cvss"])

# analizar vulnerabilidades con el motor ECEM
resultados = analizar_vulnerabilidades(vulnerabilidades)

# generar estadísticas del sistema
resumen, iee = generar_estadisticas(resultados)

prob_anual, costo_min, costo_max = calcular_riesgo_empresarial(resultados)
proyeccion = proyeccion_incidentes(prob_anual)

print("\nResultados del análisis:\n")

for r in resultados:
    print(r["host"], r["cve"], "→ Riesgo:", r["riesgo"])

print("\nIndice de Exposición Empresarial:", iee, "/100")

print("\nRIESGO EMPRESARIAL ESTIMADO\n")

print("Probabilidad de incidente en 1 año:", proyeccion["1"],"%")
print("Probabilidad en 2 años:", proyeccion["2"],"%")
print("Probabilidad en 3 años:", proyeccion["3"],"%")
print("Probabilidad en 5 años:", proyeccion["5"],"%")

print("\nCosto potencial estimado:")
print("Entre $",costo_min,"y $",costo_max,"CLP")


# guardar archivo de análisis
with open("analisis_ecem.json","w") as f:
    json.dump(resultados,f,indent=4)

# generar reporte PDF
generar_reporte(resultados, resumen, iee, proyeccion, costo_min, costo_max)
generar_glosario()

print("\nArchivos generados:")
print("analisis_ecem.json")
print("reporte_ecem.pdf")
print("glosario_ecem.pdf")
enviar_reporte("samuel.gutierrez3471@gmail.com")