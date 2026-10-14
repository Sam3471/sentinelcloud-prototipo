# motor_ecem.py

# Esta función clasifica el nivel de riesgo según el puntaje CVSS
def calcular_riesgo(cvss):

    if cvss >= 9:
        return "Crítico","Urgente"
    elif cvss >= 7:
        return "Alto","Alta"
    elif cvss >= 4:
        return "Medio","Media"
    else:
        return "Bajo","Baja"


# Esta función analiza todas las vulnerabilidades
def analizar_vulnerabilidades(vulnerabilidades):

    resultados = []
    causa_id = 1

    for v in vulnerabilidades:

        riesgo, prioridad = calcular_riesgo(v["cvss"])

        # generar ID ECEM estructurada
        causa = f"ECEM-{causa_id:03d}"

        v["riesgo"] = riesgo
        v["prioridad"] = prioridad
        v["causa"] = causa

        resultados.append(v)

        causa_id += 1

    return resultados

#Función determinante de riesgo
def generar_estadisticas(resultados):

    resumen = {
        "critico": 0,
        "alto": 0,
        "medio": 0,
        "bajo": 0
    }

    puntaje_total = 0

    for r in resultados:

        riesgo = r["riesgo"]

        if riesgo == "Crítico":
            resumen["critico"] += 1
            puntaje_total += 100

        elif riesgo == "Alto":
            resumen["alto"] += 1
            puntaje_total += 70

        elif riesgo == "Medio":
            resumen["medio"] += 1
            puntaje_total += 40

        else:
            resumen["bajo"] += 1
            puntaje_total += 10


    if len(resultados) == 0:
        iee = 0
    else:
        iee = int(puntaje_total / len(resultados))


    return resumen, iee

#Función cálculo de IEE (Índice de Exposición Empresarial)
def calcular_iee(vulnerabilidades):

    puntaje = 0

    for v in vulnerabilidades:

        if v["riesgo"] == "Crítico":
            puntaje += 10

        elif v["riesgo"] == "Alto":
            puntaje += 7

        elif v["riesgo"] == "Medio":
            puntaje += 4

        else:
            puntaje += 1

    max_puntaje = len(vulnerabilidades) * 10

    iee = (puntaje / max_puntaje) * 100

    return round(iee)

def calcular_riesgo_empresarial(resultados):

    prob_total = 0
    costo_total_min = 0
    costo_total_max = 0

    for r in resultados:

        if r["riesgo"] == "Crítico":
            prob = 0.40
            costo = 20000000

        elif r["riesgo"] == "Alto":
            prob = 0.20
            costo = 10000000

        elif r["riesgo"] == "Medio":
            prob = 0.10
            costo = 5000000

        else:
            prob = 0.05
            costo = 1000000

        prob_total += prob

        costo_total_min += costo * 0.5
        costo_total_max += costo * 1.5

    prob_total = min(prob_total, 0.95)

    return prob_total, int(costo_total_min), int(costo_total_max)

def proyeccion_incidentes(prob_anual):

    p1 = prob_anual

    p2 = 1 - (1 - prob_anual)**2
    p3 = 1 - (1 - prob_anual)**3
    p5 = 1 - (1 - prob_anual)**5

    return {

        "1": round(p1*100,1),
        "2": round(p2*100,1),
        "3": round(p3*100,1),
        "5": round(p5*100,1)

    }