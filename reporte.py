from reportlab.lib.pagesizes import letter
from reportlab.lib.colors import HexColor
from reportlab.pdfgen import canvas
from glosario_ecem import glosario
from database import obtener_remediacion

def estimar_costos(clientes):

    # estimación simple basada en escenarios legales
    multa_base = 2000000 * (clientes/10)

    demanda_base = 500000 * clientes

    multa_min = int(multa_base * 0.5)
    multa_max = int(multa_base * 2)

    demanda_min = int(demanda_base * 0.5)
    demanda_max = int(demanda_base * 1.5)

    total_min = multa_min + demanda_min
    total_max = multa_max + demanda_max

    return multa_min, multa_max, demanda_min, demanda_max, total_min, total_max

def generar_reporte(vulnerabilidades, resumen, iee, proyeccion, costo_min, costo_max):

    generar_reporte_ejecutivo(vulnerabilidades, resumen, iee, proyeccion, costo_min, costo_max)
    generar_reporte_tecnico(vulnerabilidades)
    generar_glosario()
    generar_reporte_remediacion(vulnerabilidades)

    print("✅ Todos los reportes (Ejecutivo, Técnico, Glosario y Remediación) han sido generados con éxito.")


def generar_reporte_ejecutivo(vulnerabilidades, resumen, iee, proyeccion, costo_min, costo_max):

    c = canvas.Canvas("reporte_ejecutivo.pdf", pagesize=letter)

    y = 750

    c.setFont("Helvetica-Bold",16)
    c.drawString(200,y,"Reporte Ejecutivo de Riesgos")

    y -= 40

    c.setFont("Helvetica",12)

    c.drawString(50,y,f"Vulnerabilidades detectadas: {len(vulnerabilidades)}")

    y -= 20
    c.drawString(50,y,f"Críticas: {resumen['critico']}")

    y -= 20
    c.drawString(50,y,f"Altas: {resumen['alto']}")

    y -= 20
    c.drawString(50,y,f"Medias: {resumen['medio']}")

    y -= 20
    c.drawString(50,y,f"Bajas: {resumen['bajo']}")

    y -= 40

    for i, v in enumerate(vulnerabilidades):

        riesgo = v["riesgo"]

        if riesgo == "Crítico":
            prob = "40%"
            impacto = "Posible pérdida financiera grave o interrupción total del sistema"
            clientes = 200

        elif riesgo == "Alto":
            prob = "20%"
            impacto = "Robo de información de clientes o daño reputacional"
            clientes = 100

        elif riesgo == "Medio":
            prob = "10%"
            impacto = "Acceso limitado a datos internos"
            clientes = 50

        else:
            prob = "5%"
            impacto = "Impacto bajo en operaciones"
            clientes = 20


        multa_min, multa_max, demanda_min, demanda_max, total_min, total_max = estimar_costos(clientes)

        c.setFont("Helvetica-Bold",11)
        c.drawString(50,y,f"Causa {v['causa']}")

        y -= 15

        c.setFont("Helvetica",11)

        c.drawString(60,y,f"Host: {v['host']}")

        y -= 15
        c.drawString(60,y,f"Nivel de riesgo: {riesgo} ({prob})")

        y -= 15
        c.drawString(60,y,f"Impacto potencial: {impacto}")

        y -= 15
        c.drawString(60,y,f"Clientes potencialmente afectados: {clientes}")

        y -= 15
        c.drawString(60,y,f"Multas regulatorias estimadas: ${multa_min:,} - ${multa_max:,} CLP")

        y -= 15
        c.drawString(60,y,f"Demandas potenciales: ${demanda_min:,} - ${demanda_max:,} CLP")

        y -= 15
        c.drawString(60,y,f"Costo total estimado: ${total_min:,} - ${total_max:,} CLP")

        y -= 35

        if y < 120:
            c.showPage()
            y = 750

    #Verificamos si queda espacio de página
    if y < 120:
        c.showPage()
        y = 750

    #IEE
    y -= 30

    if iee <= 25:
        nivel = "Bajo"
    elif iee <= 50:
        nivel = "Moderado"
    elif iee <= 75:
        nivel = "Alto"
    else:
        nivel = "Crítico"

    c.setFont("Helvetica-Bold",12)
    c.drawString(50,y,"Índice de Exposición Empresarial del Sistema")

    y -= 20

    c.setFont("Helvetica",12)
    c.drawString(50,y,f"IEE: {iee}/100")

    y -= 30

    c.setFont("Helvetica-Bold",12)
    c.drawString(50,y,"Resumen de Riesgo Empresarial")

    y -= 20

    c.setFont("Helvetica",11)

    c.drawString(50,y,f"Probabilidad de incidente en 1 año: {proyeccion['1']}%")

    y -= 15
    c.drawString(50,y,f"Probabilidad en 2 años: {proyeccion['2']}%")

    y -= 15
    c.drawString(50,y,f"Probabilidad en 3 años: {proyeccion['3']}%")

    y -= 15
    c.drawString(50,y,f"Probabilidad en 5 años: {proyeccion['5']}%")

    y -= 25

    c.drawString(50,y,f"Costo potencial total estimado:")

    y -= 15
    c.drawString(50,y,f"${costo_min:,} - ${costo_max:,} CLP")

    y -= 15
    c.drawString(50,y,f"Nivel de riesgo global: {nivel}")

    y -= 30

    #Glosario
    # NUEVA PAGINA - GLOSARIO

    c.showPage()
    y = 750

    c.setFont("Helvetica-Bold",16)
    c.drawString(200,y,"Glosario de Causas")

    y -= 40
    c.setFont("Helvetica",11)

    for v in vulnerabilidades:

        servicio = v["servicio"]

        descripcion = glosario.get(
            servicio,
            f"Servicio {servicio} expuesto en puerto {v['puerto']}"
        )

        c.drawString(
            50,
            y,
            f"{v['causa']}: {descripcion}"
        )   

        y -= 20

        if y < 100:
            c.showPage()
            y = 750

    c.save()

def generar_reporte_tecnico(vulnerabilidades):

    c = canvas.Canvas("reporte_tecnico.pdf", pagesize=letter)

    y = 750

    c.setFont("Helvetica-Bold",16)
    c.drawString(200,y,"Reporte Técnico de Vulnerabilidades")

    y -= 40

    c.setFont("Helvetica",11)

    for i, v in enumerate(vulnerabilidades):

        c.drawString(50,y,f"Causa {v['causa']}")

        y -= 15
        c.drawString(60,y,f"Host: {v['host']}")

        y -= 15
        c.drawString(60,y,f"Servicio: {v['servicio']}")

        y -= 15
        c.drawString(60,y,f"Puerto: {v['puerto']}")

        y -= 15
        c.drawString(60,y,f"CVE: {v['cve']}")

        y -= 15
        c.drawString(60,y,f"CVSS: {v['cvss']}")

        y -= 15
        c.drawString(60,y,f"Riesgo calculado: {v['riesgo']}")

        y -= 25

        if y < 100:
            c.showPage()
            y = 750

    c.save()

def generar_glosario():
    c = canvas.Canvas("glosario_ecem.pdf", pagesize=letter)

    y = 750

    c.setFont("Helvetica-Bold", 16)
    c.drawString(200, y, "Glosario ECEM")

    y -= 40

    c.setFont("Helvetica", 11)

    for servicio, descripcion in glosario.items():
        c.drawString(50, y, f"{servicio}: {descripcion}")

        y -= 20

        if y < 100:
            c.showPage()
            y = 750

    c.save()

def generar_seccion_remediacion(puertos_detectados):
    """
    Recibe la lista de puertos detectados por Nmap y consulta en Supabase
    las guías de remediación específicas para cada servicio.
    """
    bloque_remediacion = []
    
    for item in puertos_detectados:
        servicio = item.get('servicio', 'desconocido')
        puerto = item.get('puerto', 'N/A')
        
        # Consulta remota a la nube en Supabase
        guia = obtener_remediacion(servicio)
        
        datos_remediacion = {
            "puerto": puerto,
            "servicio": servicio,
            "titulo": guia["titulo"],
            "pasos": guia["pasos"],
            "comando": guia["comando"]
        }
        bloque_remediacion.append(datos_remediacion)
        
    return bloque_remediacion

def generar_reporte_remediacion(vulnerabilidades):
    """
    Genera un documento PDF independiente (o sección) con el manual de remediación 
    consultando dinámicamente la base de datos remota en Supabase.
    """
    c = canvas.Canvas("reporte_remediacion.pdf", pagesize=letter)
    
    y = 750

    c.setFont("Helvetica-Bold", 16)
    c.drawString(150, y, "Manual de Remediación y Mitigación")

    y -= 40
    c.setFont("Helvetica", 11)

    # Obtenemos los datos procesados mediante tu función conectada a Supabase
    remediaciones = generar_seccion_remediacion(vulnerabilidades)

    for item in remediaciones:
        # Título del hallazgo / servicio
        c.setFont("Helvetica-Bold", 11)
        c.drawString(50, y, f"Puerto {item['puerto']} ({item['servicio'].upper()}): {item['titulo']}")
        y -= 20

        # Pasos de mitigación
        c.setFont("Helvetica-Bold", 10)
        c.drawString(60, y, "Pasos recomendados:")
        y -= 15
        
        c.setFont("Helvetica", 10)
        for paso in item['pasos'].split('\n'):
            if paso.strip():
                c.drawString(70, y, f"- {paso.strip()}")
                y -= 15
                
                # Control de salto de página si se acaba el espacio durante los pasos
                if y < 100:
                    c.showPage()
                    y = 750
                    c.setFont("Helvetica", 10)

        y -= 5
        # Comando de verificación técnica
        c.setFont("Helvetica-Bold", 10)
        c.drawString(60, y, f"Comando de verificación: {item['comando']}")
        
        y -= 30  # Espacio entre cada remediación
        
        # Verificamos si queda espacio en la página para la siguiente remediación
        if y < 100:
            c.showPage()
            y = 750

    c.save()