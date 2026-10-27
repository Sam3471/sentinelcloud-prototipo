import smtplib
from email.message import EmailMessage


def enviar_reporte(destinatario):

    remitente = "samuel.gutierrez3471@gmail.com"
    password = "csxqoftohoplkyvp"

    msg = EmailMessage()

    msg["Subject"] = "Reporte de Seguridad - SentinelCloud"
    msg["From"] = remitente
    msg["To"] = destinatario

    msg.set_content(
        "Estimado,\n\nAdjunto encontrará el reporte de análisis de vulnerabilidades generado por SentinelCloud.\n\nSaludos."
    )

    # adjuntar PDF ejecutivo
    with open("reporte_ejecutivo.pdf", "rb") as f:
        msg.add_attachment(
            f.read(),
            maintype="application",
            subtype="pdf",
            filename="reporte_ejecutivo.pdf"
        )

    # adjuntar PDF técnico
    with open("reporte_tecnico.pdf", "rb") as f:
        msg.add_attachment(
            f.read(),
            maintype="application",
            subtype="pdf",
            filename="reporte_tecnico.pdf"
        )

    # adjuntar PDF Glosario
    with open("glosario_ecem.pdf", "rb") as f:
        msg.add_attachment(
            f.read(),
            maintype="application",
            subtype="pdf",
            filename="glosario_ecem.pdf"
        )

    # adjuntar PDF Remediación (Manual desde Supabase)
    with open("reporte_remediacion.pdf", "rb") as f:
        msg.add_attachment(
            f.read(),
            maintype="application",
            subtype="pdf",
            filename="reporte_remediacion.pdf"
        )

    # adjuntar JSON Análisis
    with open("analisis_ecem.json", "rb") as f:
        msg.add_attachment(
            f.read(),
            maintype="application",
            subtype="json",
            filename="analisis_ecem.json"
        )

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
        smtp.login(remitente, password)
        smtp.send_message(msg)

    print("Reporte enviado por correo.")