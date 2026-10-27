import os
import psycopg2
from dotenv import load_dotenv

# Carga las variables del archivo .env
load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")

def obtener_conexion():
    """Establece conexión cifrada con PostgreSQL en Supabase de forma explícita."""
    if not DATABASE_URL:
        raise ValueError("❌ No se encontró la variable de entorno DATABASE_URL.")
    
    # Si la URL viene completa, podemos usarla directamente o descomponerla de forma segura
    # Forzamos los parámetros uno a uno para evitar errores de interpretación del host
    return psycopg2.connect(
        dsn=DATABASE_URL,
        sslmode='require'
    )

def inicializar_bd():
    """Crea la tabla de remediaciones en la base de datos remota si no existe."""
    try:
        conn = psycopg2.connect(dsn=os.getenv("DATABASE_URL"), sslmode='require')
        cursor = conn.cursor()
        
        # Crear la tabla en la nube
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS remediaciones (
                id SERIAL PRIMARY KEY,
                servicio VARCHAR(100) UNIQUE NOT NULL,
                titulo_problema VARCHAR(200) NOT NULL,
                pasos_mitigacion TEXT NOT NULL,
                comando_verificacion VARCHAR(255)
            )
        ''')
        
        # Datos institucionales iniciales para el manual de remediación
        remediaciones_iniciales = [
            ("msrpc", "Exposición de Microsoft RPC (Puerto 135)", 
             "1. Deshabilite el servicio RPC Endpoint Mapper si no es necesario.\n2. Restrinja el acceso mediante reglas de firewall perimetral.\n3. Aplique los últimos parches de seguridad de Windows.", 
             "Get-Service RpcMapper"),
            
            ("netbios-ssn", "Exposición de NetBIOS Session Service (Puerto 139)", 
             "1. Deshabilite NetBIOS sobre TCP/IP si utiliza DHCP moderno.\n2. Bloquee el puerto 139 TCP en el firewall corporativo.", 
             "nmap -p 139 --script nbstat"),
            
            ("microsoft-ds", "Exposición de SMB Direct/CIFS (Puerto 445)", 
             "1. Deshabilite el protocolo SMBv1 obsoleto.\n2. Exija firmas SMB obligatorias.\n3. Bloquee el puerto 445 en la frontera perimetral.", 
             "Get-SmbServerConfiguration | Select EnableSMB1"),
            
            ("http", "Servicio HTTP sin restricciones o versión desactualizada", 
             "1. Actualice el servidor web a su última versión estable.\n2. Oculte la versión en las cabeceras HTTP.\n3. Implemente redirección estricta a HTTPS (TLS 1.2/1.3).", 
             "curl -I http://objetivo"),
            
            ("vnc", "Acceso VNC sin cifrar expuesto a red (Puerto 5900)", 
             "1. Nunca exponga VNC directamente a Internet; utilice túneles SSH o VPN.\n2. Configure autenticación robusta por contraseña.", 
             "nmap -p 5900 --script vnc-info"),

            ("ftp", "Servicio FTP sin cifrar expuesto (Puerto 21)", 
             "1. Deshabilite el acceso anónimo en el servidor FTP.\n2. Migre a protocolos seguros como SFTP (SSH) o FTPS.\n3. Restrinja el  acceso por IP mediante reglas de firewall.", 
             "nmap -p 21 --script ftp-anon"),

            ("mysql", "Base de datos MySQL expuesta directamente a la red (Puerto 3306)", 
             "1. Modifique la directiva 'bind-address' para escuchar solo en localhost/red interna.\n2. Elimine usuarios sin contraseña o   con privilegios excesivos.\n3. Implemente un túnel VPN/SSH para administración remota.", 
             "nmap -p 3306 --script mysql-info")
        ]
        
        for rem in remediaciones:
            cursor.execute('''
                INSERT INTO remediaciones (servicio, titulo_problema, pasos_mitigacion, comando_verificacion)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (servicio) DO UPDATE SET 
                    titulo_problema = EXCLUDED.titulo_problema,
                    pasos_mitigacion = EXCLUDED.pasos_mitigacion,
                    comando_verificacion = EXCLUDED.comando_verificacion
            ''', rem)
        
        conn.commit()
        cursor.close()
        conn.close()
        print("✅ Base de datos remota en Supabase sincronizada e inicializada exitosamente.")
        
    except Exception as e:
        print(f"❌ Error al conectar o inicializar la base de datos remota: {e}")

def obtener_remediacion(servicio, puerto=None, host=None):
    """Consulta la guía de remediación directamente desde la base de datos en la nube."""
    try:
        conn = obtener_conexion()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT titulo_problema, pasos_mitigacion, comando_verificacion 
            FROM remediaciones 
            WHERE LOWER(servicio) = LOWER(%s)
        ''', (servicio,))
        
        resultado = cursor.fetchone()
        cursor.close()
        conn.close()
        
        if resultado:
            return {
                "titulo": resultado[0],
                "pasos": resultado[1],
                "comando": resultado[2]
            }
        else:
            return {
                "titulo": f"Servicio genérico expuesto ({servicio})",
                "pasos": "1. Valide la necesidad operativa del servicio.\n2. Aplique segmentación de red y reglas de denegación por defecto en el firewall.",
                "comando": f"nmap -sV -p [puerto] [objetivo]"
            }
        
    except Exception as e:
        print(f"⚠️ Aviso en consulta remota: {e}")

    # Fallback dinámico sin valores duros tipo [puerto]
    p_str = str(puerto) if puerto else "21/3306"
    h_str = str(host) if host else "10.0.0.15"

    return {
        "titulo": f"Servicio detectado ({servicio})",
        "pasos": "1. Verifique la criticidad y el propósito operativo del servicio en el activo.\n2. Aplique el principio de mínimo privilegio restringiendo el acceso por red al puerto asociado.\n3. Actualice el software a la versión con soporte del fabricante.",
        "comando": f"nmap -sV -p [puerto] [objetivo]"
    }

if __name__ == "__main__":
    inicializar_bd()