# utils/virustotal.py

import os
import re
import vt
from dotenv import load_dotenv

# Cargar la clave de API desde una variable de entorno
load_dotenv()
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "0a9e835e00a0dcf5ccc2da13ad61afd9179f22382239e4f30b0b3d4155e0c377")

# Inicializar el cliente de VirusTotal de forma global
# Esto evita tener que reiniciarlo en cada llamada
vt_client = None
if VT_API_KEY:
    try:
        vt_client = vt.Client(VT_API_KEY)
    except Exception as e:
        print(f"Error initializing VirusTotal client: {e}")
        vt_client = None

def extract_urls(text: str) -> list[str]:
    """
    Extrae todas las URLs de un texto usando una expresión regular.
    Devuelve una lista de URLs únicas.
    """
    # Expresión regular mejorada para capturar URLs, incluyendo protocolos http/https
    # y dominios con subdominios.
    url_pattern = re.compile(r'https?://[^\s/$.?#].[^\s]*', re.IGNORECASE)
    
    # Encontrar todas las coincidencias
    urls = url_pattern.findall(text)
    
    # Devolver una lista de URLs únicas para evitar análisis duplicados
    return list(set(urls))

async def analyze_url_with_virustotal(url: str) -> dict:
    """
    Analiza una URL con VirusTotal y devuelve un resumen del resultado.
    """
    if not vt_client:
        return {"error": "Cliente de VirusTotal no inicializado."}

    summary = {
        "url": url,
        "status": "No Analizado",
        "positives": 0,
        "total": 0,
        "details": {},
        "categories": {}
    }

    try:
        # El ID de una URL en VT es el hash SHA-256 de la URL en sí
        url_id = vt.url_id(url)
        
        # Obtener el reporte de la URL
        # Usamos un bloque try-except para manejar el caso de que la URL nunca haya sido vista
        try:
            report = await vt_client.get_object_async(f"/urls/{url_id}")
            
            # Extraer las estadísticas de análisis
            stats = report.last_analysis_stats
            summary["positives"] = stats.get("malicious", 0) + stats.get("suspicious", 0)
            summary["total"] = sum(stats.values())
            summary["status"] = "Analizado"

            # Contar las categorías
            categories = {}
            for result in report.last_analysis_results.values():
                category = result["category"]
                categories[category] = categories.get(category, 0) + 1
            summary["categories"] = categories

            # Extraer los detalles de qué motores lo marcaron como malicioso
            for engine, result in report.last_analysis_results.items():
                if result["category"] in ["malicious", "suspicious"]:
                    summary["details"][engine] = result["result"]

        except vt.error.APIError as e:
            if e.code == "NotFoundError":
                # Si la URL no se encuentra, la enviamos a analizar
                analysis = await vt_client.scan_url_async(url, wait_for_completion=False)
                summary["status"] = "Análisis en progreso"
            else:
                summary["error"] = f"Error de API de VirusTotal: {e}"

    except Exception as e:
        summary["error"] = f"Error inesperado al analizar la URL: {e}"

    return summary
