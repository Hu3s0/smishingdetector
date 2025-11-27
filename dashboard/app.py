# dashboard/app.py

import streamlit as st
import requests
import json
import socket
import qrcode
from io import BytesIO
import os # Added for environment variables


# --- Configuración de la Página ---
st.set_page_config(
    page_title="Smishing Detector Dashboard",
    page_icon="📱",
    layout="centered"
)

# --- Título y Descripción ---
st.title("🔬 Smishing Detector")
st.markdown("""
Bienvenido al panel de análisis de Smishing. Este sistema utiliza un modelo de Machine Learning
y un motor de reglas para determinar si un mensaje SMS es potencialmente malicioso.
""")

# --- URL de la API ---
# La API debe estar corriendo para que el dashboard funcione.
# Por defecto, se asume que corre localmente en el puerto 8000.
API_URL = os.environ.get('API_URL', 'http://api:8000/predict')

# Escalabilidad:
# - En un entorno de producción, la URL de la API no debería estar hardcodeada.
#   Se podría obtener de una variable de entorno para mayor flexibilidad.
# - Se podría añadir autenticación para que solo usuarios autorizados usen el dashboard.
#   Streamlit ofrece mecanismos para gestionar secretos y estado de sesión.

# --- Obtener IP local para el código QR ---
def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # No necesita ser alcanzable
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

local_ip = os.environ.get('HOST_IP', '127.0.0.1')
API_URL_FOR_QR = f"http://{local_ip}:8000/"

# Generar la URL del dashboard para el código QR
DASHBOARD_URL_FOR_QR = f"http://{local_ip}:8000/"


# --- Interfaz de Usuario ---
st.header("Analizador de Mensajes SMS")

# Caja de texto para que el usuario introduzca el mensaje
message_text = st.text_area(
    "Introduce el mensaje SMS que quieres analizar:",
    height=150,
    placeholder="Ej: Felicidades! Has ganado un premio de $1000. Reclama aquí: http://bit.ly/premiofalso"
)

# Botón para iniciar el análisis
analyze_button = st.button("Analizar Mensaje")

# --- Lógica de Análisis ---
if analyze_button:
    if not message_text:
        st.warning("Por favor, introduce un mensaje para analizar.")
    else:
        with st.spinner("Analizando..."):
            try:
                # Payload para la petición a la API
                payload = {"message": message_text}
                
                # Realizar la petición POST a la API de FastAPI
                response = requests.post(API_URL, json=payload)
                
                if response.status_code == 200:
                    st.success("Análisis completado con éxito.")
                    
                    # Extraer los resultados
                    results = response.json()
                    
                    # --- Mostrar Resultados ---
                    st.subheader("Resultados del Análisis")
                    
                    # Mostrar la predicción principal
                    prediction = results.get("prediction", "N/A")
                    score = results.get("score", 0.0)
                    
                    if prediction == "smishing":
                        st.metric(label="Veredicto", value="Smishing Detectado", delta=f"{score:.2%} de confianza")
                        st.error("Este mensaje es potencialmente **peligroso**.")
                    else:
                        st.metric(label="Veredicto", value="Mensaje Legítimo", delta=f"{(1-score):.2%} de confianza")
                        st.success("Este mensaje parece ser **seguro**.")

                    # Mostrar las reglas heurísticas activadas
                    triggered_rules = results.get("triggered_rules", [])
                    if triggered_rules:
                        st.warning("Se activaron las siguientes reglas de alerta:")
                        for rule in triggered_rules:
                            st.markdown(f"- _{rule}_")
                    
                    # Mostrar el JSON completo en un expander
                    with st.expander("Ver respuesta completa de la API (JSON)"):
                        st.json(results)

                else:
                    st.error(f"Error al contactar la API. Código de estado: {response.status_code}")
                    try:
                        st.json(response.json())
                    except json.JSONDecodeError:
                        st.text(response.text)

            except requests.exceptions.ConnectionError:
                st.error(
                    "No se pudo conectar con la API. "
                    "Asegúrate de que el servidor de FastAPI esté corriendo en la siguiente dirección: "
                    f"`{API_URL}`"
                )
            except Exception as e:
                st.error(f"Ha ocurrido un error inesperado: {e}")

# --- Código QR para acceso móvil ---
with st.sidebar:
    st.header("Acceso desde tu móvil")
    st.markdown("Escanea este código QR para abrir una página y enviar mensajes directamente desde tu teléfono a la API.")

    # Generar el QR
    qr_img = qrcode.make(DASHBOARD_URL_FOR_QR)
    buf = BytesIO()
    qr_img.save(buf, format="PNG")
    st.image(buf, caption=f"Dashboard Endpoint: {DASHBOARD_URL_FOR_QR}", use_column_width=True)

# --- Nota sobre la ejecución ---
st.info("""
**Para usar este dashboard:**
1. Asegúrate de que el servidor de la API esté en funcionamiento. Ejecuta el siguiente comando en tu terminal:
   ```
   uvicorn api.main:app --reload
   ```
2. Una vez que la API esté corriendo, puedes interactuar con este panel.
""")

# Para ejecutar el dashboard, usa el comando:
# streamlit run dashboard/app.py
