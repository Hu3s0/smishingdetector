# dashboard/app.py

import streamlit as st
import requests
import json
import socket
import qrcode
from io import BytesIO
import os # Added for environment variables
import pandas as pd # Added for DataFrame operations
import plotly.express as px # Added for charting


# --- Configuración de la API y Dashboard URLs ---
API_URL = os.environ.get("API_URL", "http://localhost:8000/predict")
DASHBOARD_URL_FOR_QR = os.environ.get("DASHBOARD_URL_FOR_QR", "http://localhost:8501")

# --- Configuración de la Página ---
st.set_page_config(
    page_title="Smishing Detector Dashboard",
    page_icon="📱",
    layout="centered"
)

# Helper function for score visualization
def get_score_status_and_color(score):
    if score > 70:
        return "Riesgo Alto", "red", "🚨" # Red
    elif 40 <= score <= 70:
        return "Riesgo Medio", "orange", "⚠️" # Orange/Yellow
    else:
        return "Riesgo Bajo", "green", "✅" # Green

# --- Título y Descripción ---
st.title("🔬 Smishing Detector")
st.markdown("""
Bienvenido al panel de análisis de Smishing. Este sistema utiliza un modelo de Machine Learning
y un motor de reglas para determinar si un mensaje SMS es potencialmente malicioso.
""")

# --- Sidebar para Navegación ---
with st.sidebar:
    st.header("Navegación")
    page_selection = st.radio("Ir a:", ["Clasificador", "Monitoreo"])

# --- Contenido Principal ---
if page_selection == "Clasificador":
    st.header("Analizador de Mensajes SMS")

    # Selector para elegir entre análisis individual o por lotes
    analysis_mode = st.radio("Selecciona el modo de análisis:", ("Individual", "Por Lotes (Archivo)"))

    if analysis_mode == "Individual":
        # Caja de texto para que el usuario introduzca el mensaje
        message_text = st.text_area(
            "Introduce el mensaje SMS que quieres analizar:",
            height=150,
            placeholder="Ej: Felicidades! Has ganado un premio de $1000. Reclama aquí: http://bit.ly/premiofalso"
        )

        # Botón para iniciar el análisis
        analyze_button = st.button("Analizar Mensaje")

        # --- Lógica de Análisis Individual ---
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

                            status_text, color, emoji = get_score_status_and_color(score)

                            st.markdown(f"**Veredicto:** <span style='color: {color};'>{emoji} {prediction.capitalize()}</span>", unsafe_allow_html=True)
                            st.markdown(f"**Nivel de Riesgo:** <span style='color: {color};'>{status_text}</span>", unsafe_allow_html=True)
                            st.markdown(f"**Puntuación de Confianza:** <span style='color: {color};'>{score:.2f}%</span>", unsafe_allow_html=True)

                            # Mostrar las reglas heurísticas activadas
                            triggered_rules = results.get("triggered_rules", [])
                            
                            with st.expander("Explicación del Resultado (XAI) / Reglas Heurísticas Activas"):
                                if triggered_rules:
                                    st.warning("Se activaron las siguientes reglas de alerta:")
                                    for rule in triggered_rules:
                                        st.markdown(f"- _{rule}_")
                                else:
                                    st.info("No se activó ninguna regla heurística en este mensaje.")
                                
                                ml_relevant_tokens = results.get("ml_relevant_tokens", {})
                                if ml_relevant_tokens:
                                    st.subheader("Tokens Relevantes del Modelo ML:")
                                    if ml_relevant_tokens.get("smishing"):
                                        st.markdown(f"**Para Smishing:** {', '.join(ml_relevant_tokens['smishing'])}")
                                    if ml_relevant_tokens.get("legitimo"):
                                        st.markdown(f"**Para Legítimo:** {', '.join(ml_relevant_tokens['legitimo'])}")
                                else:
                                    st.info("No se encontraron tokens relevantes del modelo ML para mostrar.")
                            
                            # Mostrar el JSON completo en un expander
                            with st.expander("Ver respuesta completa de la API (JSON)"):
                                st.json(results)

                            st.subheader("Acciones de Feedback")
                            col1, col2, col3 = st.columns(3)
                            with col1:
                                if st.button("👍 Marcar como Falso Positivo"):
                                    st.info("Feedback: Marcar como Falso Positivo (Implementación de API pendiente)")
                            with col2:
                                if st.button("👎 Marcar como Falso Negativo"):
                                    st.info("Feedback: Marcar como Falso Negativo (Implementación de API pendiente)")
                            with col3:
                                if st.button("🚫 Enviar a Bloqueo de Dominio"):
                                    st.info("Acción: Enviar a Bloqueo de Dominio (Implementación de API pendiente)")

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
        st.subheader("Tendencias de Detección")
        TRENDS_API_URL = f"{API_URL.rsplit('/', 1)[0]}/metrics/trends" # Dynamically get base URL

        try:
            trends_response = requests.get(TRENDS_API_URL)
            if trends_response.status_code == 200:
                trends_data = trends_response.json()

                # --- Gráfico de Líneas: Tendencia horaria de Smishing ---
                smishing_trend_df = pd.DataFrame(trends_data.get("smishing_trend_hourly", []))
                if not smishing_trend_df.empty:
                    smishing_trend_df["timestamp"] = pd.to_datetime(smishing_trend_df["timestamp"])
                    smishing_trend_df = smishing_trend_df.sort_values("timestamp")
                    
                    fig_smishing_trend = px.line(
                        smishing_trend_df,
                        x="timestamp",
                        y="count",
                        title="Tendencia Horaria de Mensajes Smishing (Últimas 24h)",
                        labels={"timestamp": "Hora", "count": "Número de Smishing Detectados"}
                    )
                    fig_smishing_trend.update_xaxes(dtick="H", tickformat="%H:%M") # Show hourly ticks
                    st.plotly_chart(fig_smishing_trend, use_container_width=True)
                else:
                    st.info("No hay datos de tendencia de Smishing disponibles en las últimas 24 horas.")

                # --- Gráfico de Barras: Top 10 Reglas Heurísticas ---
                top_rules_df = pd.DataFrame(trends_data.get("top_10_rules", []))
                if not top_rules_df.empty:
                    fig_top_rules = px.bar(
                        top_rules_df,
                        x="count",
                        y="rule_name",
                        orientation='h',
                        title="Top 10 Reglas Heurísticas Más Activadas",
                        labels={"count": "Número de Activaciones", "rule_name": "Regla Heurística"}
                    )
                    fig_top_rules.update_layout(yaxis={'categoryorder':'total ascending'}) # Sort bars
                    st.plotly_chart(fig_top_rules, use_container_width=True)
                else:
                    st.info("No hay datos de reglas heurísticas activadas disponibles.")

            else:
                st.error(f"Error al obtener datos de tendencias de la API. Código: {trends_response.status_code}")
                try:
                    st.json(trends_response.json())
                except json.JSONDecodeError:
                    st.text(response.text)
        except requests.exceptions.ConnectionError:
            st.error("No se pudo conectar con la API para obtener los datos de tendencias. Asegúrate de que el servicio 'api' esté corriendo.")
        except Exception as e:
            st.error(f"Ha ocurrido un error inesperado al cargar los datos de tendencias: {e}")
    elif analysis_mode == "Por Lotes (Archivo)":
        st.subheader("Análisis de Mensajes por Lotes")
        uploaded_file = st.file_uploader("Sube un archivo CSV o TXT", type=["csv", "txt"])

        if uploaded_file is not None:
            messages_to_analyze = []
            file_type = uploaded_file.type

            if file_type == "text/csv":
                # Asume que el CSV tiene una columna llamada 'message'
                import pandas as pd
                df = pd.read_csv(uploaded_file)
                if 'message' in df.columns:
                    messages_to_analyze = df['message'].tolist()
                else:
                    st.error("El archivo CSV debe contener una columna llamada 'message'.")
            elif file_type == "text/plain":
                # Lee cada línea como un mensaje
                messages_to_analyze = uploaded_file.read().decode("utf-8").splitlines()
            
            if messages_to_analyze:
                st.info(f"Se encontraron {len(messages_to_analyze)} mensajes para analizar.")
                batch_analyze_button = st.button("Analizar Mensajes por Lotes")

                if batch_analyze_button:
                    results_df_data = []
                    with st.spinner("Analizando mensajes por lotes..."):
                        for i, message in enumerate(messages_to_analyze):
                            if message.strip() == "":
                                continue # Skip empty lines
                            try:
                                payload = {"message": message}
                                response = requests.post(API_URL, json=payload)
                                
                                if response.status_code == 200:
                                    result = response.json()
                                    results_df_data.append({
                                        "Mensaje": message,
                                        "Veredicto": result.get("prediction", "Error"),
                                        "Confianza": f"{result.get('score', 0.0):.2%}",
                                        "Reglas Activadas": ", ".join(result.get("triggered_rules", []))
                                    })
                                else:
                                    results_df_data.append({
                                        "Mensaje": message,
                                        "Veredicto": "Error API",
                                        "Confianza": "N/A",
                                        "Reglas Activadas": f"Status {response.status_code}"
                                    })
                            except requests.exceptions.ConnectionError:
                                results_df_data.append({
                                    "Mensaje": message,
                                    "Veredicto": "Error de Conexión",
                                    "Confianza": "N/A",
                                    "Reglas Activadas": "No se pudo conectar con la API"
                                })
                            except Exception as e:
                                results_df_data.append({
                                    "Mensaje": message,
                                    "Veredicto": "Error Inesperado",
                                    "Confianza": "N/A",
                                    "Reglas Activadas": str(e)
                                })
                    
                    if results_df_data:
                        st.subheader("Resultados del Análisis por Lotes")
                        st.dataframe(pd.DataFrame(results_df_data), use_container_width=True)
                    else:
                        st.warning("No se obtuvieron resultados del análisis por lotes.")
            else:
                st.warning("El archivo subido no contiene mensajes válidos para analizar.")
elif page_selection == "Monitoreo":
    st.header("Centro de Monitoreo")
    
    # --- Filtros en el Sidebar para la página de Monitoreo ---
    with st.sidebar:
        st.header("Filtros de Monitoreo")
        
        today = datetime.now().date()
        start_date = st.date_input("Fecha de inicio", today - timedelta(days=7))
        end_date = st.date_input("Fecha de fin", today)
        
        risk_options = ["Todos", "Riesgo Alto", "Riesgo Medio", "Riesgo Bajo"]
        risk_level = st.selectbox("Nivel de Riesgo", options=risk_options)

    # --- Fetch KPIs ---
    kpis_api_url = f"{API_URL.rsplit('/', 1)[0]}/metrics/kpis"
    kpis_params = {
        "start_date": start_date.isoformat(),
        "end_date": end_date.isoformat(),
        "risk_level": risk_level if risk_level != "Todos" else None
    }
    
    try:
        kpis_response = requests.get(kpis_api_url, params=kpis_params)
        if kpis_response.status_code == 200:
            kpis_data = kpis_response.json()
            
            st.subheader("KPIs del Periodo Seleccionado")
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric(label="Volumen Total Analizado", value=kpis_data.get("total_analyzed_24h", 0))
            with col2:
                st.metric(label="Tasa de Detección de Smishing", value=f"{kpis_data.get('smishing_detection_rate_24h', 0.0):.2f}%")
            with col3:
                st.metric(label="Latencia Media de la API", value=f"{kpis_data.get('avg_api_latency_ms', 0.0):.2f} ms")
        else:
            st.error(f"Error al obtener KPIs de la API. Código: {kpis_response.status_code}")
            try:
                st.json(kpis_response.json())
            except json.JSONDecodeError:
                st.text(kpis_response.text)
    except requests.exceptions.ConnectionError:
        st.error("No se pudo conectar con la API para obtener los KPIs. Asegúrate de que el servicio 'api' esté corriendo.")
    except Exception as e:
        st.error(f"Ha ocurrido un error inesperado al cargar los KPIs: {e}")


    # --- Fetch Trends ---
    trends_api_url = f"{API_URL.rsplit('/', 1)[0]}/metrics/trends"
    trends_params = {
        "start_date": start_date.isoformat(),
        "end_date": end_date.isoformat(),
        "risk_level": risk_level if risk_level != "Todos" else None
    }
    
    try:
        trends_response = requests.get(trends_api_url, params=trends_params)
        if trends_response.status_code == 200:
            trends_data = trends_response.json()

            # --- Gráfico de Líneas: Tendencia horaria de Smishing ---
            st.subheader("Tendencias de Detección")
            smishing_trend_df = pd.DataFrame(trends_data.get("smishing_trend_hourly", []))
            if not smishing_trend_df.empty:
                smishing_trend_df["timestamp"] = pd.to_datetime(smishing_trend_df["timestamp"])
                smishing_trend_df = smishing_trend_df.sort_values("timestamp")
                
                fig_smishing_trend = px.line(
                    smishing_trend_df,
                    x="timestamp",
                    y="count",
                    title="Tendencia Horaria de Mensajes Smishing",
                    labels={"timestamp": "Hora", "count": "Número de Smishing Detectados"}
                )
                fig_smishing_trend.update_xaxes(dtick="H", tickformat="%H:%M") # Show hourly ticks
                st.plotly_chart(fig_smishing_trend, use_container_width=True)
            else:
                st.info("No hay datos de tendencia de Smishing disponibles para el rango de fechas y filtro seleccionados.")

            # --- Gráfico de Barras: Top 10 Reglas Heurísticas ---
            top_rules_df = pd.DataFrame(trends_data.get("top_10_rules", []))
            if not top_rules_df.empty:
                fig_top_rules = px.bar(
                    top_rules_df,
                    x="count",
                    y="rule_name",
                    orientation='h',
                    title="Top 10 Reglas Heurísticas Más Activadas",
                    labels={"count": "Número de Activaciones", "rule_name": "Regla Heurística"}
                )
                fig_top_rules.update_layout(yaxis={'categoryorder':'total ascending'}) # Sort bars
                st.plotly_chart(fig_top_rules, use_container_width=True)
            else:
                st.info("No hay datos de reglas heurísticas activadas disponibles para el rango de fechas y filtro seleccionados.")

        else:
            st.error(f"Error al obtener datos de tendencias de la API. Código: {trends_response.status_code}")
            try:
                st.json(trends_response.json())
            except json.JSONDecodeError:
                st.text(trends_response.text)
    except requests.exceptions.ConnectionError:
        st.error("No se pudo conectar con la API para obtener los datos de tendencias. Asegúrate de que el servicio 'api' esté corriendo.")
    except Exception as e:
        st.error(f"Ha ocurrido un error inesperado al cargar los datos de tendencias: {e}")

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
