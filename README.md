# SmishingDetector: Sistema de Detección de Smishing

SmishingDetector es un sistema diseñado para identificar mensajes de texto (SMS) maliciosos, comúnmente conocidos como *smishing*. Utiliza un enfoque híbrido que combina un motor de reglas heurísticas y un modelo de Machine Learning (TF-IDF + Regresión Logística) para proporcionar un análisis completo y preciso.

El proyecto está construido con una arquitectura modular y escalable, utilizando FastAPI para la API y Streamlit para un dashboard interactivo.

## Arquitectura del Proyecto

El proyecto sigue una estructura de directorios clara y organizada para facilitar el mantenimiento y la escalabilidad.

```
SmishingDetector/
│
├── api/
│   └── main.py           # Servidor FastAPI con el endpoint /predict.
│
├── rules/
│   └── rules.py          # Motor de reglas heurísticas para detección rápida.
│
├── utils/
│   └── preprocessing.py  # Módulo de limpieza y preprocesamiento de texto.
│
├── models/
│   ├── classifier.pkl    # Modelo de clasificación entrenado.
│   └── vectorizer.pkl    # Vectorizador TF-IDF entrenado.
│
├── train/
│   └── train.py          # Script para entrenar y guardar el modelo de ML.
│
├── dashboard/
│   └── app.py            # Dashboard interactivo construido con Streamlit.
│
├── data/
│   └── dataset.csv       # Dataset de ejemplo para el entrenamiento.
│
├── requirements.txt      # Dependencias del proyecto.
└── README.md             # Este archivo.
```

---

## Instalación

Para poner en marcha el proyecto, sigue estos pasos.

**1. Clonar el Repositorio (si aplica)**
```bash
git clone <url-del-repositorio>
cd SmishingDetector
```

**2. Crear un Entorno Virtual (Recomendado)**
```bash
python -m venv venv
source venv/bin/activate  # En Windows: venv\Scripts\activate
```

**3. Instalar Dependencias**
El proyecto tiene dependencias que pueden requerir compilación. Se recomienda instalarlas en orden.

```bash
pip install -r requirements.txt
```

> **Nota sobre la instalación en Windows:**
> La librería `streamlit` depende de `pyarrow`, la cual puede fallar al instalarse si no tienes las herramientas de compilación de C++ y CMake instaladas. Si encuentras un error al instalar `pyarrow`:
> 1. Asegúrate de tener instalado "Microsoft C++ Build Tools" desde el "Visual Studio Installer".
> 2. Asegúrate de tener CMake instalado y disponible en el PATH del sistema.
>
> Si el problema persiste, puedes continuar usando el motor de ML y la API, ya que `streamlit` solo es necesario para el dashboard.

---

## Uso del Sistema

El sistema se compone de tres partes principales que puedes ejecutar de forma independiente: el entrenamiento del modelo, la API de predicción y el dashboard de análisis.

### 1. Entrenamiento del Modelo

Antes de poder realizar predicciones, necesitas entrenar el modelo con los datos de `data/dataset.csv`.

Ejecuta el siguiente comando desde la raíz del proyecto:
```bash
python train/train.py
```
Este script procesará los datos, entrenará un vectorizador TF-IDF y un clasificador de Regresión Logística, y guardará los artefactos (`vectorizer.pkl` y `classifier.pkl`) en el directorio `models/`.

### 2. Ejecución del Servidor FastAPI

La API es el núcleo del sistema y expone la lógica de detección a través de un endpoint HTTP.

Para iniciar el servidor, ejecuta:
```bash
uvicorn api.main:app --reload
```
El servidor estará disponible en `http://127.0.0.1:8000`. Puedes explorar la documentación interactiva de la API (generada por Swagger) en `http://127.0.0.1:8000/docs`.

### 3. Ejecución del Dashboard

El dashboard de Streamlit proporciona una interfaz gráfica para interactuar con el sistema de forma sencilla.

**Requisito:** La API de FastAPI debe estar en ejecución.

Para lanzar el dashboard, ejecuta:
```bash
streamlit run dashboard/app.py
```
Se abrirá una nueva pestaña en tu navegador con la interfaz del dashboard, lista para analizar mensajes.

---

## Roadmap para Versión Profesional

Esta versión básica está diseñada para ser el punto de partida de una solución de nivel profesional. Las futuras mejoras incluyen:

- **Base de Datos Escalable:**
  - **Qué:** Reemplazar el dataset CSV por una base de datos como PostgreSQL o una base de datos NoSQL.
  - **Cómo:** Integrar un ORM como SQLAlchemy en la API para registrar todas las peticiones, predicciones y feedback de los usuarios. Esto permitirá re-entrenar el modelo con datos nuevos.

- **Modelos de Lenguaje Avanzados (BERT):**
  - **Qué:** Utilizar modelos Transformer como BERT o RoBERTa para capturar mejor el contexto y la semántica de los mensajes.
  - **Cómo:** Modificar `train/train.py` para usar librerías como `transformers` (de Hugging Face) y `PyTorch`/`TensorFlow`. Esto requerirá una infraestructura de entrenamiento más potente (idealmente con GPUs).

- **Autenticación y Gestión de Usuarios:**
  - **Qué:** Proteger la API y el dashboard para que solo usuarios autorizados puedan acceder.
  - **Cómo:** Implementar OAuth2 en FastAPI (`Depends`) y usar el sistema de gestión de secretos y estado de sesión de Streamlit.

- **Logging y Monitorización Avanzada:**
  - **Qué:** Registrar eventos clave de la aplicación (peticiones, errores, rendimiento del modelo) para monitorización en tiempo real.
  - **Cómo:** Integrar librerías como `loguru` y enviar los logs a plataformas como ELK Stack (Elasticsearch, Logstash, Kibana) o Grafana/Loki.

- **Contenerización (Docker):**
  - **Qué:** Empaquetar cada componente (API, dashboard) en contenedores Docker para un despliegue consistente y aislado.
  - **Cómo:** Crear un `Dockerfile` para cada servicio y un archivo `docker-compose.yml` para orquestar el levantamiento de toda la aplicación con un solo comando.

- **Panel de Control tipo SOC (Security Operations Center):**
  - **Qué:** Desarrollar un dashboard avanzado para analistas de seguridad.
  - **Cómo:** Usar los datos almacenados en la base de datos para crear visualizaciones sobre tendencias de smishing, reglas más activadas, remitentes comunes, etc., utilizando herramientas como Grafana, Kibana o un dashboard de Streamlit más complejo.
