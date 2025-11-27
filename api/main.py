# api/main.py

import joblib
from fastapi import FastAPI, HTTPException, Depends
from fastapi.responses import FileResponse
from pydantic import BaseModel
import os
import sys
from datetime import datetime

# SQLAlchemy imports
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy.orm import Session # Import Session for type hinting


# Añadir el directorio raíz al path para poder importar los módulos locales
# Esto es crucial para que la API pueda encontrar 'utils' y 'rules'
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from utils.preprocessing import preprocess_text
from rules.rules import check_heuristic_rules


# --- Configuración de la Base de Datos ---
# Define la URL de la base de datos SQLite.
# El 'db/' es relativo a donde se ejecuta la API (dentro del contenedor, /app/db)
DATABASE_URL = "sqlite:////tmp/db/predictions.sqlite"

# Crea el motor de SQLAlchemy
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})

# Crea una clase SessionLocal para cada sesión de base de datos
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base para los modelos declarativos de SQLAlchemy
Base = declarative_base()

# --- Definición del Modelo de Base de Datos ---
class Prediction(Base):
    __tablename__ = "predictions"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    sms_text = Column(String)
    prediction_label = Column(String)
    prediction_score = Column(Float)

# Función para crear las tablas en la base de datos
def create_db_tables():
    Base.metadata.create_all(bind=engine)

# Dependency para obtener una sesión de base de datos
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- Creación de la App FastAPI ---
app = FastAPI(
    title="Smishing Detector API",
    description="Una API para detectar mensajes de smishing usando un modelo de ML y reglas heurísticas.",
    version="1.0.0"
)

vectorizer = None
classifier = None

@app.on_event("startup")
async def startup_event():
    global vectorizer, classifier
    # Create database tables
    create_db_tables()
    print("Database tables ensured.")

    # Load models
    MODELS_DIR = 'models/'
    VECTORIZER_PATH = os.path.join(MODELS_DIR, 'vectorizer.pkl')
    CLASSIFIER_PATH = os.path.join(MODELS_DIR, 'classifier.pkl')

    try:
        vectorizer = joblib.load(VECTORIZER_PATH)
        classifier = joblib.load(CLASSIFIER_PATH)
        print("Modelos cargados correctamente.")
    except FileNotFoundError:
        # Raise an error to prevent the app from starting if models are missing
        raise RuntimeError(
            "Error: No se encontraron los archivos del modelo. "
            "Asegúrate de ejecutar 'train/train.py' primero y que los modelos estén en la ruta correcta."
        )
    except Exception as e:
        raise RuntimeError(f"Error al cargar los modelos: {e}")

# --- Modelos de Datos (Pydantic) ---
class PredictionRequest(BaseModel):
    message: str

class PredictionResponse(BaseModel):
    prediction: str
    score: float
    triggered_rules: list[str]

# --- Endpoints de la API ---

@app.get("/", response_class=FileResponse, tags=["General"])
def read_root():
    """
    Endpoint raíz que sirve la página de análisis de mensajes.
    """
    return os.path.join(os.path.dirname(__file__), "index.html")

@app.post("/predict", response_model=PredictionResponse, tags=["Prediction"])
def predict_smishing(request: PredictionRequest, db: Session = Depends(get_db)):
    """
    Analiza un mensaje SMS para detectar si es smishing.

    Recibe un mensaje de texto y devuelve:
    - **prediction**: "smishing" o "legítimo".
    - **score**: La probabilidad de que el mensaje sea smishing (de 0.0 a 1.0).
    - **triggered_rules**: Una lista de las reglas heurísticas que se activaron.
    """
    # Models are guaranteed to be loaded by the startup event
    # No need for 'if not vectorizer or not classifier:' check here.

    sms_text = request.message

    # 1. Aplicar reglas heurísticas sobre el texto original
    triggered_rules = check_heuristic_rules(sms_text)

    # 2. Preprocesar el texto para el modelo de ML
    processed_text = preprocess_text(sms_text)

    # 3. Vectorizar el texto preprocesado
    text_tfidf = vectorizer.transform([processed_text])

    # 4. Realizar la predicción y obtener probabilidades
    prediction_proba = classifier.predict_proba(text_tfidf)
    smishing_score = prediction_proba[0][1] # Probabilidad de la clase '1' (smishing)
    
    # 5. Determinar la etiqueta final
    # Se puede definir un umbral. Aquí usamos 0.5 como umbral por defecto.
    prediction_label = "smishing" if smishing_score > 0.5 else "legítimo"

    # 6. Guardar la predicción en la base de datos
    db_prediction = Prediction(
        sms_text=sms_text,
        prediction_label=prediction_label,
        prediction_score=smishing_score,
        timestamp=datetime.utcnow() # Ensure the timestamp is set
    )
    db.add(db_prediction)
    db.commit()
    db.refresh(db_prediction) # Refresh to get the generated ID and timestamp

    # Escalabilidad:
    # - Logging: Aquí se debería registrar la petición, el texto y la respuesta.
    #   (ej. usando el módulo `logging` de Python).
    # - Autenticación: Se podría proteger este endpoint para que solo usuarios
    #   autenticados puedan usarlo (ej. con FastAPI's `Depends` y OAuth2).

    return {
        "prediction": prediction_label,
        "score": smishing_score,
        "triggered_rules": triggered_rules
    }


# Para ejecutar la API, usa el comando:
# uvicorn api.main:app --reload
#
# El flag --reload es útil para desarrollo, ya que reinicia el servidor
# automáticamente cuando detecta cambios en el código.
