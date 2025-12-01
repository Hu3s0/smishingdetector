import joblib
from fastapi import FastAPI, HTTPException, Depends, Query
from fastapi.responses import FileResponse
from pydantic import BaseModel
import os
import sys
import json
import asyncio
from datetime import datetime, timedelta, date
import time # Import time for latency calculation
from typing import Optional, Any # Import Optional

# SQLAlchemy imports
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Text
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy.orm import Session # Import Session for type hinting
from sqlalchemy import func # Import func for date truncation


# Añadir el directorio raíz al path para poder importar los módulos locales
# Esto es crucial para que la API pueda encontrar 'utils' y 'rules'
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from utils.preprocessing import preprocess_text
from rules.rules import check_heuristic_rules
from utils.virustotal import extract_urls, analyze_url_with_virustotal


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
    triggered_rules = Column(String) # New column for triggered rules
    latency_ms = Column(Float, nullable=True) # New column for API latency
    virustotal_report = Column(Text, nullable=True) # New column for VirusTotal report

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
    ml_relevant_tokens: Optional[dict[str, list[str]]] = None # New field for XAI tokens
    virustotal_analysis: Optional[list[dict[str, Any]]] = None # New field for VirusTotal analysis

# --- Definición del Modelo de Base de Datos para Feedback ---
class Feedback(Base):
    __tablename__ = "feedback"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    original_message = Column(String)
    original_prediction_label = Column(String)
    original_prediction_score = Column(Float)
    feedback_type = Column(String) # e.g., "false_positive", "false_negative"

class FeedbackRequest(BaseModel):
    original_message: str
    original_prediction_label: str
    original_prediction_score: float
    feedback_type: str

class KPIResponse(BaseModel):
    total_analyzed: int
    smishing_detection_rate: float
    avg_api_latency_ms: float

class SmishingTrendItem(BaseModel):
    timestamp: datetime
    count: int

class RuleTrendItem(BaseModel):
    rule_name: str
    count: int

class TrendResponse(BaseModel):
    smishing_trend_hourly: list[SmishingTrendItem]
    top_10_rules: list[RuleTrendItem]

# --- Endpoints de la API ---

@app.get("/", response_class=FileResponse, tags=["General"])
def read_root():
    """
    Endpoint raíz que sirve la página de análisis de mensajes.
    """
    return os.path.join(os.path.dirname(__file__), "index.html")

@app.post("/predict", response_model=PredictionResponse, tags=["Prediction"])
async def predict_smishing(request: PredictionRequest, db: Session = Depends(get_db)):
    """
    Analiza un mensaje SMS para detectar si es smishing.

    Recibe un mensaje de texto y devuelve:
    - **prediction**: "smishing" o "legítimo".
    - **score**: La probabilidad de que el mensaje sea smishing (de 0.0 a 1.0).
    - **triggered_rules**: Una lista de las reglas heurísticas que se activaron.
    - **virustotal_analysis**: El resultado del análisis de URLs en VirusTotal.
    """
    start_time = time.time()
    sms_text = request.message
    virustotal_results = []

    # 1. Extraer y analizar URLs con VirusTotal
    urls = extract_urls(sms_text)
    if urls:
        tasks = [analyze_url_with_virustotal(url) for url in urls]
        virustotal_results = await asyncio.gather(*tasks)

    # 2. Aplicar reglas heurísticas
    triggered_rules = check_heuristic_rules(sms_text)

    # 3. Preprocesar y predecir con el modelo de ML
    processed_text = preprocess_text(sms_text)
    text_tfidf = vectorizer.transform([processed_text])
    prediction_proba = classifier.predict_proba(text_tfidf)
    smishing_score_raw = prediction_proba[0][1]

    # 4. Ajustar la puntuación basada en el análisis de VirusTotal
    is_vt_malicious = any(res.get("positives", 0) > 0 for res in virustotal_results)
    if is_vt_malicious:
        smishing_score_raw = 1.0  # Forzar la puntuación a 100% si VT detecta algo
        if "URL maliciosa detectada por VirusTotal" not in triggered_rules:
            triggered_rules.append("URL maliciosa detectada por VirusTotal")

    # 5. Determinar la etiqueta final
    prediction_label = "smishing" if smishing_score_raw > 0.5 else "legítimo"
    smishing_score_scaled = round(smishing_score_raw * 100, 2)
    
    end_time = time.time()
    latency_ms = (end_time - start_time) * 1000

    # 6. Guardar la predicción en la base de datos
    db_prediction = Prediction(
        sms_text=sms_text,
        prediction_label=prediction_label,
        prediction_score=smishing_score_raw,
        timestamp=datetime.utcnow(),
        triggered_rules=",".join(triggered_rules),
        latency_ms=latency_ms,
        virustotal_report=json.dumps(virustotal_results) if virustotal_results else None
    )
    db.add(db_prediction)
    db.commit()
    db.refresh(db_prediction)

    # 7. Preparar tokens de XAI del modelo
    ml_relevant_tokens = {"smishing": [], "legitimo": []}
    if hasattr(classifier, 'coef_') and vectorizer:
        feature_names = vectorizer.get_feature_names_out()
        coef = classifier.coef_[0]
        
        sorted_coef_indices = coef.argsort()
        
        top_smishing_indices = [i for i in sorted_coef_indices[::-1] if coef[i] > 0][:5]
        ml_relevant_tokens["smishing"] = [feature_names[i] for i in top_smishing_indices]
        
        top_legitimo_indices = [i for i in sorted_coef_indices if coef[i] < 0][:5]
        ml_relevant_tokens["legitimo"] = [feature_names[i] for i in top_legitimo_indices]

    return {
        "prediction": prediction_label,
        "score": smishing_score_scaled,
        "triggered_rules": triggered_rules,
        "ml_relevant_tokens": ml_relevant_tokens,
        "virustotal_analysis": virustotal_results
    }

@app.post("/feedback", tags=["Feedback"])
def post_feedback(request: FeedbackRequest, db: Session = Depends(get_db)):
    db_feedback = Feedback(
        original_message=request.original_message,
        original_prediction_label=request.original_prediction_label,
        original_prediction_score=request.original_prediction_score,
        feedback_type=request.feedback_type,
        timestamp=datetime.utcnow()
    )
    db.add(db_feedback)
    db.commit()
    db.refresh(db_feedback)
    return {"message": "Feedback received successfully", "feedback_id": db_feedback.id}


@app.get("/metrics/kpis", response_model=KPIResponse, tags=["Metrics"])
def get_kpis(
    db: Session = Depends(get_db),
    start_date: Optional[date] = Query(None),
    end_date: Optional[date] = Query(None),
    risk_level: Optional[str] = Query(None)
):
    query = db.query(Prediction)

    # Apply date filters
    if start_date:
        query = query.filter(Prediction.timestamp >= start_date)
    if end_date:
        query = query.filter(Prediction.timestamp < (end_date + timedelta(days=1))) # Include the whole end_date
    
    # Apply risk level filter
    if risk_level:
        if risk_level == "Riesgo Alto":
            query = query.filter(Prediction.prediction_score > 0.7)
        elif risk_level == "Riesgo Medio":
            query = query.filter(Prediction.prediction_score >= 0.4, Prediction.prediction_score <= 0.7)
        elif risk_level == "Riesgo Bajo":
            query = query.filter(Prediction.prediction_score < 0.4)

    total_analyzed = query.count()
    smishing_detections = query.filter(Prediction.prediction_label == "smishing").count()

    smishing_detection_rate = (smishing_detections / total_analyzed * 100) if total_analyzed > 0 else 0.0

    avg_latency = query.with_entities(func.avg(Prediction.latency_ms)).scalar() # Calculate avg latency on the filtered query

    return {
        "total_analyzed": total_analyzed,
        "smishing_detection_rate": round(smishing_detection_rate, 2),
        "avg_api_latency_ms": round(avg_latency, 2) if avg_latency is not None else 0.0
    }


@app.get("/metrics/trends", response_model=TrendResponse, tags=["Metrics"])
def get_trends(
    db: Session = Depends(get_db),
    start_date: Optional[date] = Query(None),
    end_date: Optional[date] = Query(None),
    risk_level: Optional[str] = Query(None)
):
    base_query = db.query(Prediction)

    # Apply date filters to the base query
    if start_date:
        base_query = base_query.filter(Prediction.timestamp >= start_date)
    if end_date:
        base_query = base_query.filter(Prediction.timestamp < (end_date + timedelta(days=1)))
    
    # Apply risk level filter to the base query
    if risk_level:
        if risk_level == "Riesgo Alto":
            base_query = base_query.filter(Prediction.prediction_score > 0.7)
        elif risk_level == "Riesgo Medio":
            base_query = base_query.filter(Prediction.prediction_score >= 0.4, Prediction.prediction_score <= 0.7)
        elif risk_level == "Riesgo Bajo":
            base_query = base_query.filter(Prediction.prediction_score < 0.4)

    # Smishing Trend (hourly for the last 24 hours, or filtered date range)
    smishing_trend_data = []
    
    # Determine the time range for the trends. If dates are provided, use them. Otherwise, default to last 24 hours.
    if start_date and end_date:
        current_end_time = datetime.combine(end_date, datetime.min.time()) + timedelta(days=1)
        current_start_time = datetime.combine(start_date, datetime.min.time())
    else:
        current_end_time = datetime.utcnow()
        current_start_time = datetime.utcnow() - timedelta(hours=24) # Default to last 24h if no filters

    # Generate hourly buckets. This assumes trends are hourly.
    # We'll go from oldest to newest hour within the selected range
    time_buckets = []
    temp_time = current_start_time
    while temp_time < current_end_time:
        time_buckets.append(temp_time)
        temp_time += timedelta(hours=1)
    
    if not time_buckets: # Handle cases where start_date == end_date or range is too small
        time_buckets.append(current_start_time)
        time_buckets.append(current_end_time)


    for i in range(len(time_buckets) - 1):
        bucket_start = time_buckets[i]
        bucket_end = time_buckets[i+1] if i < len(time_buckets) - 1 else current_end_time

        smishing_count = base_query.filter(
            Prediction.timestamp >= bucket_start,
            Prediction.timestamp < bucket_end,
            Prediction.prediction_label == "smishing"
        ).count()
        smishing_trend_data.append(SmishingTrendItem(timestamp=bucket_start, count=smishing_count))

    # Top 10 Activated Rules
    all_triggered_rules = base_query.with_entities(Prediction.triggered_rules).all()
    rule_counts = {}
    for entry in all_triggered_rules:
        if entry.triggered_rules:
            rules = [r.strip() for r in entry.triggered_rules.split(',')]
            for rule in rules:
                if rule: # Avoid empty strings from split
                    rule_counts[rule] = rule_counts.get(rule, 0) + 1
    
    top_10_rules_list = sorted(rule_counts.items(), key=lambda item: item[1], reverse=True)[:10]
    top_10_rules_data = [RuleTrendItem(rule_name=name, count=count) for name, count in top_10_rules_list]

    return TrendResponse(
        smishing_trend_hourly=smishing_trend_data, # Show in chronological order
        top_10_rules=top_10_rules_data
    )

# Para ejecutar la API, usa el comando:
# uvicorn api.main:app --reload
#
# El flag --reload es útil para desarrollo, ya que reinicia el servidor
# automáticamente cuando detecta cambios en el código.
