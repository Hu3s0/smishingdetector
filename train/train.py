# train/train.py

import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report
import joblib
import sys
import os

# Añadir el directorio raíz al path para poder importar los módulos locales
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from utils.preprocessing import preprocess_text

# --- Definición de Rutas ---
DATA_PATH = 'data/dataset.csv'
MODELS_DIR = 'models/'
VECTORIZER_PATH = os.path.join(MODELS_DIR, 'vectorizer.pkl')
CLASSIFIER_PATH = os.path.join(MODELS_DIR, 'classifier.pkl')

def train_model():
    """
    Entrena un modelo de clasificación de smishing y lo guarda en disco.
    
    El proceso incluye:
    1. Cargar el dataset.
    2. Preprocesar los textos.
    3. Dividir los datos en conjuntos de entrenamiento y prueba.
    4. Crear y entrenar un vectorizador TF-IDF.
    5. Entrenar un clasificador de Regresión Logística.
    6. Evaluar el modelo.
    7. Guardar el vectorizador y el clasificador entrenados.

    # Escalabilidad:
    # - Dataset: Conectar a una base de datos (PostgreSQL, etc.) para leer un dataset
    #   mucho más grande y realista.
    # - Modelos: Experimentar con modelos más avanzados como Naive Bayes, SVM, o
    #   modelos de deep learning como LSTMs o Transformers (BERT) para mejorar la precisión.
    #   Esto requeriría librerías como TensorFlow o PyTorch.
    # - Validación: Implementar validación cruzada (cross-validation) para obtener una
    #   métrica de rendimiento más robusta.
    # - MLOps: Integrar herramientas como MLflow para registrar experimentos, versionar
    #   modelos y gestionar el ciclo de vida del ML.
    """
    print("Iniciando el proceso de entrenamiento del modelo...")

    # 1. Cargar el dataset
    try:
        df = pd.read_csv(DATA_PATH)
        print(f"Dataset cargado correctamente. Forma: {df.shape}")
    except FileNotFoundError:
        print(f"Error: El archivo de datos no se encontró en '{DATA_PATH}'.")
        print("Asegúrate de que 'data/dataset.csv' exista.")
        return

    # 2. Preprocesar los textos
    print("Preprocesando los mensajes de texto...")
    # Se crea una nueva columna para no alterar la original, lo cual es buena práctica
    df['processed_text'] = df['text'].apply(preprocess_text)
    print("Preprocesamiento completado.")

    # Definir características (X) y etiquetas (y)
    X = df['processed_text']
    y = df['label']

    # 3. Dividir datos en entrenamiento y prueba
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"Datos divididos en {len(X_train)} para entrenamiento y {len(X_test)} para prueba.")

    # 4. Vectorización TF-IDF
    print("Entrenando el vectorizador TF-IDF...")
    vectorizer = TfidfVectorizer(max_features=5000) # Limitar a las 5000 palabras más frecuentes
    X_train_tfidf = vectorizer.fit_transform(X_train)
    X_test_tfidf = vectorizer.transform(X_test)
    print("Vectorización completada.")

    # 5. Entrenamiento del clasificador (Regresión Logística)
    print("Entrenando el clasificador de Regresión Logística...")
    classifier = LogisticRegression(random_state=42)
    classifier.fit(X_train_tfidf, y_train)
    print("Entrenamiento del clasificador completado.")

    # 6. Evaluación del modelo
    print("Evaluando el modelo...")
    y_pred = classifier.predict(X_test_tfidf)
    accuracy = accuracy_score(y_test, y_pred)
    report = classification_report(y_test, y_pred, target_names=['Legítimo', 'Smishing'])
    
    print("\n--- Resultados de la Evaluación ---")
    print(f"Precisión (Accuracy): {accuracy:.4f}")
    print("Reporte de Clasificación:")
    print(report)
    print("-----------------------------------\n")

    # 7. Guardar los modelos entrenados
    print("Guardando el vectorizador y el clasificador...")
    # Asegurarse de que el directorio de modelos exista
    os.makedirs(MODELS_DIR, exist_ok=True)
    
    joblib.dump(vectorizer, VECTORIZER_PATH)
    joblib.dump(classifier, CLASSIFIER_PATH)
    
    print(f"Vectorizador guardado en: {VECTORIZER_PATH}")
    print(f"Clasificador guardado en: {CLASSIFIER_PATH}")
    print("\nProceso de entrenamiento finalizado con éxito.")

if __name__ == '__main__':
    train_model()
