# utils/preprocessing.py

import re
import string

def preprocess_text(text: str) -> str:
    """
    Limpia y normaliza el texto de un mensaje SMS.

    Args:
        text (str): El mensaje SMS original.

    Returns:
        str: El mensaje preprocesado.
    
    # Escalabilidad:
    # - Se podría añadir lematización o stemming para reducir palabras a su raíz.
    #   (ej. usando NLTK o Spacy).
    # - Considerar la gestión de emojis, convirtiéndolos a texto o eliminándolos.
    # - Mejorar la extracción y tratamiento de entidades como fechas, números de teléfono, etc.
    """
    # Convertir a minúsculas
    text = text.lower()
    
    # Eliminar signos de puntuación
    text = text.translate(str.maketrans('', '', string.punctuation))
    
    # Eliminar caracteres especiales y números (dejando texto)
    # Se mantienen los números por si son relevantes (ej. "llama al 900..."),
    # pero se podría optar por eliminarlos con `re.sub(r'\d+', '', text)`.
    text = re.sub(r'[^a-z\s]', '', text)
    
    # Eliminar espacios extra
    text = " ".join(text.split())
    
    return text

def extract_urls(text: str) -> list:
    """
    Extrae todas las URLs de un texto.

    Args:
        text (str): El texto del que extraer URLs.

    Returns:
        list: Una lista de URLs encontradas.
    """
    # Expresión regular para encontrar URLs
    # Esta es una regex simple, se puede mejorar para cubrir más casos.
    url_pattern = re.compile(r'https?://\S+|www\.\S+')
    return url_pattern.findall(text)

if __name__ == '__main__':
    # Ejemplo de uso
    sample_sms = "Felicidades! Has ganado un premio de $1000. Reclama aquí: http://bit.ly/premiofalso. Llama ya!"
    
    # Extraer URLs antes de preprocesar el texto principal
    urls = extract_urls(sample_sms)
    print(f"URLs encontradas: {urls}")

    # Preprocesar el texto
    cleaned_text = preprocess_text(sample_sms)
    print(f"Texto original: '{sample_sms}'")
    print(f"Texto preprocesado: '{cleaned_text}'")

    sample_sms_2 = "URGENTE: Tu cuenta ha sido comprometida. Verifica tu identidad en http://bancofalso.com/login"
    urls_2 = extract_urls(sample_sms_2)
    cleaned_text_2 = preprocess_text(sample_sms_2)
    print(f"\nURLs encontradas: {urls_2}")
    print(f"Texto original: '{sample_sms_2}'")
    print(f"Texto preprocesado: '{cleaned_text_2}'")
