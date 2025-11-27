# rules/rules.py

import re
import json
import os

# --- Carga y Compilación de Reglas Heurísticas ---
# Las reglas se cargan desde un archivo JSON externo y sus patrones regex se compilan.
# Esto permite modificar las reglas sin cambiar el código de la aplicación.

_RULES_FILE = os.path.join(os.path.dirname(__file__), 'rules.json')
_LOADED_RULES = []

try:
    with open(_RULES_FILE, 'r', encoding='utf-8') as f:
        raw_rules = json.load(f)
        for rule in raw_rules:
            # Compile regex patterns after loading
            rule["pattern"] = re.compile(rule["pattern"], re.IGNORECASE)
            _LOADED_RULES.append(rule)
    print(f"Reglas heurísticas cargadas y compiladas desde {_RULES_FILE}")
except FileNotFoundError:
    print(f"Error: No se encontró el archivo de reglas {_RULES_FILE}. Asegúrate de que exista.")
    # Fallback or raise an error if rules are essential for app functionality
except json.JSONDecodeError:
    print(f"Error: {_RULES_FILE} no es un JSON válido.")
except Exception as e:
    print(f"Error al cargar o compilar las reglas: {e}")


def check_heuristic_rules(text: str) -> list:
    """
    Aplica un conjunto de reglas heurísticas a un mensaje de texto.

    Args:
        text (str): El mensaje SMS a analizar.

    Returns:
        list: Una lista de las descripciones de las reglas que se activaron.
              Devuelve una lista vacía si no se activa ninguna regla.
    """
    triggered_rules = []
    # Use _LOADED_RULES instead of HEURISTIC_RULES
    for rule in _LOADED_RULES:
        if rule["pattern"].search(text):
            triggered_rules.append(rule["description"])
    return triggered_rules

if __name__ == '__main__':
    # Ejemplos de uso
    smishing_sms = "URGENTE: Tu cuenta bancaria ha sido comprometida. Reclama tu acceso ahora en http://bit.ly/fakebank"
    legit_sms = "Hola, te recuerdo la cita de mañana a las 10am. Saludos."

    print(f"Analizando mensaje 1: '{smishing_sms}'")
    triggered = check_heuristic_rules(smishing_sms)
    if triggered:
        print("Reglas disparadas:")
        for desc in triggered:
            print(f"- {desc}")
    else:
        print("No se disparó ninguna regla.")

    print("\n" + "="*30 + "\n")

    print(f"Analizando mensaje 2: '{legit_sms}'")
    triggered_2 = check_heuristic_rules(legit_sms)
    if triggered_2:
        print("Reglas disparadas:")
        for desc in triggered_2:
            print(f"- {desc}")
    else:
        print("No se disparó ninguna regla.")