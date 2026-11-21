"""Pobiera modele twarzy z OpenCV Zoo do katalogu models/ (aplikacja robi to też sama przy pierwszym użyciu).

  YuNet  – wykrywanie twarzy, licencja MIT
  SFace  – wektory cech twarzy (128-d), licencja Apache 2.0

Uruchomienie:  python tools/get_models.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from app.vision import MODELS_DIR, ensure_models  # noqa: E402

if __name__ == "__main__":
    ok = ensure_models(download=True)
    print("Modele gotowe w" if ok else "Nie udało się pobrać modeli do", MODELS_DIR)
    sys.exit(0 if ok else 1)
