"""Analiza obrazu: OCR zrzutów ekranu i rozpoznawanie twarzy z bazy referencyjnej.

OCR – pierwszy dostępny silnik (wszystkie na otwartych licencjach):
  1. Tesseract (Apache 2.0) przez pytesseract – najlepszy dla polskiego (język "pol"), wymaga instalacji programu,
  2. RapidOCR (Apache 2.0, onnxruntime) – działa od razu po `pip install`, modele w paczce,
  3. EasyOCR (Apache 2.0) – jeśli zainstalowany (ciągnie PyTorch).

Twarze – modele z OpenCV Zoo uruchamiane przez wbudowane w OpenCV API (bez PyTorch/insightface):
  - wykrywanie: YuNet (MIT)                  cv2.FaceDetectorYN
  - wektor cech: SFace (Apache 2.0), 128-d   cv2.FaceRecognizerSF
  insightface świadomie NIE jest używany – jego gotowe modele mają licencję niekomercyjną, co koliduje
  z przeniesieniem praw autorskich do kodu i utworów.
  Próg dopasowania: cosinus ≥ 0.363 (wartość rekomendowana przez autorów SFace).
"""
from __future__ import annotations

import io
import shutil
import threading
import urllib.request
from pathlib import Path

import numpy as np
from PIL import Image, ImageOps

MODELS_DIR = Path(__file__).resolve().parent.parent / "models"
ZOO = "https://github.com/opencv/opencv_zoo/raw/main/models"
MODEL_FILES = {
    "yunet": ("face_detection_yunet_2023mar.onnx", f"{ZOO}/face_detection_yunet/face_detection_yunet_2023mar.onnx"),
    "sface": ("face_recognition_sface_2021dec.onnx", f"{ZOO}/face_recognition_sface/face_recognition_sface_2021dec.onnx"),
}
FACE_MATCH_THRESHOLD = 0.363     # cosinus SFace: ta sama osoba
FACE_MIN_SCORE = 0.8             # pewność detekcji YuNet
FACE_MIN_SIZE = 28               # px – mniejsze twarze są zbyt niewyraźne do porównania
_lock = threading.Lock()


# ================================================================= wspólne
def load_image(data: bytes) -> Image.Image | None:
    try:
        img = Image.open(io.BytesIO(data))
        img = ImageOps.exif_transpose(img)  # zdjęcia z telefonu bywają obrócone w EXIF
        return img.convert("RGB")
    except Exception:
        return None


def _to_bgr(img: Image.Image) -> np.ndarray:
    return np.ascontiguousarray(np.asarray(img)[:, :, ::-1])


# ================================================================= OCR
_ocr_engine = None
_ocr_name: str | None = None


def _tesseract_cmd() -> str | None:
    for c in (shutil.which("tesseract"), r"C:\Program Files\Tesseract-OCR\tesseract.exe",
              r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe"):
        if c and Path(c).exists():
            return c
    return None


def ocr_backend() -> str | None:
    """Wybiera i inicjalizuje (raz) silnik OCR. Zwraca jego nazwę albo None."""
    global _ocr_engine, _ocr_name
    with _lock:
        if _ocr_name is not None:
            return _ocr_name or None
        try:
            import pytesseract
            cmd = _tesseract_cmd()
            if cmd:
                pytesseract.pytesseract.tesseract_cmd = cmd
                langs = pytesseract.get_languages()
                _ocr_engine = ("tesseract", "pol+eng" if "pol" in langs else "eng")
                _ocr_name = f"tesseract ({_ocr_engine[1]})"
                return _ocr_name
        except Exception:
            pass
        try:
            from rapidocr_onnxruntime import RapidOCR
            _ocr_engine = ("rapidocr", RapidOCR())
            _ocr_name = "rapidocr"
            return _ocr_name
        except Exception:
            pass
        try:
            import easyocr
            _ocr_engine = ("easyocr", easyocr.Reader(["pl", "en"], gpu=False, verbose=False))
            _ocr_name = "easyocr"
            return _ocr_name
        except Exception:
            pass
        _ocr_name = ""
        return None


def _prepare_for_ocr(img: Image.Image) -> Image.Image:
    # zrzuty z telefonu bywają małe/ściśnięte – powiększenie wyraźnie poprawia rozpoznawanie
    w, h = img.size
    scale = 1600 / max(w, h) if max(w, h) < 1000 else (2400 / max(w, h) if max(w, h) > 2400 else 1)
    return img.resize((int(w * scale), int(h * scale)), Image.LANCZOS) if scale != 1 else img


def ocr_image(data: bytes) -> dict:
    """{'text': str, 'backend': str|None, 'lines': [{'text', 'conf'}]} – pusty tekst, gdy brak silnika/obrazu."""
    img = load_image(data)
    backend = ocr_backend()
    if img is None or not backend:
        return {"text": "", "backend": backend, "lines": []}
    img = _prepare_for_ocr(img)
    kind, engine = _ocr_engine
    lines: list[dict] = []
    try:
        if kind == "tesseract":
            import pytesseract
            d = pytesseract.image_to_data(img, lang=engine, output_type=pytesseract.Output.DICT)
            rows: dict[tuple, list] = {}
            for i, word in enumerate(d["text"]):
                if word.strip() and float(d["conf"][i]) > 30:
                    rows.setdefault((d["block_num"][i], d["par_num"][i], d["line_num"][i]), []).append(
                        (word, float(d["conf"][i]) / 100))
            lines = [{"text": " ".join(w for w, _ in ws), "conf": round(sum(c for _, c in ws) / len(ws), 2)}
                     for ws in rows.values()]
        elif kind == "rapidocr":
            result, _ = engine(np.asarray(img))
            for box, text, conf in sorted(result or [], key=lambda r: (round(r[0][0][1] / 12), r[0][0][0])):
                if float(conf) > 0.5:
                    lines.append({"text": text, "conf": round(float(conf), 2)})
        elif kind == "easyocr":
            for box, text, conf in engine.readtext(np.asarray(img)):
                if conf > 0.3:
                    lines.append({"text": text, "conf": round(float(conf), 2)})
    except Exception as e:  # OCR nie może zatrzymać analizy
        return {"text": "", "backend": backend, "lines": [], "error": f"{type(e).__name__}: {e}"[:200]}
    return {"text": "\n".join(l["text"] for l in lines), "backend": backend, "lines": lines}


# ================================================================= twarze
_detector = None
_recognizer = None


def ensure_models(download: bool = True) -> bool:
    MODELS_DIR.mkdir(exist_ok=True)
    for name, url in MODEL_FILES.values():
        p = MODELS_DIR / name
        if p.exists() and p.stat().st_size > 100_000:
            continue
        if not download:
            return False
        try:
            tmp = p.with_suffix(".part")
            urllib.request.urlretrieve(url, tmp)
            tmp.replace(p)
        except Exception:
            return False
    return True


def _face_models():
    global _detector, _recognizer
    with _lock:
        if _detector is None:
            import cv2
            if not ensure_models():
                return None, None
            _detector = cv2.FaceDetectorYN.create(str(MODELS_DIR / MODEL_FILES["yunet"][0]), "", (320, 320),
                                                  FACE_MIN_SCORE, 0.3, 5000)
            _recognizer = cv2.FaceRecognizerSF.create(str(MODELS_DIR / MODEL_FILES["sface"][0]), "")
    return _detector, _recognizer


def faces_available() -> bool:
    try:
        return _face_models()[0] is not None
    except Exception:
        return False


def face_embeddings(data: bytes, max_faces: int = 8) -> list[dict]:
    """Wykrywa twarze i zwraca dla każdej: box [x,y,w,h] (w pikselach oryginału), score, embedding (128 float)."""
    img = load_image(data)
    if img is None:
        return []
    try:
        det, rec = _face_models()
    except Exception:
        return []
    if det is None:
        return []
    w, h = img.size
    scale = min(1.0, 1280 / max(w, h))
    if scale < 1:
        img = img.resize((int(w * scale), int(h * scale)), Image.LANCZOS)
    bgr = _to_bgr(img)
    with _lock:
        det.setInputSize((bgr.shape[1], bgr.shape[0]))
        _, faces = det.detect(bgr)
        out = []
        for f in (faces if faces is not None else [])[:max_faces]:
            if f[2] < FACE_MIN_SIZE or f[3] < FACE_MIN_SIZE:
                continue
            aligned = rec.alignCrop(bgr, f)
            emb = rec.feature(aligned).flatten().astype(np.float32)
            emb /= (np.linalg.norm(emb) or 1)
            out.append({"box": [round(float(v) / scale) for v in f[:4]], "score": round(float(f[14]), 3),
                        "embedding": [round(float(v), 5) for v in emb]})
    return sorted(out, key=lambda x: -x["box"][2] * x["box"][3])


def cosine(a: list[float], b: list[float]) -> float:
    va, vb = np.asarray(a, dtype=np.float32), np.asarray(b, dtype=np.float32)
    na, nb = np.linalg.norm(va), np.linalg.norm(vb)
    return float(va @ vb / (na * nb)) if na and nb else 0.0


def match_faces(faces: list[dict], references: list[dict]) -> list[dict]:
    """references: [{'person_id', 'name', 'embedding'}]. Zwraca dla każdej twarzy najlepsze dopasowanie ≥ progu."""
    matches = []
    for i, f in enumerate(faces):
        best = max(((cosine(f["embedding"], r["embedding"]), r) for r in references), default=(0.0, None),
                   key=lambda t: t[0])
        if best[1] is not None and best[0] >= FACE_MATCH_THRESHOLD:
            matches.append({"face": i, "person_id": best[1]["person_id"], "name": best[1]["name"],
                            "similarity": round(best[0], 3)})
    return matches


def status() -> dict:
    return {"ocr": ocr_backend(), "faces": faces_available(),
            "tesseract_installed": bool(_tesseract_cmd()), "models_dir": str(MODELS_DIR)}
