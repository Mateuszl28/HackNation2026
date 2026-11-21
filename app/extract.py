"""Ekstrakcja sygnałów z materiału: tekst (OCR), URL/przekierowania, metadane, wiek domeny, hash obrazu."""
import datetime as dt
import html
import io
import re
import unicodedata
from urllib.parse import urlparse

import httpx
from PIL import Image

MOBILE_UA = (
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0 Mobile Safari/537.36"
)

# Leksykon typowych haseł z reklam-oszustw (inwestycje, "cudowne leki", fałszywe newsy)
SCAM_LEXICON = {
    "inwestycja": ["inwestuj", "inwestycj", "zarabiaj", "zarobek", "pasywny dochód", "dochód pasywny",
                    "platforma inwestycyjna", "kryptowalut", "bitcoin", "zysk", "zwrot z inwestycji"],
    "cud_medyczny": ["cudown", "lekarze nienawidzą", "lekarze są w szoku", "w 7 dni", "w 14 dni",
                      "bez recepty", "naturalny sposób", "przełomow", "rewolucyjn", "cukrzyc", "stawy",
                      "nadciśnieni", "odchudz", "schudnij"],
    "pilnosc": ["tylko dziś", "ostatnie sztuki", "ograniczona", "zostało tylko", "nie czekaj",
                 "już dziś", "pospiesz", "dopóki nie usuną", "zanim usuną"],
    "falszywy_news": ["skandal", "szok", "ujawnił", "wywiad", "telewizja", "na żywo", "zakazane",
                       "rząd ukrywa", "banki są wściekłe", "wpadka na wizji"],
    "rejestracja": ["zarejestruj", "wpłać", "depozyt", "250 zł", "1000 zł", "konto", "formularz"],
}

SUSPICIOUS_TLDS = {"xyz", "top", "click", "shop", "online", "site", "live", "info", "buzz", "icu", "cfd", "sbs"}
PLATFORM_DOMAINS = {"facebook.com", "fb.com", "instagram.com", "google.com", "youtube.com",
                    "tiktok.com", "bit.ly", "t.co", "l.facebook.com", "lm.facebook.com"}


def normalize(text: str) -> str:
    return unicodedata.normalize("NFKC", text or "").lower()


def registrable_domain(url_or_host: str) -> str | None:
    if not url_or_host:
        return None
    host = urlparse(url_or_host).hostname if "://" in url_or_host else url_or_host
    if not host:
        return None
    host = host.lower().removeprefix("www.")
    parts = host.split(".")
    # uproszczenie: obsługa typowych 2-poziomowych sufiksów (com.pl, co.uk...)
    if len(parts) >= 3 and parts[-2] in {"com", "co", "org", "net", "gov", "edu"}:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def find_urls(text: str) -> list[str]:
    urls = re.findall(r"https?://[^\s\"'<>]+", text or "")
    bare = re.findall(r"\b(?:[a-z0-9-]+\.)+(?:pl|com|net|org|xyz|top|online|site|shop|info|live|click|eu)\b(?:/[^\s]*)?",
                      normalize(text))
    out = list(dict.fromkeys(urls + [b if b.startswith("http") else "https://" + b for b in bare]))
    return out[:5]


def extract_keywords(text: str) -> list[str]:
    t = normalize(text)
    hits = []
    for theme, phrases in SCAM_LEXICON.items():
        for p in phrases:
            if p in t:
                hits.append(f"{theme}:{p}")
    return sorted(set(hits))


def match_persons(text: str, persons: list[dict]) -> list[int]:
    t = normalize(text)
    found = []
    for p in persons:
        names = [p["name"]] + list(p.get("aliases") or [])
        if any(normalize(n) in t for n in names if n):
            found.append(p["id"])
    return found


def ocr_image(data: bytes) -> str:
    try:
        import pytesseract  # opcjonalne
        img = Image.open(io.BytesIO(data))
        return pytesseract.image_to_string(img, lang="pol+eng")
    except Exception:
        return ""


def dhash(data: bytes, size: int = 8) -> str | None:
    """Perceptual difference hash (64 bity) – wykrywa ten sam szablon/grafikę mimo kompresji i skalowania."""
    try:
        img = Image.open(io.BytesIO(data)).convert("L").resize((size + 1, size), Image.LANCZOS)
    except Exception:
        return None
    px = list(img.getdata())
    bits = 0
    for row in range(size):
        for col in range(size):
            left = px[row * (size + 1) + col]
            right = px[row * (size + 1) + col + 1]
            bits = (bits << 1) | (1 if left > right else 0)
    return f"{bits:016x}"


def _meta(html_text: str, name: str) -> str | None:
    m = re.search(
        rf'<meta[^>]+(?:name|property)=["\']{re.escape(name)}["\'][^>]+content=["\']([^"\']*)', html_text, re.I
    ) or re.search(
        rf'<meta[^>]+content=["\']([^"\']*)["\'][^>]+(?:name|property)=["\']{re.escape(name)}["\']', html_text, re.I
    )
    return html.unescape(m.group(1)).strip() if m else None


async def analyze_url(url: str) -> dict:
    """Śledzi łańcuch przekierowań (z mobilnym UA, bo fejki często cloakują) i zbiera metadane strony."""
    result = {"input_url": url, "final_url": url, "redirect_chain": [url], "title": None,
              "description": None, "page_text": "", "error": None}
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=10, headers={"User-Agent": MOBILE_UA},
                                     verify=False) as client:
            r = await client.get(url)
            chain = [str(h.url) for h in r.history] + [str(r.url)]
            result["redirect_chain"] = chain
            result["final_url"] = str(r.url)
            body = r.text[:500_000]
            # proste przekierowania JS / meta-refresh
            m = re.search(r'http-equiv=["\']refresh["\'][^>]+url=([^"\'>]+)', body, re.I) or \
                re.search(r'(?:window\.)?location(?:\.href)?\s*=\s*["\'](https?://[^"\']+)', body)
            if m and len(chain) < 8:
                nxt = m.group(1).strip()
                result["redirect_chain"].append(nxt)
                result["final_url"] = nxt
            t = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
            result["title"] = html.unescape(t.group(1)).strip()[:300] if t else _meta(body, "og:title")
            result["description"] = _meta(body, "description") or _meta(body, "og:description")
            text = re.sub(r"<(script|style)[^>]*>.*?</\1>", " ", body, flags=re.S | re.I)
            text = re.sub(r"<[^>]+>", " ", text)
            result["page_text"] = re.sub(r"\s+", " ", html.unescape(text))[:5000]
    except Exception as e:  # sieć / DNS / timeout – zapisujemy, ale nie przerywamy analizy
        result["error"] = f"{type(e).__name__}: {e}"[:300]
    return result


async def domain_age_days(domain: str) -> int | None:
    """Wiek domeny z RDAP (publiczny, bez klucza API)."""
    if not domain:
        return None
    try:
        async with httpx.AsyncClient(timeout=6, follow_redirects=True) as client:
            r = await client.get(f"https://rdap.org/domain/{domain}")
            if r.status_code != 200:
                return None
            for ev in r.json().get("events", []):
                if ev.get("eventAction") == "registration":
                    reg = dt.datetime.fromisoformat(ev["eventDate"].replace("Z", "+00:00"))
                    return (dt.datetime.now(dt.timezone.utc) - reg).days
    except Exception:
        return None
    return None


def risk_score(ad: dict) -> tuple[float, list[str]]:
    reasons, score = [], 0.0
    themes = {k.split(":")[0] for k in ad.get("keywords") or []}
    if themes:
        score += min(0.4, 0.12 * len(themes))
        reasons.append("hasła typowe dla oszustw: " + ", ".join(sorted(themes)))
    age = ad.get("domain_age_days")
    if age is not None and age < 180:
        score += 0.25
        reasons.append(f"młoda domena ({age} dni)")
    chain = ad.get("redirect_chain") or []
    if len({registrable_domain(u) for u in chain}) > 2:
        score += 0.15
        reasons.append(f"łańcuch przekierowań przez {len(chain)} adresów")
    dom = ad.get("domain") or ""
    if dom.split(".")[-1] in SUSPICIOUS_TLDS:
        score += 0.1
        reasons.append(f"podejrzana domena najwyższego poziomu .{dom.split('.')[-1]}")
    if ad.get("persons"):
        score += 0.2
        reasons.append("wykorzystany wizerunek/nazwisko osoby publicznej")
    return round(min(score, 1.0), 2), reasons
