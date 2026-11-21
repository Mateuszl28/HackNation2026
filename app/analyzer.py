"""Analiza w tle – ekstrakcja sygnałów z materiału.

1. Przekierowania: śledzenie łańcucha z User-Agentem smartfona (Android Chrome / iPhone Mobile Safari),
   każdy hop osobno (HTTP 3xx, meta-refresh, przekierowanie JS) + test cloakingu (UA desktopowy).
   Domeny fikcyjne (*.example.pl, *.example, *.test, *.invalid) i adresy z danych demo są rozwiązywane
   lokalnie, więc demo działa offline bez błędów sieciowych.
2. Wiek domeny: RDAP – serwer rejestru wskazany przez IANA bootstrap (np. rdap.dns.pl dla .pl,
   rdap.verisign.com dla .com), fallback rdap.org.
3. Hasła: 5 grup (inwestycje, cudowne leki, presja czasu, fałszywe newsy, wpłata/depozyt); dopasowanie
   odporne na brak polskich znaków i zamianę liter na cyfry/symbole (z@r4biaj).
4. Odcisk obrazu: dHash (imagehash + Pillow), odporny na przeskalowanie i kompresję.
5. Osoby: dopasowanie do tabeli persons po imieniu/nazwisku i aliasach, z tolerancją odmiany
   (Wiśniewska -> Wiśniewskiej, Kowalczyk -> Kowalczyka).
"""
import asyncio
import datetime as dt
import html
import io
import json
import re
import unicodedata
from urllib.parse import urljoin, urlparse

import httpx
from PIL import Image

from .db import DATA_DIR, load_json

# ---------------------------------------------------------------- User-Agenty
UA_ANDROID = ("Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) "
              "Chrome/126.0.0.0 Mobile Safari/537.36")
UA_IPHONE = ("Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) "
             "Version/17.5 Mobile/15E148 Safari/604.1")
UA_DESKTOP = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
              "Chrome/126.0.0.0 Safari/537.36")
MOBILE_UA = UA_ANDROID
MAX_HOPS = 10

# ---------------------------------------------------------------- domeny
# sufiksy dwupoziomowe (uproszczona Public Suffix List)
TWO_LEVEL_SUFFIXES = {
    "com.pl", "net.pl", "org.pl", "gov.pl", "edu.pl", "info.pl", "biz.pl", "waw.pl", "krakow.pl", "wroclaw.pl",
    "co.uk", "org.uk", "com.au", "com.br", "co.jp",
    "example.pl", "example.com",  # fikcyjne domeny demo traktujemy jak sufiks, żeby każda była osobną domeną
}
OFFLINE_SUFFIXES = (".example", ".example.pl", ".example.com", ".example.org", ".example.net",
                    ".test", ".invalid", ".localhost")
SUSPICIOUS_TLDS = {"xyz", "top", "click", "shop", "online", "site", "live", "info", "buzz", "icu", "cfd", "sbs"}
# platformy i skracacze – sam ich udział nie łączy reklam w kampanię
PLATFORM_DOMAINS = {"facebook.com", "fb.com", "instagram.com", "google.com", "youtube.com", "tiktok.com",
                    "bit.ly", "t.co", "tinyurl.com", "skroc.example.pl"}

# ---------------------------------------------------------------- 5 grup haseł
PHRASE_GROUPS = {
    "inwestycja": ["inwestuj", "inwestycj", "zarabiaj", "zarobi", "zarobek", "pasywny dochod", "dochod pasywny",
                   "platforma inwestycyjn", "kryptowalut", "bitcoin", "zysk", "zwrot z inwestycji",
                   "gwarantowany zwrot", "bez ryzyka", "automatyczny handel", "robot inwestycyjny"],
    "cud_medyczny": ["cudown", "lekarze nienawidza", "lekarze sa w szoku", "w 7 dni", "w 14 dni", "w 30 dni",
                     "bez recepty", "naturalny sposob", "przelomow", "rewolucyjn", "cukrzyc", "stawy", "stawow",
                     "nadcisnieni", "odchudz", "schudnij", "pasozyt", "wyleczy", "koniec z bolem"],
    "pilnosc": ["tylko dzis", "ostatnie sztuki", "ograniczon", "zostalo tylko", "nie czekaj", "juz dzis",
                "pospiesz", "dopoki nie usuna", "zanim usuna", "promocja konczy sie", "ostatnia szansa"],
    "falszywy_news": ["skandal", "szok", "ujawnil", "ujawnia", "wywiad", "w telewizji", "na zywo", "zakazan",
                      "rzad ukrywa", "banki sa wsciekle", "wpadka na wizji", "sensacj", "potwierdzil"],
    "wplata": ["zarejestruj", "wplac", "depozyt", "250 zl", "1000 zl", "dane konta", "numer karty",
               "formularz", "zwrot", "doplat", "przelew", "kod blik"],
}
GROUP_NAMES = {"inwestycja": "inwestycje", "cud_medyczny": "cudowne leki", "pilnosc": "presja czasu",
               "falszywy_news": "fałszywe newsy", "wplata": "wpłata/depozyt"}
SCAM_LEXICON = PHRASE_GROUPS  # zgodność wsteczna

_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s", "€": "e"})
_PL = str.maketrans("ąćęłńóśźż", "acelnoszz")


def normalize(text: str) -> str:
    """Małe litery + NFKC (z zachowaniem polskich znaków) – do porównań tekstu."""
    return unicodedata.normalize("NFKC", text or "").lower()


def fold(text: str) -> str:
    """Do wyszukiwania haseł: bez polskich znaków i diakrytyków, cyfry/symbole -> litery (OCR, obfuskacja)."""
    t = normalize(text).translate(_PL)
    t = "".join(c for c in unicodedata.normalize("NFKD", t) if not unicodedata.combining(c))
    # zamiana cyfr/symboli tylko w słowach, które zawierają też litery ("z@r4biaj" -> "zarabiaj", "250 zl" bez zmian)
    tokens = [tok.translate(_LEET) if re.search(r"[a-z]", tok) and re.search(r"[0-9@$€]", tok) else tok
              for tok in t.split()]
    return " ".join(tokens)


def registrable_domain(url_or_host: str) -> str | None:
    if not url_or_host:
        return None
    host = urlparse(url_or_host).hostname if "://" in url_or_host else url_or_host.split("/")[0]
    if not host:
        return None
    host = host.lower().removeprefix("www.")
    parts = host.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in TWO_LEVEL_SUFFIXES:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def find_urls(text: str) -> list[str]:
    urls = re.findall(r"https?://[^\s\"'<>]+", text or "")
    bare = re.findall(r"\b(?:[a-z0-9-]+\.)+(?:pl|com|net|org|eu|xyz|top|online|site|shop|info|live|click|icu|sbs|cfd)"
                      r"\b(?:/[^\s]*)?", normalize(text))
    out = list(dict.fromkeys(urls + [b if b.startswith("http") else "https://" + b for b in bare]))
    return out[:5]


def extract_keywords(text: str) -> list[str]:
    """Zwraca listę 'grupa:fraza' dla wszystkich trafień z 5 grup."""
    t = fold(text)
    return sorted({f"{g}:{p}" for g, phrases in PHRASE_GROUPS.items() for p in phrases if p in t})


# ---------------------------------------------------------------- osoby
def _stem(word: str) -> str:
    w = fold(word)
    for suf in ("iego", "ego", "iej", "emu", "owi", "ej", "a", "i", "y", "e", "u", "o"):
        if len(w) - len(suf) >= 4 and w.endswith(suf):
            return w[: -len(suf)]
    return w


def _name_pattern(name: str) -> re.Pattern:
    """Każdy człon nazwy jako rdzeń + dowolna końcówka fleksyjna (do 4 liter)."""
    tokens = [t for t in re.split(r"[\s.-]+", name) if t]
    parts = [re.escape(_stem(t)) + r"\w{0,4}" if len(t) > 3 else re.escape(fold(t)) for t in tokens]
    return re.compile(r"\b" + r"[\s.-]+".join(parts) + r"\b")


def match_persons_detailed(text: str, persons: list[dict]) -> list[dict]:
    t = fold(text)
    out = []
    for p in persons:
        for alias in [p["name"]] + list(p.get("aliases") or []):
            if alias and _name_pattern(alias).search(t):
                out.append({"id": p["id"], "name": p["name"], "matched": alias})
                break
    return out


def match_persons(text: str, persons: list[dict]) -> list[int]:
    return [m["id"] for m in match_persons_detailed(text, persons)]


# ---------------------------------------------------------------- obraz
def ocr_image(data: bytes) -> str:
    try:
        import pytesseract  # opcjonalne – wymaga zainstalowanego Tesseracta z językiem pol
        return pytesseract.image_to_string(Image.open(io.BytesIO(data)), lang="pol+eng")
    except Exception:
        return ""


def dhash(data: bytes, size: int = 8) -> str | None:
    """64-bitowy difference hash jako 16 znaków hex."""
    try:
        img = Image.open(io.BytesIO(data))
        img.load()
    except Exception:
        return None
    try:
        import imagehash
        return str(imagehash.dhash(img, hash_size=size))
    except ImportError:  # fallback bez imagehash – ten sam algorytm
        g = img.convert("L").resize((size + 1, size), Image.LANCZOS)
        px = list(g.getdata())
        bits = 0
        for r in range(size):
            for c in range(size):
                bits = (bits << 1) | (px[r * (size + 1) + c] > px[r * (size + 1) + c + 1])
        return f"{bits:0{size * size // 4}x}"


# ---------------------------------------------------------------- symulowana sieć demo (offline)
_DEMO_WEB: dict | None = None


def demo_web() -> dict:
    """url -> {next, title, description, text, domain_age_days}, zbudowane z łańcuchów w danych demo."""
    global _DEMO_WEB
    if _DEMO_WEB is None:
        web: dict[str, dict] = {}
        for f in ("seed_ads.json", "seed_feed.json", "demo_variants.json"):
            for it in load_json(DATA_DIR / f):
                chain = it.get("redirect_chain") or [it.get("url")]
                for i, u in enumerate(chain):
                    node = web.setdefault(u, {})
                    if i + 1 < len(chain):
                        node["next"] = chain[i + 1]
                    else:
                        node.update({k: it.get(k) for k in ("title", "description", "text", "domain_age_days")})
        _DEMO_WEB = web
    return _DEMO_WEB


def is_offline(url: str) -> bool:
    host = (urlparse(url).hostname or "").lower()
    return url in demo_web() or host.endswith(OFFLINE_SUFFIXES) or host in {s.lstrip(".") for s in OFFLINE_SUFFIXES}


def _simulate(url: str) -> dict:
    web, chain, hops = demo_web(), [url], [{"url": url, "status": 200, "via": "demo"}]
    while url in web and web[url].get("next") and len(chain) < MAX_HOPS:
        hops[-1]["status"] = 302
        url = web[url]["next"]
        chain.append(url)
        hops.append({"url": url, "status": 200, "via": "demo"})
    page = web.get(url, {})
    return {"input_url": chain[0], "final_url": url, "redirect_chain": chain, "hops": hops,
            "title": page.get("title"), "description": page.get("description"), "page_text": page.get("text") or "",
            "offline": True, "domain_age_days": page.get("domain_age_days"), "cloaking": None, "error": None}


# ---------------------------------------------------------------- przekierowania (sieć)
def _meta(body: str, name: str) -> str | None:
    m = re.search(rf'<meta[^>]+(?:name|property)=["\']{re.escape(name)}["\'][^>]+content=["\']([^"\']*)', body, re.I) \
        or re.search(rf'<meta[^>]+content=["\']([^"\']*)["\'][^>]+(?:name|property)=["\']{re.escape(name)}["\']',
                     body, re.I)
    return html.unescape(m.group(1)).strip() if m else None


def _soft_redirect(body: str) -> tuple[str, str] | None:
    m = re.search(r'http-equiv=["\']?refresh["\']?[^>]+content=["\'][^"\']*url=([^"\'>]+)', body, re.I)
    if m:
        return m.group(1).strip(), "meta-refresh"
    m = re.search(r'(?:window|document|top)\.location(?:\.href)?\s*=\s*["\']([^"\']+)["\']', body) or \
        re.search(r'location\.(?:replace|assign)\(\s*["\']([^"\']+)["\']', body)
    return (m.group(1).strip(), "js") if m else None


async def follow_redirects(url: str, ua: str = UA_ANDROID) -> dict:
    hops, body, error = [], "", None
    try:
        async with httpx.AsyncClient(follow_redirects=False, timeout=8, verify=False,
                                     headers={"User-Agent": ua, "Accept-Language": "pl-PL,pl;q=0.9"}) as client:
            cur = url
            for _ in range(MAX_HOPS):
                r = await client.get(cur)
                hops.append({"url": cur, "status": r.status_code, "via": "http"})
                if r.is_redirect and r.headers.get("location"):
                    cur = urljoin(cur, r.headers["location"])
                    continue
                body = r.text[:500_000] if "html" in r.headers.get("content-type", "html") else ""
                soft = _soft_redirect(body)
                if soft and urljoin(cur, soft[0]) not in {h["url"] for h in hops}:
                    hops[-1]["via"] = soft[1]
                    cur = urljoin(cur, soft[0])
                    continue
                break
    except Exception as e:
        error = f"{type(e).__name__}: {e}"[:300]
        if not hops:
            hops.append({"url": url, "status": None, "via": "error"})
    t = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    text = re.sub(r"<(script|style)[^>]*>.*?</\1>", " ", body, flags=re.S | re.I)
    text = re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", " ", text))).strip()
    return {"input_url": url, "final_url": hops[-1]["url"], "redirect_chain": [h["url"] for h in hops], "hops": hops,
            "title": (html.unescape(t.group(1)).strip()[:300] if t else None) or _meta(body, "og:title"),
            "description": _meta(body, "description") or _meta(body, "og:description"),
            "page_text": text[:5000], "offline": False, "domain_age_days": None, "error": error}


async def analyze_url(url: str) -> dict:
    """Łańcuch przekierowań z UA smartfona + porównanie z UA desktopowym (cloaking)."""
    if is_offline(url):
        return _simulate(url)
    mobile, desktop = await asyncio.gather(follow_redirects(url, UA_ANDROID), follow_redirects(url, UA_DESKTOP))
    dm, dd = registrable_domain(mobile["final_url"]), registrable_domain(desktop["final_url"])
    mobile["cloaking"] = ({"mobile": dm, "desktop": dd}
                          if dm and dd and dm != dd and not mobile["error"] and not desktop["error"] else None)
    return mobile


# ---------------------------------------------------------------- RDAP
_RDAP_BOOTSTRAP: dict[str, str] | None = None
_RDAP_CACHE: dict[str, int | None] = {}


async def _rdap_server(tld: str, client: httpx.AsyncClient) -> str:
    global _RDAP_BOOTSTRAP
    if _RDAP_BOOTSTRAP is None:
        try:
            data = (await client.get("https://data.iana.org/rdap/dns.json")).json()
            _RDAP_BOOTSTRAP = {t: urls[0] for tlds, urls in data["services"] for t in tlds}
        except Exception:
            _RDAP_BOOTSTRAP = {}
    base = _RDAP_BOOTSTRAP.get(tld) or {"pl": "https://rdap.dns.pl/"}.get(tld) or "https://rdap.org/"
    return base if base.endswith("/") else base + "/"


async def domain_age_days(domain: str) -> int | None:
    if not domain:
        return None
    if domain.endswith(OFFLINE_SUFFIXES):
        ages = [v.get("domain_age_days") for u, v in demo_web().items()
                if registrable_domain(u) == domain and v.get("domain_age_days") is not None]
        return ages[0] if ages else None
    if domain in _RDAP_CACHE:
        return _RDAP_CACHE[domain]
    age = None
    try:
        async with httpx.AsyncClient(timeout=6, follow_redirects=True,
                                     headers={"Accept": "application/rdap+json"}) as client:
            r = await client.get(f"{await _rdap_server(domain.rsplit('.', 1)[-1], client)}domain/{domain}")
            if r.status_code == 200:
                for ev in r.json().get("events", []):
                    if ev.get("eventAction") == "registration":
                        reg = dt.date.fromisoformat(ev["eventDate"][:10])
                        age = (dt.date.today() - reg).days
                        break
    except Exception:
        age = None
    _RDAP_CACHE[domain] = age
    return age


# ---------------------------------------------------------------- ocena ryzyka
def risk_score(ad: dict, page: dict | None = None, person_names: list[str] | None = None) -> tuple[float, list[str]]:
    reasons, score = [], 0.0
    groups = sorted({k.split(":")[0] for k in ad.get("keywords") or []})
    if groups:
        score += min(0.4, 0.12 * len(groups))
        reasons.append("hasła typowe dla oszustw: " + ", ".join(GROUP_NAMES.get(g, g) for g in groups))
    age = ad.get("domain_age_days")
    if age is not None and age < 180:
        score += 0.25
        reasons.append(f"młoda domena ({age} dni od rejestracji)")
    chain = ad.get("redirect_chain") or []
    if len({registrable_domain(u) for u in chain}) > 2:
        score += 0.15
        reasons.append(f"łańcuch przekierowań przez {len(chain)} adresów")
    tld = (ad.get("domain") or "").rsplit(".", 1)[-1]
    if tld in SUSPICIOUS_TLDS:
        score += 0.1
        reasons.append(f"podejrzana domena najwyższego poziomu .{tld}")
    if page and page.get("cloaking"):
        score += 0.3
        reasons.append(f"cloaking: telefon trafia na {page['cloaking']['mobile']}, "
                       f"komputer na {page['cloaking']['desktop']}")
    if ad.get("persons"):
        score += 0.2
        who = ", ".join(person_names) if person_names else "osoby publicznej"
        reasons.append(f"wykorzystany wizerunek/nazwisko: {who}")
    return round(min(score, 1.0), 2), reasons
