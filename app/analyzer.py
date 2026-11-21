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


URL_TLDS = r"(?:pl|com|net|org|eu|io|co|info|biz|xyz|top|online|site|shop|store|live|click|icu|sbs|cfd|buzz|space|fun|ru)"


def ocr_url_fix(text: str) -> str:
    """Naprawia typowe błędy OCR w adresach: 'zysk-news . example. pl' / 'domena,pl' / 'https: //' / 'www .'."""
    t = text or ""
    t = re.sub(r"(?i)\b(https?)\s*:\s*/\s*/\s*", lambda m: m.group(1).lower() + "://", t)
    t = re.sub(r"(?i)\bwww\s*[.,]\s*", "www.", t)
    # człony domen piszemy małymi literami – dzięki temu nie sklejamy końca zdania z początkiem kolejnego
    # ("szoku. Dni, pl" zostaje tekstem), a naprawiamy "example . pl", "example. pl", "zysk24,example.pl"
    lab = r"[a-z0-9][a-z0-9-]*"
    t = re.sub(rf"\b({lab})\s*\.\s+(?={URL_TLDS}\b)", r"\1.", t)
    t = re.sub(rf"\b({lab})\s+\.\s*(?={URL_TLDS}\b)", r"\1.", t)
    t = re.sub(rf"\b({lab}),(?={URL_TLDS}\b(?!\w))", r"\1.", t)
    t = re.sub(rf"\b({lab}),({lab}\.{URL_TLDS}\b)", r"\1.\2", t)
    t = re.sub(rf"\b({lab})\s+\.\s*({lab}\.{URL_TLDS}\b)", r"\1.\2", t)
    return t


def find_urls(text: str) -> list[str]:
    """Adresy z tekstu – także z tekstu OCR, gdzie link jest częścią grafiki ('zysk-news.pl/oferta')."""
    t = ocr_url_fix(text)
    urls = [u.rstrip(".,;:!?)\"'") for u in re.findall(r"https?://[^\s\"'<>]+", t)]
    bare = re.findall(rf"(?<![@\w.-])(?:www\.)?(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+{URL_TLDS}\b(?:/[^\s\"'<>]*)?",
                      normalize(t))
    out: list[str] = []
    for u in urls + [b if b.startswith("http") else "https://" + b for b in bare]:
        u = u.rstrip(".,;:!?)")
        host = registrable_domain(u)
        if host in TWO_LEVEL_SUFFIXES:  # sam sufiks (np. "example.pl" z ucięcia OCR) to nie adres
            continue
        if host and not any(registrable_domain(o) == host and urlparse(o).path in ("", "/") for o in out):
            if not any(o.startswith(u) or u.startswith(o) for o in out):
                out.append(u)
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
    """Tekst ze zrzutu (silnik wybiera app/vision.py: Tesseract -> RapidOCR -> EasyOCR)."""
    from .vision import ocr_image as _ocr
    return _ocr(data)["text"]


# ---------------------------------------------------------------- strona docelowa: ślady infrastruktury
TRACKER_PATTERNS = [
    # (rodzaj, regex) – identyfikatory kont reklamowych/analitycznych są wspólne dla wszystkich stron operatora
    ("meta_pixel", r"fbq\(\s*['\"]init['\"]\s*,\s*['\"](\d{10,20})"),
    ("meta_pixel", r"facebook\.com/tr\?id=(\d{10,20})"),
    ("google_tag", r"\b(G-[A-Z0-9]{6,12})\b"),
    ("google_ua", r"\b(UA-\d{4,10}-\d{1,4})\b"),
    ("google_tm", r"\b(GTM-[A-Z0-9]{4,9})\b"),
    ("google_ads", r"\b(AW-\d{9,11})\b"),
    ("tiktok_pixel", r"ttq\.load\(\s*['\"]([A-Z0-9]{15,25})"),
    ("yandex_metrika", r"ym\(\s*(\d{6,10})\s*,\s*['\"]init"),
    ("yandex_metrika", r"mc\.yandex\.ru/watch/(\d{6,10})"),
    ("hotjar", r"hjid\s*:\s*(\d{5,10})"),
]
# zestawy do cloakingu / dystrybucji ruchu (TDS) – typowe dla kampanii oszustw
TDS_PATTERNS = [("keitaro", r"keitaro|/\?_lp=1|_token=[a-f0-9]{20,}"), ("binom", r"binom|/click\.php\?lp="),
                ("palladium", r"palladium"), ("clickid", r"[?&](?:clickid|subid|sub_id|fbclid_redirect)=")]
FORM_FIELDS = {
    # rodzaj formularza: wzorce nazw/typów pól (po fold – bez polskich znaków)
    "haslo": [r"type=['\"]?password"],
    "karta": [r"cc-number|cc-exp|cc-csc|card.?number|numer.?karty|cvv|cvc|data.?waznosci"],
    "blik": [r"\bblik\b"],
    "bank": [r"\biban\b|numer.?konta|nr.?konta|login.?bank|bankowosc"],
    "pesel": [r"\bpesel\b|numer.?dowodu"],
    "lead": [r"name=['\"]?(first.?name|imie|fname)", r"name=['\"]?(last.?name|nazwisko|lname)",
             r"type=['\"]?tel|name=['\"]?(phone|telefon)"],
}
FORM_RISK = {"karta": 0.35, "blik": 0.35, "bank": 0.3, "haslo": 0.2, "pesel": 0.3, "lead": 0.15}
FORM_NAMES = {"karta": "dane karty płatniczej", "blik": "kod BLIK", "bank": "dane bankowe/logowanie do banku",
              "haslo": "hasło", "pesel": "PESEL/dowód", "lead": "formularz kontaktowy „inwestora” (imię, nazwisko, telefon)"}


def extract_page_signals(body: str) -> dict:
    """Ślady w HTML strony docelowej: ID pikseli/analityki, zestawy TDS, formularze wyłudzające dane."""
    trackers = sorted({f"{kind}:{m}" for kind, rx in TRACKER_PATTERNS for m in re.findall(rx, body or "")})
    # dla HTML tylko małe litery i bez polskich znaków (bez zamiany cyfr na litery – psułaby adresy i parametry)
    low = "".join(c for c in unicodedata.normalize("NFKD", normalize(body or "").translate(_PL))
                  if not unicodedata.combining(c))
    tds = sorted({kind for kind, rx in TDS_PATTERNS if re.search(rx, low)})
    forms = []
    for form_html in re.findall(r"<form\b.*?</form>", low, flags=re.S) or ([low] if "<input" in low else []):
        for kind, rxs in FORM_FIELDS.items():
            hits = sum(bool(re.search(rx, form_html)) for rx in rxs)
            if (kind == "lead" and hits >= 2) or (kind != "lead" and hits):
                forms.append(kind)
    return {"trackers": trackers, "tds": tds, "forms": sorted(set(forms))}


def _cert_info(host: str, port: int = 443) -> dict:
    """Odcisk SHA-256 certyfikatu, wystawca i domeny z SAN (inne domeny na tym samym certyfikacie)."""
    import hashlib
    import socket
    import ssl
    out = {}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as s:
                der, info = s.getpeercert(binary_form=True), s.getpeercert()
        out["cert_sha256"] = hashlib.sha256(der).hexdigest()
        out["cert_issuer"] = dict(x[0] for x in info.get("issuer", ())).get("organizationName")
        out["cert_sans"] = sorted({v.lower() for k, v in info.get("subjectAltName", ()) if k == "DNS"})[:50]
    except ssl.SSLError:
        try:  # niepoprawny/samopodpisany certyfikat – sam odcisk też jest śladem
            ctx = ssl._create_unverified_context()
            with socket.create_connection((host, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as s:
                    out["cert_sha256"] = hashlib.sha256(s.getpeercert(binary_form=True)).hexdigest()
                    out["cert_invalid"] = True
        except Exception:
            pass
    except Exception:
        pass
    return out


async def _ip_info(host: str) -> dict:
    """IP hosta i sieć/ASN z RDAP rejestru IP (RIPE/ARIN… przez rdap.org)."""
    import socket
    out = {}
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(host, 443, type=socket.SOCK_STREAM)
        ip = next((i[4][0] for i in infos if i[0] == socket.AF_INET), infos[0][4][0])
        out["ip"] = ip
        async with httpx.AsyncClient(timeout=6, follow_redirects=True,
                                     headers={"Accept": "application/rdap+json"}) as client:
            r = await client.get(f"https://rdap.org/ip/{ip}")
            if r.status_code == 200:
                j = r.json()
                out["net_name"] = j.get("name")
                out["net_country"] = j.get("country")
                cidr = (j.get("cidr0_cidrs") or [{}])[0]
                if cidr.get("v4prefix"):
                    out["net_cidr"] = f"{cidr['v4prefix']}/{cidr.get('length')}"
                asns = [str(a) for a in (j.get("arin_originas0_originautnums") or [])]
                if asns:
                    out["asn"] = "AS" + asns[0]
            if "asn" not in out:  # RDAP RIPE/APNIC nie podaje ASN – RIPEstat (publiczne API, bez klucza)
                r = await client.get("https://stat.ripe.net/data/network-info/data.json", params={"resource": ip})
                if r.status_code == 200:
                    d = r.json().get("data") or {}
                    if d.get("asns"):
                        out["asn"] = "AS" + str(d["asns"][0])
                    out.setdefault("net_cidr", d.get("prefix"))
    except Exception:
        pass
    return out


async def host_signals(url: str, headers: dict | None = None) -> dict:
    host = (urlparse(url).hostname or "").lower()
    if not host:
        return {}
    ip_task = asyncio.create_task(_ip_info(host))
    cert = await asyncio.to_thread(_cert_info, host) if url.startswith("https") else {}
    info = {**(await ip_task), **cert}
    h = {k.lower(): v for k, v in (headers or {}).items()}
    for key, name in (("server", "server"), ("x-powered-by", "powered_by")):
        if h.get(key):
            info[name] = h[key][:80]
    return info


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
                        node.update({k: it.get(k) for k in ("title", "description", "text", "domain_age_days", "infra")})
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
    if not page.get("infra") and not page.get("title"):
        # inna podstrona znanej domeny demo – ta sama witryna: wiek domeny, infrastruktura, tytuł
        dom = registrable_domain(url)
        page = next((v for u, v in web.items() if registrable_domain(u) == dom and (v.get("infra") or v.get("title"))),
                    page)
    return {"input_url": chain[0], "final_url": url, "redirect_chain": chain, "hops": hops,
            "title": page.get("title"), "description": page.get("description"), "page_text": page.get("text") or "",
            "offline": True, "domain_age_days": page.get("domain_age_days"), "cloaking": None, "error": None,
            "infra": dict(page.get("infra") or {})}


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
    hops, body, error, final_headers = [], "", None, {}
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
                final_headers = dict(r.headers)
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
            "page_text": text[:5000], "offline": False, "domain_age_days": None, "error": error,
            "infra": extract_page_signals(body), "headers": final_headers}


async def analyze_url(url: str) -> dict:
    """Łańcuch przekierowań z UA smartfona + porównanie z UA desktopowym (cloaking)."""
    if is_offline(url):
        return _simulate(url)
    mobile, desktop = await asyncio.gather(follow_redirects(url, UA_ANDROID), follow_redirects(url, UA_DESKTOP))
    dm, dd = registrable_domain(mobile["final_url"]), registrable_domain(desktop["final_url"])
    mobile["cloaking"] = ({"mobile": dm, "desktop": dd}
                          if dm and dd and dm != dd and not mobile["error"] and not desktop["error"] else None)
    # ślady infrastruktury strony docelowej: IP/sieć/ASN, certyfikat SSL, nagłówki serwera
    if not mobile["error"] or len(mobile["hops"]) > 1:
        mobile["infra"].update(await host_signals(mobile["final_url"], mobile.pop("headers", {})))
    mobile.pop("headers", None)
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
    infra = ad.get("infra") or {}
    forms = infra.get("forms") or []
    if forms:
        score += min(0.45, sum(FORM_RISK.get(f, 0.1) for f in forms))
        reasons.append("strona docelowa zbiera: " + ", ".join(FORM_NAMES.get(f, f) for f in forms))
    if infra.get("tds"):
        score += 0.2
        reasons.append("ślady systemu dystrybucji ruchu/cloakingu (TDS): " + ", ".join(infra["tds"]))
    if infra.get("cert_invalid"):
        score += 0.1
        reasons.append("niepoprawny certyfikat SSL strony docelowej")
    if ad.get("persons"):
        score += 0.2
        who = ", ".join(person_names) if person_names else "osoby publicznej"
        reasons.append(f"wykorzystany wizerunek/nazwisko: {who}")
    return round(min(score, 1.0), 2), reasons
