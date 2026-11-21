# FejkRadar / Campaign Weaver

System typu OSINT do wykrywania i łączenia w kampanie fałszywych reklam (inwestycyjne „cudowne zyski”, „cudowne leki”, podszywanie się pod osoby publiczne).

- **Web** – stanowisko analityczne: zgłoszenia, raport, eksplorator kampanii (graf powiązań), baza referencyjna osób, scheduler skanów.
- **Mobile (PWA)** – ta sama aplikacja instalowana na telefonie: szybkie zgłoszenie (zrzut ekranu / aparat / link), *Udostępnij → FejkRadar* (Web Share Target), powiadomienia o nowych wariantach obserwowanej kampanii.

## Uruchomienie

```bash
python -m venv .venv
.venv\Scripts\activate          # Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Otwórz http://localhost:8000. Przy starcie baza zasiewa się 7 fikcyjnymi reklamami (`data/seed_ads.json`: kampania inwestycyjna, „cud na stawy” i jedna reklama osobna), a scheduler skanuje fikcyjną bibliotekę reklam (`data/seed_feed.json` kopiowany do `data/ad_library_feed.json`).

### Baza danych (`app/db.py`, SQLite)

| Tabela | Zawartość |
|---|---|
| `ads` | materiały: URL, domena, przekierowania, tekst, ryzyko i powody, przypisana kampania |
| `ad_features` | wyekstrahowane cechy (domena, hop przekierowania, hasło, motyw, osoba, hash, tytuł) |
| `similarity_edges` | pary powyżej progu z wynikiem i **jawnymi powodami** |
| `campaigns` | klastry: nazwa, rozmiar, ryzyko, domeny, motywy, osoby |
| `campaign_watches`, `alerts` | obserwowane kampanie i powiadomienia o nowych wariantach |
| `persons` | baza referencyjna osób (rola, aliasy) |
| `sources`, `seen_items`, `scan_log` | scheduler: źródła, przetworzone pozycje, dziennik |

Opcjonalnie OCR zrzutów ekranu: zainstaluj [Tesseract](https://github.com/tesseract-ocr/tesseract) z językiem `pol` oraz `pip install pytesseract`. Bez niego analiza zrzutów korzysta z tekstu wpisanego ręcznie i hasha wizualnego.

Na telefonie (PWA, Share Target i powiadomienia wymagają HTTPS): wystaw serwer np. przez tunel (`cloudflared tunnel --url http://localhost:8000`), otwórz adres w Chrome na Androidzie → „Dodaj do ekranu głównego”.

## Scenariusz demo

1. **Złap fejk** → wklej tekst reklamy, np. „Dr Kowalczyk: lekarze są w szoku, stawy w 7 dni” → raport pokazuje dopasowanie do znanej kampanii i powody.
2. Kliknij **Obserwuj tę kampanię**.
3. **Scheduler** → **Wstrzyknij nowy wariant** → **skanuj** (lub poczekaj 30 s).
4. **Alerty** / powiadomienie systemowe: nowy wariant w obserwowanej kampanii.
5. **Graf** – reklamy, domeny, domeny pośredniczące w przekierowaniach i osoby; kliknięcie krawędzi pokazuje, dlaczego materiały zostały połączone.

Reset danych demo: przycisk **Reset demo** w zakładce Scheduler (lub `POST /api/demo/reset`).

## Potok analizy

Moduł `app/analyzer.py`:

| Etap | Sygnały |
|---|---|
| Wejście | URL, tekst/hasło/nazwa produktu, zrzut ekranu (aparat, plik, udostępnienie) |
| Przekierowania | każdy hop osobno (HTTP 3xx, meta-refresh, JS) z User-Agentem smartfona (Android Chrome); równoległy przebieg z UA desktopowym wykrywa **cloaking** (telefon i komputer lądują na innych domenach) |
| Wiek domeny | RDAP z serwera rejestru wskazanego przez IANA bootstrap (`rdap.dns.pl` dla .pl, `rdap.verisign.com` dla .com…), fallback `rdap.org`, cache w pamięci |
| Hasła | 5 grup: inwestycje, cudowne leki, presja czasu, fałszywe newsy, wpłata/depozyt; dopasowanie odporne na brak polskich znaków i obfuskację (`z@r4biaj` → `zarabiaj`) |
| Tekst ze zrzutu | OCR (Tesseract, opcjonalnie) |
| Wizualne | dHash (`imagehash` + Pillow), odporny na przeskalowanie i kompresję |
| Osoby | tabela `persons`: imię i nazwisko + aliasy, z tolerancją odmiany (Wiśniewska → Wiśniewskiej, Kowalczyk → Kowalczyka) |

**Tryb offline demo:** wszystkie domeny w danych demo są fikcyjne (`*.example.pl`). Adresy z `*.example.pl`, `*.example`, `*.test`, `*.invalid` oraz z łańcuchów w danych demo są rozwiązywane lokalnie (symulowane przekierowania, tytuły, wiek domen), więc prezentacja działa bez internetu i bez błędów sieciowych. Prawdziwe adresy idą do sieci.

### Łączenie w kampanie

Moduł `app/clustering.py` – punktacja wspólnych cech każdej pary reklam:

| Wspólna cecha | Punkty |
|---|---|
| domena docelowa | 0.55 |
| domeny w łańcuchu przekierowań (bez platform i skracaczy) | 0.40 |
| tytuł strony (`page_title`) | 0.30 |
| podobieństwo tekstu – Jaccard na słowach ≥ 3 znaki (od J ≥ 0.12) | 0.90 × J |
| hasła oszustw (Jaccard zbiorów haseł) | 0.30 × J |
| osoba z bazy referencyjnej | 0.35 |
| szablon graficzny – Hamming dHash ≤ 6 | 0.45 × (1 − d/12) |

Wynik **> 0.6** → zapis krawędzi z listą powodów (`similarity_edges`) i ta sama kampania. Żaden pojedynczy ślad (np. sama wspólna domena pośrednia = 0.40) nie wystarcza – liczy się kombinacja.

**Przypisanie przyrostowe** (`assign_ad`): nowa reklama jest porównywana ze wszystkimi dotychczasowymi.
- brak krawędzi → **nowa kampania**,
- krawędzie do jednej kampanii → **dołącza** do niej,
- krawędzie do kilku kampanii → kampanie są **scalane** w najstarszą; obserwujący scalonej kampanii są przenoszeni, alert informuje o scaleniu.

`POST /api/rebuild` przelicza wszystko od zera (union-find) – daje identyczny wynik jak przyrostowe przypisanie; przydatne po zmianie wag lub progu.

Na danych demo: wszystkie reklamy w obrębie każdej kampanii są połączone (bezpośrednio lub przez inne reklamy), a najwyższy wynik między różnymi kampaniami to 0.40 (sama wspólna domena pośrednia), więc nie ma fałszywych połączeń.

## API (skrót)

- `POST /api/submit` (multipart: `url`, `text`, `file`) → raport
- `POST /share` – Web Share Target z PWA
- `GET /api/ads`, `GET /api/ads/{id}`
- `GET /api/clusters`, `GET /api/graph`
- `GET /api/edges/{ad_id}` – krawędzie podobieństwa z powodami
- `POST /api/rebuild` – pełne przeliczenie kampanii
- `POST|DELETE /api/campaigns/{id}/watch`, `GET /api/alerts`
- `GET|POST /api/persons`, `DELETE /api/persons/{id}`
- `GET|POST /api/sources`, `POST /api/sources/{id}/run`, `POST /api/sources/{id}/toggle`
- `POST /api/demo/inject`, `POST /api/demo/reset`

Źródło schedulera to feed JSON (plik lub URL) – lista obiektów `{id, url, text, [redirect_chain, title, domain_age_days]}`. W ten sposób podpina się eksport z bibliotek reklam (np. Meta Ad Library API).

## Dane i licencje

- Osoby i domeny w danych demo są **fikcyjne**.
- Baza referencyjna osób powinna zawierać wyłącznie osoby publiczne; przetwarzanie wizerunku to dane szczególnej kategorii (RODO art. 9).
- Zależności: FastAPI, Uvicorn, httpx, python-multipart (MIT/BSD), Pillow (MIT-CMU), Cytoscape.js (MIT), opcjonalnie Tesseract (Apache 2.0). Brak zamkniętych komponentów.

## Roadmapa

- dopasowanie twarzy (embeddingi, licencja modelu zgodna z przeniesieniem praw)
- semantyczne embeddingi tekstu zamiast n-gramów
- render strony docelowej w Playwright (cloaking, zrzut landing page)
- integracja z Meta Ad Library API
- Web Push (VAPID) zamiast pollingu, eksport grafu do Neo4j
