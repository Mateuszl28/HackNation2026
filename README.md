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

Otwórz http://localhost:8000. Przy starcie scheduler automatycznie skanuje przykładową bibliotekę reklam (`data/ad_library_feed.json`) i buduje klastry.

Opcjonalnie OCR zrzutów ekranu: zainstaluj [Tesseract](https://github.com/tesseract-ocr/tesseract) z językiem `pol` oraz `pip install pytesseract`. Bez niego analiza zrzutów korzysta z tekstu wpisanego ręcznie i hasha wizualnego.

Na telefonie (PWA, Share Target i powiadomienia wymagają HTTPS): wystaw serwer np. przez tunel (`cloudflared tunnel --url http://localhost:8000`), otwórz adres w Chrome na Androidzie → „Dodaj do ekranu głównego”.

## Scenariusz demo

1. **Złap fejk** → wklej tekst reklamy, np. „Dr Kowalczyk: lekarze są w szoku, stawy w 7 dni” → raport pokazuje dopasowanie do znanej kampanii i powody.
2. Kliknij **Obserwuj tę kampanię**.
3. **Scheduler** → **Wstrzyknij nowy wariant** → **skanuj** (lub poczekaj 30 s).
4. **Alerty** / powiadomienie systemowe: nowy wariant w obserwowanej kampanii.
5. **Graf** – reklamy, domeny, domeny pośredniczące w przekierowaniach i osoby; kliknięcie krawędzi pokazuje, dlaczego materiały zostały połączone.

Reset danych demo: usuń `data/fejkradar.db` i przywróć `data/ad_library_feed.json` (`git checkout data/ad_library_feed.json`).

## Potok analizy

| Etap | Sygnały |
|---|---|
| Wejście | URL, tekst/hasło/nazwa produktu, zrzut ekranu (aparat, plik, udostępnienie) |
| Tekst | OCR (Tesseract, opcjonalnie), leksykon haseł oszustw (inwestycje, cud medyczny, presja czasu, fałszywy news, rejestracja/depozyt) |
| Technika | łańcuch przekierowań z mobilnym User-Agentem (HTTP + meta-refresh/JS), domena docelowa, wiek domeny (RDAP), podejrzane TLD, tytuł/opis strony |
| Wizualne | perceptual hash (dHash) – ten sam szablon/grafika mimo skalowania i kompresji |
| Osoby | dopasowanie do bazy referencyjnej (imię, nazwisko, aliasy) |

### Łączenie w kampanie

Ważone podobieństwo wielocechowe dla każdej pary materiałów (`app/similarity.py`):

| Sygnał | Waga |
|---|---|
| ta sama domena docelowa | 0.55 |
| wspólna domena pośrednia w przekierowaniach | 0.40 |
| identyczny tytuł strony docelowej | 0.30 |
| podobieństwo narracji (cosinus n-gramów znakowych) | 0.60 × sim |
| wspólne hasła z leksykonu (Jaccard) | 0.30 × J |
| ten sam wizerunek osoby | 0.35 |
| podobny szablon graficzny (dHash ≤ 10 bitów) | 0.45 × (1 − d/16) |

Para o sumie ≥ **0.6** dostaje krawędź; kampanie to spójne składowe tego grafu (union-find). Żaden pojedynczy ślad nie musi dowodzić oszustwa – liczy się kombinacja. Każda krawędź przechowuje listę powodów, więc wynik jest wyjaśnialny.

## API (skrót)

- `POST /api/submit` (multipart: `url`, `text`, `file`) → raport
- `POST /share` – Web Share Target z PWA
- `GET /api/ads`, `GET /api/ads/{id}`
- `GET /api/clusters`, `GET /api/graph`
- `POST|DELETE /api/watch/{ad_id}`, `GET /api/alerts`
- `GET|POST /api/persons`, `DELETE /api/persons/{id}`
- `GET|POST /api/sources`, `POST /api/sources/{id}/run`, `POST /api/sources/{id}/toggle`
- `POST /api/demo/inject`

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
