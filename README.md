# FejkRadar / Campaign Weaver

System typu OSINT do wykrywania i łączenia w kampanie fałszywych reklam (inwestycyjne „cudowne zyski”, „cudowne leki”, podszywanie się pod osoby publiczne).

- **Web** – stanowisko analityczne: zgłoszenia, raport, eksplorator kampanii (graf powiązań), baza referencyjna osób, scheduler skanów.
- **Mobile (PWA)** – ta sama aplikacja instalowana na telefonie: szybkie zgłoszenie (zrzut ekranu / aparat / link), *Udostępnij → FejkRadar* (Web Share Target), powiadomienia o nowych wariantach obserwowanej kampanii.

## Uruchomienie

```bash
python -m venv .venv
.venv\Scripts\activate          # Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.app:app --reload --host 0.0.0.0 --port 8000
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

### Interfejs (`web/index.html` – jeden plik, bez kroku budowania)

| Zakładka | Co zawiera |
|---|---|
| **Złap fejk** | link, tekst/hasło, zrzut: **📷 Zrób zdjęcie** (aparat telefonu, `capture="environment"`) albo **🖼️ Wybierz zrzut/plik** z galerii; odbiór treści z Android Share Target; natychmiastowy raport: ryzyko i powody, dopasowanie do kampanii, przekierowania, domena i jej wiek, tytuł strony, osoby, podobne materiały z powodami |
| **Kampanie** | lista kampanii (domeny, motywy, maks. ryzyko), **Obserwuj**, **Pokaż w grafie**, **🧪 Wstrzyknij nowy wariant**, **Skanuj teraz** |
| **Graf** | Cytoscape.js: reklamy w kolorze kampanii, domeny docelowe (niebieskie), domeny z przekierowań (szare, przerywane), osoby (fioletowe romby); kliknięcie krawędzi pokazuje wynik i powody połączenia, kliknięcie reklamy otwiera raport; filtr kampanii |
| **Baza osób** | dodawanie i usuwanie osób z rolą i aliasami, liczba reklam z daną osobą |
| **Scheduler** | status odświeżany na żywo (odliczanie do skanu co 30 s), dodawanie źródeł JSON, włącz/wyłącz, skan od ręki, dziennik skanów, reset demo |
| **Alerty** | lista alertów; dodatkowo **pasek alertu** pod nagłówkiem na każdej zakładce (Zobacz / Wszystkie / ✕) i **powiadomienia systemowe** (Notification przez service worker) |

### Aplikacja mobilna (PWA) – `web/manifest.webmanifest`, `web/sw.js`

Na telefonie PWA wymaga HTTPS (wyjątek: `localhost`). Najprościej tunel: `cloudflared tunnel --url http://localhost:8000`, potem adres w Chrome na Androidzie.

| Funkcja | Jak działa |
|---|---|
| Instalacja na ekranie głównym | przycisk **📲 Zainstaluj** w nagłówku (lub menu Chrome → *Zainstaluj aplikację*); ikony PNG 192/512 + maskowalna, skróty *Złap fejk* i *Alerty* po przytrzymaniu ikony; na iPhonie: *Udostępnij → Do ekranu początkowego* |
| **Udostępnij → FejkRadar** (Android Share Target) | `sw.js` przechwytuje `POST /share-target` (oraz starszy `/share`), odkłada link/tekst/obraz do Cache Storage i otwiera zakładkę **Złap fejk**: formularz wypełnia się sam (link wyciągany także z pola tekstu, podgląd zrzutu) i analiza startuje automatycznie. Bez aktywnego SW serwer analizuje od razu (fallback). |
| Powiadomienia systemowe | o nowym wariancie obserwowanej kampanii (nazwa kampanii + domena); kliknięcie przełącza otwarte okno aplikacji na nową reklamę albo otwiera nowe okno. `sw.js` ma też gotową obsługę Web Push (`push`). |
| Offline | szkielet aplikacji (strona, ikony, Cytoscape.js) w cache – aplikacja otwiera się bez serwera i pokazuje ostrzeżenie; API zawsze z sieci |

Ikony generuje `python tools/make_icons.py`.

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

### Analiza obrazu (`app/vision.py`)

| Funkcja | Jak działa |
|---|---|
| **OCR zrzutów** | pierwszy dostępny silnik: Tesseract (`pol+eng`, jeśli zainstalowany) → **RapidOCR** (domyślny, Apache 2.0, bez instalacji programów) → EasyOCR. Z samego zrzutu wyciągany jest tekst reklamy, nazwiska, frazy oszustw i **adresy URL z grafiki** – z naprawą typowych błędów OCR (`zysk . example. pl`, `krypto-zysk24,example.pl`). Wyciągnięty adres przechodzi pełną analizę strony docelowej. |
| **Rozpoznawanie twarzy** | wykrywanie **YuNet** (MIT) + wektory **SFace** (Apache 2.0, 128-d) przez wbudowane API OpenCV (`FaceDetectorYN`, `FaceRecognizerSF`); próg cosinus ≥ 0.363. Do osoby w bazie dodaje się zdjęcie referencyjne (zakładka Baza osób) – wszystkie reklamy są automatycznie dopasowywane ponownie. Twarze spoza bazy są porównywane między reklamami („ten sam aktor/wizerunek”). insightface celowo nie jest używany – jego modele mają licencję niekomercyjną. |

Modele twarzy (~39 MB) nie są w repozytorium: `python tools/get_models.py` (aplikacja pobiera je też sama przy pierwszym użyciu).

### Strona docelowa – ślady infrastruktury (`app/analyzer.py`)

| Ślad | Źródło |
|---|---|
| identyfikatory śledzące | piksel Meta (`fbq init`), Google Analytics/Tag Manager/Ads, piksel TikTok, Yandex Metrika, Hotjar – wspólne ID = to samo konto reklamowe |
| formularze wyłudzające | hasło, dane karty (`cc-number`, CVV), BLIK, dane bankowe/IBAN, PESEL, formularz „inwestora” (imię + nazwisko + telefon) |
| TDS / cloaking | Keitaro, Binom, Palladium, parametry `clickid/subid` |
| serwer | IP, sieć i CIDR (RDAP), **ASN** (RDAP / RIPEstat), nagłówki `Server` / `X-Powered-By` |
| certyfikat SSL | odcisk SHA-256, wystawca, domeny z SAN (inne domeny na tym samym certyfikacie), certyfikat niepoprawny |

Ślady zapisywane są w kolumnie `ads.infra` (JSON); ta sama zawartość jest dostępna jako `ads.page_signals_json` (kolumna wyliczana SQLite, nigdy NULL).

W danych demo ślady są fikcyjne: IP z puli dokumentacyjnej RFC 5737, ASN z puli RFC 5398, zmyślone ID pikseli.

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
| **identyfikator śledzący** (piksel Meta, GA/GTM, TikTok, Metrika) | **0.65** – sam wystarcza |
| ten sam certyfikat SSL / obie domeny na jednym certyfikacie (SAN) | 0.50 |
| ten sam adres IP serwera (różne domeny) | 0.30 |
| ta sama twarz na grafikach (osoba spoza bazy) | 0.40 |
| identyczny zestaw formularzy wyłudzających (karta, BLIK, bank, hasło, „inwestor”) | 0.15 – tylko wspiera inne ślady |

Wynik **> 0.6** → zapis krawędzi z listą powodów (`similarity_edges`) i ta sama kampania. Żaden pojedynczy ślad (np. sama wspólna domena pośrednia = 0.40) nie wystarcza – liczy się kombinacja.

**Przypisanie przyrostowe** (`assign_ad`): nowa reklama jest porównywana ze wszystkimi dotychczasowymi.
- brak krawędzi → **nowa kampania**,
- krawędzie do jednej kampanii → **dołącza** do niej,
- krawędzie do kilku kampanii → kampanie są **scalane** w najstarszą; obserwujący scalonej kampanii są przenoszeni, alert informuje o scaleniu.

`POST /api/rebuild` przelicza wszystko od zera (union-find) – daje identyczny wynik jak przyrostowe przypisanie; przydatne po zmianie wag lub progu.

**Struktura kampanii (graf połączeń, `networkx`):** kampania to spójna składowa grafu – reklama A łączy się z B (wspólna osoba + tekst), B z C (wspólna domena + szablon), więc A, B i C tworzą jedną kampanię, choć A i C nie mają wspólnych cech. Wewnątrz kampanii liczone są:
- **podgrupy metodą Louvain** (modularność ważona wynikami połączeń) – „wątki” jednej operacji,
- **mosty** – pojedyncze połączenia i **reklamy-mosty** (punkty artykulacji), bez których kampania rozpada się na części; UI ostrzega, że takie scalenie warto zweryfikować (np. reklama łącząca „cud na stawy” z „dopłatą do prądu”).

Na danych demo: wszystkie reklamy w obrębie każdej kampanii są połączone (bezpośrednio lub przez inne reklamy), a najwyższy wynik między różnymi kampaniami to 0.40 (sama wspólna domena pośrednia), więc nie ma fałszywych połączeń.

## API (`app/app.py`)

Pełna, interaktywna dokumentacja: http://localhost:8000/docs

| Obszar | Endpointy |
|---|---|
| Analiza | `POST /api/submit` (multipart: `url`, `text`, `file`) → szybki raport · `POST /share-target` (Web Share Target z PWA – fallback bez service workera) · `GET /api/ads` · `GET /api/ads/{id}` (raport + krawędzie z powodami) |
| Kampanie i graf | `GET /api/campaigns` · `GET /api/graph[?campaign=ID&min_size=N]` – gotowe `elements` dla Cytoscape.js (węzły: reklamy, domeny, osoby; krawędzie: domena, przekierowanie, wizerunek, podobieństwo z wynikiem i powodami) · `GET /api/edges/{ad_id}` · `POST /api/rebuild` |
| Osoby | `GET /api/persons` (z liczbą reklam) · `POST /api/persons` · `PUT /api/persons/{id}` · `DELETE /api/persons/{id}` – każda zmiana bazy uruchamia ponowne dopasowanie osób we wszystkich reklamach i przeliczenie kampanii |
| Scheduler | `GET /api/scheduler` (źródła, czas do następnego skanu, dziennik) · `POST /api/sources` (domyślnie co **30 s**) · `POST /api/sources/{id}/run` · `POST /api/sources/{id}/toggle` |
| Alerty | `POST`/`DELETE /api/campaigns/{id}/watch` · `GET /api/alerts[?unseen=true]` · `POST /api/alerts/seen` |
| Demo | `POST /api/demo/inject[?scan=true]` – dopisuje kolejny wariant znanej kampanii do biblioteki (stała kolejność; scheduler wyłapie go w ≤ 30 s, `scan=true` od razu) · `POST /api/demo/reset` |
| Inne | `GET /api/health` |

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
