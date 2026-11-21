"""SQLite: schemat + zasiew danych demo.

Tabele:
  ads               – materiały (reklamy) z podstawowymi danymi i wynikiem ryzyka
  ad_features       – wyekstrahowane cechy (domena, hop przekierowania, hasło, osoba, hash wizualny...)
  similarity_edges  – pary reklam powyżej progu, z wynikiem i jawnymi powodami (wyjaśnialność dla jury)
  campaigns         – klastry kampanii (id = najmniejsze id reklamy w klastrze, więc jest stabilne przy scaleniach)
  campaign_watches  – obserwowane kampanie
  alerts            – powiadomienia o nowych wariantach obserwowanych kampanii
  persons           – baza referencyjna osób (rola, aliasy)
  person_faces      – zdjęcia referencyjne osób i wektory cech twarzy (SFace)
  sources, seen_items, scan_log – scheduler: źródła, przetworzone pozycje, dziennik skanów
"""
import json
import shutil
import sqlite3
import time
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
DATA_DIR.mkdir(exist_ok=True)
DB_PATH = DATA_DIR / "fejkradar.db"
SEED_ADS = DATA_DIR / "seed_ads.json"            # 7 fikcyjnych reklam, zasiewane na starcie
SEED_FEED = DATA_DIR / "seed_feed.json"          # początkowy stan fikcyjnej biblioteki reklam
FEED_PATH = DATA_DIR / "ad_library_feed.json"    # feed czytany przez scheduler (runtime, poza gitem)
DEMO_VARIANTS = DATA_DIR / "demo_variants.json"  # warianty wstrzykiwane w demo

SCHEMA = """
CREATE TABLE IF NOT EXISTS ads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at REAL NOT NULL,
    source TEXT NOT NULL,           -- seed | manual | share | scheduler:<id>
    external_id TEXT,               -- id pozycji w bibliotece reklam
    input_url TEXT,
    final_url TEXT,
    domain TEXT,
    redirect_chain TEXT,            -- json list
    title TEXT,
    description TEXT,
    text TEXT,
    keywords TEXT,                  -- json list "motyw:hasło"
    persons TEXT,                   -- json list id osób
    phash TEXT,
    image_path TEXT,
    domain_age_days INTEGER,
    risk REAL,
    risk_reasons TEXT,              -- json list
    cluster_id INTEGER,
    page_text TEXT,                 -- treść strony docelowej (do ponownego dopasowania osób/haseł)
    ocr_text TEXT,                  -- tekst odczytany ze zrzutu
    ocr_backend TEXT,
    faces TEXT,                     -- json: [{box, score, embedding, person_id?, similarity?}]
    infra TEXT                      -- json: trackers, tds, forms, ip, asn, net_name, cert_sha256, cert_sans, server...
);
CREATE TABLE IF NOT EXISTS ad_features (
    ad_id INTEGER NOT NULL,
    kind TEXT NOT NULL,             -- domain | redirect_hop | keyword | theme | person | phash | title
    value TEXT NOT NULL,
    PRIMARY KEY (ad_id, kind, value)
);
CREATE INDEX IF NOT EXISTS idx_features_kv ON ad_features(kind, value);
CREATE TABLE IF NOT EXISTS similarity_edges (
    ad_a INTEGER NOT NULL,
    ad_b INTEGER NOT NULL,
    score REAL NOT NULL,
    reasons TEXT NOT NULL,          -- json list, np. ["ta sama domena x.xyz", "zbliżona narracja (0.71)"]
    PRIMARY KEY (ad_a, ad_b)
);
CREATE TABLE IF NOT EXISTS campaigns (
    id INTEGER PRIMARY KEY,         -- = najmniejsze id reklamy w klastrze
    name TEXT,
    size INTEGER,
    max_risk REAL,
    domains TEXT,                   -- json list
    themes TEXT,                    -- json list
    persons TEXT,                   -- json list id osób
    first_seen REAL,
    last_seen REAL,
    subgroups TEXT,                 -- json: podgrupy Louvain [[ad_id,...],...]
    bridges TEXT                    -- json: krawędzie-mosty [{a, b, score}] i reklamy-mosty
);
CREATE TABLE IF NOT EXISTS person_faces (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    person_id INTEGER NOT NULL,
    embedding TEXT NOT NULL,        -- json 128 float (SFace)
    image_path TEXT,
    created_at REAL
);
CREATE TABLE IF NOT EXISTS campaign_watches (
    campaign_id INTEGER PRIMARY KEY,
    created_at REAL
);
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at REAL,
    ad_id INTEGER,
    campaign_id INTEGER,
    message TEXT,
    seen INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS persons (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,             -- unikalne (bez względu na wielkość liter): indeks niżej + kontrola w app.py
    role TEXT,
    aliases TEXT                    -- json list
);
CREATE TABLE IF NOT EXISTS sources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,             -- json_feed
    target TEXT NOT NULL,           -- ścieżka lub URL
    interval_s INTEGER DEFAULT 60,
    last_run REAL,
    last_status TEXT,
    enabled INTEGER DEFAULT 1
);
CREATE TABLE IF NOT EXISTS seen_items (
    source_id INTEGER,
    item_key TEXT,
    PRIMARY KEY (source_id, item_key)
);
CREATE TABLE IF NOT EXISTS scan_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at REAL,
    source_id INTEGER,
    found INTEGER,
    new INTEGER,
    message TEXT
);
"""

JSON_FIELDS = {"redirect_chain", "keywords", "persons", "risk_reasons", "aliases", "reasons", "domains", "themes",
               "faces", "infra", "subgroups", "bridges", "embedding"}
# kolumny dodane w kolejnych wersjach – migracja istniejących baz bez utraty danych
MIGRATIONS = {"ads": {"page_text": "TEXT", "ocr_text": "TEXT", "ocr_backend": "TEXT", "faces": "TEXT", "infra": "TEXT"},
              "campaigns": {"subgroups": "TEXT", "bridges": "TEXT"}}


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def row_to_dict(row: sqlite3.Row | None) -> dict | None:
    if row is None:
        return None
    d = dict(row)
    for k in JSON_FIELDS & d.keys():
        d[k] = json.loads(d[k]) if d[k] else []
    return d


def load_json(path: Path) -> list:
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else []


def init_db() -> None:
    """Tworzy schemat, zasiewa bazę osób, źródło schedulera i fikcyjny feed. Reklamy demo zasiewa pipeline.seed_ads()."""
    if not FEED_PATH.exists():
        shutil.copyfile(SEED_FEED, FEED_PATH)
    with connect() as conn:
        conn.executescript(SCHEMA)
        for table, cols in MIGRATIONS.items():
            have = {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}
            for col, typ in cols.items():
                if col not in have:
                    conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {typ}")
        try:  # unikalna nazwa osoby; na starej bazie z duplikatami indeks się nie utworzy – zostaje kontrola w API
            conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_persons_name ON persons(name COLLATE NOCASE)")
        except sqlite3.IntegrityError:
            print("[db] uwaga: w bazie są osoby o powtórzonych nazwach – indeks unikalności pominięty")
        if conn.execute("SELECT COUNT(*) FROM persons").fetchone()[0] == 0:
            for p in load_json(DATA_DIR / "persons_seed.json"):
                conn.execute("INSERT INTO persons(name, role, aliases) VALUES (?,?,?)",
                             (p["name"], p.get("role"), json.dumps(p.get("aliases", []), ensure_ascii=False)))
        if conn.execute("SELECT COUNT(*) FROM sources").fetchone()[0] == 0:
            conn.execute("INSERT INTO sources(kind, target, interval_s, last_run) VALUES (?,?,?,?)",
                         ("json_feed", str(FEED_PATH), 30, 0))


def reset_demo() -> None:
    """Czyści bazę i feed do stanu początkowego (przed prezentacją)."""
    with connect() as conn:  # DROP zamiast usuwania pliku (Windows blokuje otwarty plik bazy)
        for (name,) in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall():
            if not name.startswith("sqlite_"):
                conn.execute(f"DROP TABLE IF EXISTS {name}")
    shutil.copyfile(SEED_FEED, FEED_PATH)
    init_db()


def now() -> float:
    return time.time()
