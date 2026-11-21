import json
import sqlite3
import time
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
DATA_DIR.mkdir(exist_ok=True)
DB_PATH = DATA_DIR / "fejkradar.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS ads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at REAL NOT NULL,
    source TEXT NOT NULL,           -- manual | share | scheduler:<id>
    input_url TEXT,
    final_url TEXT,
    domain TEXT,
    redirect_chain TEXT,            -- json list of urls
    title TEXT,
    description TEXT,
    text TEXT,
    keywords TEXT,                  -- json list
    persons TEXT,                   -- json list of person ids
    phash TEXT,
    image_path TEXT,
    domain_age_days INTEGER,
    risk REAL,
    risk_reasons TEXT,              -- json list
    cluster_id INTEGER
);
CREATE TABLE IF NOT EXISTS persons (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    role TEXT,
    aliases TEXT                    -- json list
);
CREATE TABLE IF NOT EXISTS watches (
    ad_id INTEGER PRIMARY KEY,
    created_at REAL
);
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at REAL,
    ad_id INTEGER,
    watched_ad_id INTEGER,
    message TEXT,
    seen INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS sources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,             -- json_feed
    target TEXT NOT NULL,           -- path or URL
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

JSON_FIELDS = {"redirect_chain", "keywords", "persons", "risk_reasons", "aliases"}


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def row_to_dict(row: sqlite3.Row | None) -> dict | None:
    if row is None:
        return None
    d = dict(row)
    for k in JSON_FIELDS & d.keys():
        d[k] = json.loads(d[k]) if d[k] else []
    return d


def init_db() -> None:
    with connect() as conn:
        conn.executescript(SCHEMA)
        if conn.execute("SELECT COUNT(*) FROM persons").fetchone()[0] == 0:
            seed = json.loads((DATA_DIR / "persons_seed.json").read_text(encoding="utf-8"))
            for p in seed:
                conn.execute(
                    "INSERT INTO persons(name, role, aliases) VALUES (?,?,?)",
                    (p["name"], p.get("role"), json.dumps(p.get("aliases", []), ensure_ascii=False)),
                )
        if conn.execute("SELECT COUNT(*) FROM sources").fetchone()[0] == 0:
            conn.execute(
                "INSERT INTO sources(kind, target, interval_s, last_run) VALUES (?,?,?,?)",
                ("json_feed", str(DATA_DIR / "ad_library_feed.json"), 30, 0),
            )


def now() -> float:
    return time.time()
