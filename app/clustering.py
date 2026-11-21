"""Klastrowanie kampanii: punktacja wspólnych cech par reklam, próg > 0.6, zapis powodów, przypisanie do kampanii.

Każda para reklam dostaje punkty za wspólne cechy:
  wspólna domena docelowa ............................. 0.55
  wspólne domeny w łańcuchu przekierowań ............... 0.40   (bez platform i skracaczy)
  ten sam tytuł strony (page_title) .................... 0.30
  podobieństwo tekstu – Jaccard na słowach ≥ 3 znaki ... 0.90 × J   (gdy J ≥ 0.12)
  te same hasła oszustw (Jaccard zbiorów haseł) ........ 0.30 × J
  ta sama osoba z bazy referencyjnej ................... 0.35
  ten sam szablon graficzny (Hamming dHash ≤ 6) ........ 0.45 × (1 − d/12)

Wynik > 0.6 => krawędź z listą powodów (similarity_edges) i ta sama kampania.

Przypisanie jest przyrostowe (assign_ad): nowa reklama porównywana jest ze wszystkimi dotychczasowymi;
 - brak krawędzi                  -> nowa kampania (id = id reklamy),
 - krawędzie do jednej kampanii   -> dołącza do niej,
 - krawędzie do kilku kampanii    -> kampanie są scalane w najstarszą (najmniejsze id).
rebuild() przelicza wszystko od zera (po resecie, zmianie bazy osób lub wag).
"""
import json
import re
from collections import Counter

from .analyzer import PLATFORM_DOMAINS, fold, registrable_domain

WEIGHTS = {
    "same_domain": 0.55,
    "shared_redirect": 0.40,
    "same_title": 0.30,
    "text": 0.90,
    "keywords": 0.30,
    "person": 0.35,
    "visual": 0.45,
}
THRESHOLD = 0.6
TEXT_MIN_JACCARD = 0.12
DHASH_MAX_DISTANCE = 6

THEME_NAMES = {"inwestycja": "Fałszywe inwestycje", "cud_medyczny": "Cudowny lek", "falszywy_news": "Fałszywy news",
               "pilnosc": "Presja czasu", "wplata": "Wyłudzenie danych/wpłaty"}
THEME_TIER = {"inwestycja": 0, "cud_medyczny": 0, "falszywy_news": 1}  # konkretne motywy przed ogólnymi


# ---------------------------------------------------------------- cechy
def words(ad: dict) -> set[str]:
    """Słowa ≥ 3 znaki z tekstu, tytułu i opisu (bez polskich znaków, małe litery)."""
    text = " ".join(filter(None, [ad.get("text"), ad.get("title"), ad.get("description")]))
    return {w for w in re.findall(r"[a-z0-9]+", fold(text)) if len(w) >= 3}


def jaccard(a: set, b: set) -> float:
    return len(a & b) / len(a | b) if a and b else 0.0


def hamming_hex(a: str, b: str) -> int:
    return bin(int(a, 16) ^ int(b, 16)).count("1")


def redirect_domains(ad: dict) -> set[str]:
    doms = {registrable_domain(u) for u in ad.get("redirect_chain") or []}
    return {d for d in doms if d and d not in PLATFORM_DOMAINS}


# ---------------------------------------------------------------- punktacja pary
def pair_score(a: dict, b: dict, wa: set | None = None, wb: set | None = None) -> tuple[float, list[str]]:
    score, reasons = 0.0, []
    da, db = a.get("domain"), b.get("domain")
    if da and da == db and da not in PLATFORM_DOMAINS:
        score += WEIGHTS["same_domain"]
        reasons.append(f"wspólna domena docelowa {da}")
    shared = (redirect_domains(a) & redirect_domains(b)) - ({da} if da == db else set())
    if shared:
        score += WEIGHTS["shared_redirect"]
        reasons.append("wspólne domeny w łańcuchu przekierowań: " + ", ".join(sorted(shared)))
    if a.get("title") and fold(a["title"]) == fold(b.get("title") or ""):
        score += WEIGHTS["same_title"]
        reasons.append(f"ten sam tytuł strony „{a['title']}”")
    j = jaccard(wa if wa is not None else words(a), wb if wb is not None else words(b))
    if j >= TEXT_MIN_JACCARD:
        score += WEIGHTS["text"] * j
        reasons.append(f"podobny tekst (Jaccard {j:.2f})")
    ka, kb = set(a.get("keywords") or []), set(b.get("keywords") or [])
    if ka & kb:
        score += WEIGHTS["keywords"] * jaccard(ka, kb)
        reasons.append("te same hasła oszustw: " + ", ".join(sorted(k.split(":")[1] for k in ka & kb)[:4]))
    if set(a.get("persons") or []) & set(b.get("persons") or []):
        score += WEIGHTS["person"]
        reasons.append("ta sama osoba z bazy referencyjnej")
    if a.get("phash") and b.get("phash"):
        d = hamming_hex(a["phash"], b["phash"])
        if d <= DHASH_MAX_DISTANCE:
            score += WEIGHTS["visual"] * (1 - d / (2 * DHASH_MAX_DISTANCE))
            reasons.append(f"ten sam szablon graficzny (Hamming dHash {d}/64)")
    return round(score, 3), reasons


def best_matches(target: dict, ads: list[dict], k: int = 5) -> list[dict]:
    wt = words(target)
    scored = []
    for a in ads:
        if a["id"] == target["id"]:
            continue
        s, r = pair_score(target, a, wt, words(a))
        if s > 0:
            scored.append({"ad_id": a["id"], "score": s, "reasons": r, "cluster_id": a.get("cluster_id"),
                           "linked": s > THRESHOLD})
    return sorted(scored, key=lambda x: -x["score"])[:k]


# ---------------------------------------------------------------- zapis do bazy
def _load_ads(conn, where: str = "", params: tuple = ()) -> list[dict]:
    from .db import row_to_dict
    return [row_to_dict(r) for r in conn.execute(f"SELECT * FROM ads {where} ORDER BY id", params)]


def _campaign_name(members: list[dict], persons: dict) -> str:
    themes = Counter(k.split(":")[0] for a in members for k in a["keywords"])
    ranked = sorted(themes, key=lambda t: (THEME_TIER.get(t, 2), -themes[t]))
    name = " + ".join(THEME_NAMES.get(t, t) for t in ranked[:2]) or "Bez wyraźnego motywu"
    people = Counter(p for a in members for p in a["persons"])
    who = persons.get(people.most_common(1)[0][0]) if people else None
    return f"{name} ({who})" if who else name


def refresh_campaign(conn, cid: int) -> None:
    """Przelicza podsumowanie kampanii (nazwa, rozmiar, ryzyko, domeny, motywy, osoby)."""
    members = _load_ads(conn, "WHERE cluster_id=?", (cid,))
    if not members:
        conn.execute("DELETE FROM campaigns WHERE id=?", (cid,))
        return
    persons = {r["id"]: r["name"] for r in conn.execute("SELECT id, name FROM persons")}
    conn.execute(
        "INSERT OR REPLACE INTO campaigns VALUES (?,?,?,?,?,?,?,?,?)",
        (cid, _campaign_name(members, persons), len(members), max(a["risk"] or 0 for a in members),
         json.dumps(sorted({a["domain"] for a in members if a["domain"]})),
         json.dumps(sorted({k.split(":")[0] for a in members for k in a["keywords"]})),
         json.dumps(sorted({p for a in members for p in a["persons"]})),
         min(a["created_at"] for a in members), max(a["created_at"] for a in members)))


def _merge(conn, target: int, others: set[int]) -> None:
    for old in others:
        conn.execute("UPDATE ads SET cluster_id=? WHERE cluster_id=?", (target, old))
        conn.execute("DELETE FROM campaigns WHERE id=?", (old,))
        # obserwujący scaloną kampanię obserwują teraz kampanię docelową
        conn.execute("INSERT OR IGNORE INTO campaign_watches SELECT ?, created_at FROM campaign_watches "
                     "WHERE campaign_id=?", (target, old))
        conn.execute("DELETE FROM campaign_watches WHERE campaign_id=?", (old,))


def assign_ad(conn, ad_id: int) -> dict:
    """Przyrostowe przypisanie nowej reklamy do kampanii. Zwraca {campaign_id, edges, merged, created}."""
    ads = _load_ads(conn)
    new = next(a for a in ads if a["id"] == ad_id)
    wn = words(new)
    edges, linked = [], set()
    for a in ads:
        if a["id"] == ad_id:
            continue
        s, reasons = pair_score(a, new, words(a), wn)
        if s > THRESHOLD:
            edges.append((a["id"], ad_id, s, json.dumps(reasons, ensure_ascii=False)))
            if a["cluster_id"] is not None:
                linked.add(a["cluster_id"])
    conn.executemany("INSERT OR REPLACE INTO similarity_edges VALUES (?,?,?,?)", edges)
    if not linked:
        cid, merged = ad_id, set()          # nowa kampania
    else:
        cid = min(linked)                   # dołącz do najstarszej
        merged = linked - {cid}
        _merge(conn, cid, merged)
    conn.execute("UPDATE ads SET cluster_id=? WHERE id=?", (cid, ad_id))
    refresh_campaign(conn, cid)
    return {"campaign_id": cid, "edges": len(edges), "merged": sorted(merged), "created": not linked}


def rebuild(conn) -> None:
    """Pełne przeliczenie: wszystkie pary, krawędzie i kampanie od zera (union-find)."""
    ads = _load_ads(conn)
    cache = {a["id"]: words(a) for a in ads}
    parent = {a["id"]: a["id"] for a in ads}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    edges = []
    for i, a in enumerate(ads):
        for b in ads[i + 1:]:
            s, reasons = pair_score(a, b, cache[a["id"]], cache[b["id"]])
            if s > THRESHOLD:
                edges.append((a["id"], b["id"], s, json.dumps(reasons, ensure_ascii=False)))
                ra, rb = find(a["id"]), find(b["id"])
                if ra != rb:
                    parent[max(ra, rb)] = min(ra, rb)
    conn.execute("DELETE FROM similarity_edges")
    conn.executemany("INSERT INTO similarity_edges VALUES (?,?,?,?)", edges)
    conn.executemany("UPDATE ads SET cluster_id=? WHERE id=?", [(find(x), x) for x in parent])
    # obserwacje podążają za kampaniami (id kampanii = id reklamy, która w niej była)
    for (wid,) in conn.execute("SELECT campaign_id FROM campaign_watches").fetchall():
        if wid in parent and find(wid) != wid:
            conn.execute("INSERT OR IGNORE INTO campaign_watches SELECT ?, created_at FROM campaign_watches "
                         "WHERE campaign_id=?", (find(wid), wid))
            conn.execute("DELETE FROM campaign_watches WHERE campaign_id=?", (wid,))
    conn.execute("DELETE FROM campaigns")
    for cid in {find(x) for x in parent}:
        refresh_campaign(conn, cid)
