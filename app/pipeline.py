"""Potok analizy: wejście -> ekstrakcja sygnałów -> zapis (reklama + cechy) -> przypisanie do kampanii -> alerty.

Sygnały z obrazu (app/vision.py): OCR zrzutu (tekst reklamy, nazwiska, frazy, adresy URL ukryte na grafice)
oraz twarze – dopasowywane do zdjęć referencyjnych osób z bazy (SFace) i porównywane między reklamami.
Sygnały ze strony docelowej (app/analyzer.py): przekierowania, identyfikatory śledzące, formularze, IP/ASN, SSL.
"""
import asyncio
import json
import uuid

from . import clustering, vision
from .analyzer import (PLATFORM_DOMAINS, analyze_url, dhash, domain_age_days, extract_keywords, find_urls,
                       match_persons_detailed, registrable_domain, risk_score)
from .db import DATA_DIR, SEED_ADS, connect, load_json, now, row_to_dict

UPLOADS = DATA_DIR / "uploads"
UPLOADS.mkdir(exist_ok=True)
PREFETCH_KEYS = ("redirect_chain", "title", "description", "domain_age_days", "phash", "infra")


def all_ads(conn=None) -> list[dict]:
    conn = conn or connect()
    return [row_to_dict(r) for r in conn.execute("SELECT * FROM ads ORDER BY id")]


def all_persons(conn=None) -> list[dict]:
    conn = conn or connect()
    return [row_to_dict(r) for r in conn.execute("SELECT * FROM persons ORDER BY id")]


def face_refs(conn=None) -> list[dict]:
    """Wektory twarzy z bazy referencyjnej: [{person_id, name, embedding}]."""
    conn = conn or connect()
    q = "SELECT f.person_id, p.name, f.embedding FROM person_faces f JOIN persons p ON p.id = f.person_id"
    return [{"person_id": r[0], "name": r[1], "embedding": json.loads(r[2])} for r in conn.execute(q)]


def match_people(text: str, faces: list[dict], persons: list[dict], refs: list[dict]) -> tuple[list[dict], list[dict]]:
    """Osoby z bazy: po imieniu/nazwisku/aliasach w tekście oraz po twarzy na grafice.
    Zwraca (lista dopasowań {id, name, via, detail}, twarze uzupełnione o person_id/similarity)."""
    hits = {m["id"]: {"id": m["id"], "name": m["name"], "via": ["tekst"], "detail": f"„{m['matched']}”",
                      "label": f"tekst „{m['matched']}”"} for m in match_persons_detailed(text, persons)}
    faces = [{k: v for k, v in f.items() if k not in ("person_id", "name", "similarity")} for f in faces]
    for m in vision.match_faces(faces, refs) if refs else []:
        faces[m["face"]].update(person_id=m["person_id"], name=m["name"], similarity=m["similarity"])
        h = hits.setdefault(m["person_id"], {"id": m["person_id"], "name": m["name"], "via": [], "detail": "",
                                             "label": ""})
        if "twarz" not in h["via"]:
            h["via"].append("twarz")
            h["label"] = "; ".join(filter(None, [h["label"], f"twarz {m['similarity']:.2f}"]))
    return list(hits.values()), faces


def ad_text(ad: dict) -> str:
    """Cały tekst reklamy użyty przy analizie: treść/OCR, tytuł, opis i treść strony docelowej."""
    return " ".join(filter(None, [ad.get("text"), ad.get("title"), ad.get("description"), ad.get("page_text")]))


def _person_labels(hits: list[dict]) -> list[str]:
    return [f"{h['name']} ({h['label']})" for h in hits]


def _features(ad: dict) -> list[tuple[str, str]]:
    f = []
    if ad.get("domain"):
        f.append(("domain", ad["domain"]))
    for u in (ad.get("redirect_chain") or [])[:-1]:
        d = registrable_domain(u)
        if d and d != ad.get("domain") and d not in PLATFORM_DOMAINS:
            f.append(("redirect_hop", d))
    for k in ad.get("keywords") or []:
        f.append(("keyword", k))
        f.append(("theme", k.split(":")[0]))
    f += [("person", str(p)) for p in ad.get("persons") or []]
    if ad.get("phash"):
        f.append(("phash", ad["phash"]))
    if ad.get("title"):
        f.append(("title", ad["title"]))
    infra = ad.get("infra") or {}
    f += [("tracker", t) for t in infra.get("trackers") or []]
    f += [("form", x) for x in infra.get("forms") or []]
    for key in ("ip", "asn", "cert_sha256", "net_name", "server"):
        if infra.get(key):
            f.append((key, str(infra[key])))
    return sorted(set(f))


def _dump(v):
    return json.dumps(v, ensure_ascii=False) if isinstance(v, (list, dict)) else v


async def analyze(*, source: str, url: str | None = None, text: str | None = None, image: bytes | None = None,
                  image_name: str | None = None, prefetched: dict | None = None,
                  external_id: str | None = None) -> dict:
    """prefetched: dane z biblioteki reklam (redirect_chain, title, domain_age_days, infra...) – bez pobierania z sieci."""
    prefetched = prefetched or {}
    text = (text or "").strip()
    image_path, phash, faces, ocr, ocr_urls = None, None, [], {"text": "", "backend": None}, []
    if image:
        ext = (image_name or "img.png").rsplit(".", 1)[-1][:5].lower()
        fname = f"{uuid.uuid4().hex}.{ext}"
        (UPLOADS / fname).write_bytes(image)
        image_path = f"uploads/{fname}"
        phash = dhash(image)
        # OCR i twarze to obliczenia CPU – w osobnych wątkach, równolegle
        ocr, faces = await asyncio.gather(asyncio.to_thread(vision.ocr_image, image),
                                          asyncio.to_thread(vision.face_embeddings, image))
        if ocr["text"].strip():
            ocr_urls = find_urls(ocr["text"])
            text = (text + "\n" + ocr["text"]).strip()
    phash = prefetched.get("phash", phash)

    reasons_extra = []
    if not url:
        urls = find_urls(text)
        url = urls[0] if urls else None
        if url and url in ocr_urls:
            reasons_extra.append(f"adres odczytany z grafiki (OCR): {url}")

    page = {"input_url": url, "final_url": url, "redirect_chain": [url] if url else [], "title": None,
            "description": None, "page_text": "", "error": None, "infra": {}}
    if "redirect_chain" in prefetched:
        page.update({k: prefetched[k] for k in ("redirect_chain", "title", "description", "infra") if k in prefetched})
        page["final_url"] = (prefetched.get("redirect_chain") or [url])[-1]
    elif url:
        page = await analyze_url(url)

    domain = registrable_domain(page["final_url"] or url or "")
    age = prefetched.get("domain_age_days", page.get("domain_age_days"))
    if age is None and domain and "redirect_chain" not in prefetched:
        age = await domain_age_days(domain)

    full_text = " ".join(filter(None, [text, page.get("title"), page.get("description"), page.get("page_text")]))
    with connect() as conn:
        hits, faces = match_people(full_text, faces, all_persons(conn), face_refs(conn))
    ad = {
        "created_at": now(), "source": source, "external_id": external_id, "input_url": url,
        "final_url": page["final_url"], "domain": domain, "redirect_chain": page["redirect_chain"],
        "title": page.get("title"), "description": page.get("description"),
        "text": (text or page.get("page_text") or "")[:5000], "keywords": extract_keywords(full_text),
        "persons": [h["id"] for h in hits], "phash": phash, "image_path": image_path,
        "domain_age_days": age, "page_text": (page.get("page_text") or "")[:5000] or None,
        "ocr_text": ocr["text"][:5000] or None, "ocr_backend": ocr.get("backend"),
        "faces": faces, "infra": page.get("infra") or {},
    }
    ad["risk"], ad["risk_reasons"] = risk_score(ad, page, _person_labels(hits))
    ad["risk_reasons"] += reasons_extra
    if page.get("error"):
        ad["risk_reasons"].append(f"nie udało się pobrać strony: {page['error'][:120]}")

    with connect() as conn:
        cols = list(ad.keys())
        ad_id = conn.execute(f"INSERT INTO ads({','.join(cols)}) VALUES ({','.join('?' * len(cols))})",
                             [_dump(v) for v in ad.values()]).lastrowid
        conn.executemany("INSERT OR IGNORE INTO ad_features VALUES (?,?,?)",
                         [(ad_id, k, v) for k, v in _features(ad)])
        result = clustering.assign_ad(conn, ad_id)
        # alert dla obserwujących kampanię, do której dołączył nowy wariant
        if not result["created"] and conn.execute("SELECT 1 FROM campaign_watches WHERE campaign_id=?",
                                                  (result["campaign_id"],)).fetchone():
            merged = f", scalono z kampaniami {result['merged']}" if result["merged"] else ""
            conn.execute("INSERT INTO alerts(created_at, ad_id, campaign_id, message) VALUES (?,?,?,?)",
                         (now(), ad_id, result["campaign_id"],
                          f"Nowy wariant w obserwowanej kampanii #{result['campaign_id']} (reklama #{ad_id}{merged})"))
    return report(ad_id)


async def seed_ads() -> int:
    """Zasiewa bazę 7 fikcyjnymi reklamami demo (tylko gdy jest pusta)."""
    if connect().execute("SELECT COUNT(*) FROM ads").fetchone()[0]:
        return 0
    items = load_json(SEED_ADS)
    for it in items:
        await analyze(source="seed", url=it.get("url"), text=it.get("text"),
                      prefetched={k: it[k] for k in PREFETCH_KEYS if k in it}, external_id=it.get("id"))
    return len(items)


def rebuild() -> None:
    with connect() as conn:
        clustering.rebuild(conn)


PAGE_REASONS = ("cloaking:", "nie udało się pobrać strony", "adres odczytany z grafiki")


def rematch_persons() -> int:
    """Po zmianie bazy osób (dane lub zdjęcia): ponowne dopasowanie osób po tekście i twarzy we wszystkich reklamach,
    przeliczenie ryzyka, cech i kampanii. Zwraca liczbę reklam, w których zmieniła się lista osób."""
    changed = 0
    with connect() as conn:
        persons, refs = all_persons(conn), face_refs(conn)
        for ad in all_ads(conn):
            hits, faces = match_people(ad_text(ad), ad["faces"] or [], persons, refs)
            ids = [h["id"] for h in hits]
            if ids == ad["persons"] and faces == (ad["faces"] or []):
                continue
            changed += ids != ad["persons"]
            ad["persons"], ad["faces"] = ids, faces
            risk, reasons = risk_score(ad, None, _person_labels(hits))
            # sygnały ze strony docelowej (cloaking, błąd pobrania) nie są odtwarzalne bez sieci – przenosimy je
            kept = [r for r in ad["risk_reasons"] if r.startswith(PAGE_REASONS)]
            risk = min(1.0, risk + 0.3 * any(r.startswith("cloaking:") for r in kept))
            conn.execute("UPDATE ads SET persons=?, faces=?, risk=?, risk_reasons=? WHERE id=?",
                         (json.dumps(ids), _dump(faces), round(risk, 2), _dump(reasons + kept), ad["id"]))
            conn.execute("DELETE FROM ad_features WHERE ad_id=? AND kind='person'", (ad["id"],))
            conn.executemany("INSERT OR IGNORE INTO ad_features VALUES (?,?,?)",
                             [(ad["id"], "person", str(p)) for p in ids])
        clustering.rebuild(conn)
    return changed


def edges_for(ad_id: int, conn=None) -> list[dict]:
    conn = conn or connect()
    rows = conn.execute("SELECT * FROM similarity_edges WHERE ad_a=? OR ad_b=? ORDER BY score DESC", (ad_id, ad_id))
    return [row_to_dict(r) for r in rows]


def report(ad_id: int) -> dict:
    conn = connect()
    ad = row_to_dict(conn.execute("SELECT * FROM ads WHERE id=?", (ad_id,)).fetchone())
    if not ad:
        return {}
    camp = row_to_dict(conn.execute("SELECT * FROM campaigns WHERE id=?", (ad["cluster_id"],)).fetchone()) or {}
    members = [r[0] for r in conn.execute("SELECT id FROM ads WHERE cluster_id=? ORDER BY id", (ad["cluster_id"],))]
    hits, _ = match_people(ad_text(ad), [], all_persons(conn), [])
    by_text = {h["id"]: h for h in hits}
    pmap = {p["id"]: p for p in all_persons(conn)}
    people = []
    for pid in ad["persons"]:
        if pid not in pmap:
            continue
        face = next((f for f in ad["faces"] or [] if f.get("person_id") == pid), None)
        via = (["tekst"] if pid in by_text else []) + (["twarz"] if face else [])
        people.append({**pmap[pid], "via": via, "face_similarity": face.get("similarity") if face else None,
                       "matched": by_text[pid]["detail"] if pid in by_text else None})
    # wektory twarzy są duże – do UI wysyłamy tylko ramki i dopasowania
    ad["faces"] = [{k: v for k, v in f.items() if k != "embedding"} for f in ad["faces"] or []]
    return {
        "ad": ad,
        "persons": people,
        "campaign": {"cluster_id": ad["cluster_id"], "name": camp.get("name"), "size": len(members),
                     "members": members, "known": len(members) > 1,
                     "subgroups": camp.get("subgroups") or [], "bridges": camp.get("bridges") or {}},
        "matches": clustering.best_matches(row_to_dict(conn.execute("SELECT * FROM ads WHERE id=?",
                                                                    (ad_id,)).fetchone()), all_ads(conn)),
        "watched": bool(conn.execute("SELECT 1 FROM campaign_watches WHERE campaign_id=?",
                                     (ad["cluster_id"],)).fetchone()),
    }
