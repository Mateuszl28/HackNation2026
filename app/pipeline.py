"""Potok analizy: wejście -> ekstrakcja sygnałów -> zapis (reklama + cechy) -> klastrowanie (krawędzie + kampanie) -> alerty."""
import json
import uuid
from collections import Counter

from . import similarity
from .db import DATA_DIR, SEED_ADS, connect, load_json, now, row_to_dict
from .analyzer import (analyze_url, dhash, domain_age_days, extract_keywords, find_urls, match_persons_detailed,
                       ocr_image, registrable_domain, risk_score)

UPLOADS = DATA_DIR / "uploads"
UPLOADS.mkdir(exist_ok=True)

THEME_NAMES = {"inwestycja": "Fałszywe inwestycje", "cud_medyczny": "Cudowny lek", "falszywy_news": "Fałszywy news",
               "pilnosc": "Presja czasu", "wplata": "Wyłudzenie danych/wpłaty"}


def all_ads(conn=None) -> list[dict]:
    conn = conn or connect()
    return [row_to_dict(r) for r in conn.execute("SELECT * FROM ads ORDER BY id")]


def all_persons(conn=None) -> list[dict]:
    conn = conn or connect()
    return [row_to_dict(r) for r in conn.execute("SELECT * FROM persons ORDER BY id")]


def _features(ad: dict) -> list[tuple[str, str]]:
    f = []
    if ad.get("domain"):
        f.append(("domain", ad["domain"]))
    for u in (ad.get("redirect_chain") or [])[:-1]:
        d = registrable_domain(u)
        if d and d != ad.get("domain") and d not in similarity.PLATFORM_DOMAINS:
            f.append(("redirect_hop", d))
    for k in ad.get("keywords") or []:
        f.append(("keyword", k))
        f.append(("theme", k.split(":")[0]))
    f += [("person", str(p)) for p in ad.get("persons") or []]
    if ad.get("phash"):
        f.append(("phash", ad["phash"]))
    if ad.get("title"):
        f.append(("title", ad["title"]))
    return sorted(set(f))


async def analyze(*, source: str, url: str | None = None, text: str | None = None, image: bytes | None = None,
                  image_name: str | None = None, prefetched: dict | None = None, external_id: str | None = None,
                  recluster: bool = True) -> dict:
    """prefetched: dane z biblioteki reklam (redirect_chain, title, domain_age_days...) – pomija pobieranie z sieci."""
    prefetched = prefetched or {}
    text = text or ""
    image_path, phash = None, None
    if image:
        ext = (image_name or "img.png").rsplit(".", 1)[-1][:5]
        fname = f"{uuid.uuid4().hex}.{ext}"
        (UPLOADS / fname).write_bytes(image)
        image_path = f"uploads/{fname}"
        phash = dhash(image)
        ocr = ocr_image(image)
        if ocr.strip():
            text = (text + "\n" + ocr).strip()
    phash = prefetched.get("phash", phash)

    if not url:
        urls = find_urls(text)
        url = urls[0] if urls else None

    page = {"input_url": url, "final_url": url, "redirect_chain": [url] if url else [], "title": None,
            "description": None, "page_text": "", "error": None}
    if "redirect_chain" in prefetched:
        page.update({k: prefetched[k] for k in ("redirect_chain", "title", "description") if k in prefetched})
        page["final_url"] = (prefetched.get("redirect_chain") or [url])[-1]
    elif url:
        page = await analyze_url(url)

    domain = registrable_domain(page["final_url"] or url or "")
    age = prefetched.get("domain_age_days", page.get("domain_age_days"))
    if age is None and domain and "redirect_chain" not in prefetched:
        age = await domain_age_days(domain)

    full_text = " ".join(filter(None, [text, page.get("title"), page.get("description"), page.get("page_text")]))
    person_hits = match_persons_detailed(full_text, all_persons())
    ad = {
        "created_at": now(), "source": source, "external_id": external_id, "input_url": url,
        "final_url": page["final_url"], "domain": domain, "redirect_chain": page["redirect_chain"],
        "title": page.get("title"), "description": page.get("description"),
        "text": (text or page.get("page_text") or "")[:5000], "keywords": extract_keywords(full_text),
        "persons": [m["id"] for m in person_hits], "phash": phash, "image_path": image_path,
        "domain_age_days": age,
    }
    ad["risk"], ad["risk_reasons"] = risk_score(ad, page, [f"{m['name']} („{m['matched']}”)" for m in person_hits])
    if page.get("error"):
        ad["risk_reasons"].append(f"nie udało się pobrać strony: {page['error'][:120]}")

    with connect() as conn:
        cols = list(ad.keys())
        vals = [json.dumps(v, ensure_ascii=False) if isinstance(v, list) else v for v in ad.values()]
        ad_id = conn.execute(f"INSERT INTO ads({','.join(cols)}) VALUES ({','.join('?' * len(cols))})", vals).lastrowid
        conn.executemany("INSERT OR IGNORE INTO ad_features VALUES (?,?,?)",
                         [(ad_id, k, v) for k, v in _features(ad)])
    if recluster:
        recluster_and_alert(new_ad_ids=[ad_id])
    return report(ad_id) if recluster else {"ad": {"id": ad_id}}


async def seed_ads() -> int:
    """Zasiewa bazę 7 fikcyjnymi reklamami demo (tylko gdy jest pusta)."""
    if connect().execute("SELECT COUNT(*) FROM ads").fetchone()[0]:
        return 0
    items = load_json(SEED_ADS)
    for it in items:
        prefetched = {k: it[k] for k in ("redirect_chain", "title", "description", "domain_age_days", "phash") if k in it}
        await analyze(source="seed", url=it.get("url"), text=it.get("text"), prefetched=prefetched,
                      external_id=it.get("id"), recluster=False)
    recluster_and_alert()
    return len(items)


def _campaign_name(members: list[dict], persons: dict) -> str:
    themes = Counter(k.split(":")[0] for a in members for k in a["keywords"])
    # motywy konkretne (co jest obiecywane) mają pierwszeństwo przed ogólnymi (presja czasu, wpłata)
    tier = {"inwestycja": 0, "cud_medyczny": 0, "falszywy_news": 1}
    ranked = sorted(themes, key=lambda t: (tier.get(t, 2), -themes[t]))
    main = [THEME_NAMES.get(t, t) for t in ranked[:2]]
    people = Counter(p for a in members for p in a["persons"])
    who = persons.get(people.most_common(1)[0][0], {}).get("name") if people else None
    name = " + ".join(main) if main else "Bez wyraźnego motywu"
    return f"{name} ({who})" if who else name


def recluster_and_alert(new_ad_ids: list[int] | None = None) -> None:
    with connect() as conn:
        ads = all_ads(conn)
        edges, clusters = similarity.compute(ads)
        conn.executemany("UPDATE ads SET cluster_id=? WHERE id=?", [(c, a) for a, c in clusters.items()])

        conn.execute("DELETE FROM similarity_edges")
        conn.executemany("INSERT INTO similarity_edges VALUES (?,?,?,?)",
                         [(e["source"], e["target"], e["score"], json.dumps(e["reasons"], ensure_ascii=False))
                          for e in edges])

        persons = {p["id"]: p for p in all_persons(conn)}
        groups: dict[int, list[dict]] = {}
        for a in ads:
            groups.setdefault(clusters[a["id"]], []).append(a)
        conn.execute("DELETE FROM campaigns")
        for cid, members in groups.items():
            conn.execute(
                "INSERT INTO campaigns VALUES (?,?,?,?,?,?,?,?,?)",
                (cid, _campaign_name(members, persons), len(members), max(a["risk"] or 0 for a in members),
                 json.dumps(sorted({a["domain"] for a in members if a["domain"]})),
                 json.dumps(sorted({k.split(":")[0] for a in members for k in a["keywords"]})),
                 json.dumps(sorted({p for a in members for p in a["persons"]})),
                 min(a["created_at"] for a in members), max(a["created_at"] for a in members)))

        # obserwowane kampanie: id kampanii to id reklamy, więc po scaleniu klastrów watch "podąża" za nią
        for w in conn.execute("SELECT campaign_id FROM campaign_watches").fetchall():
            old = w["campaign_id"]
            cur = clusters.get(old)
            if cur is None:
                continue
            if cur != old:
                conn.execute("UPDATE OR IGNORE campaign_watches SET campaign_id=? WHERE campaign_id=?", (cur, old))
            for nid in new_ad_ids or []:
                if nid != cur and clusters.get(nid) == cur:
                    conn.execute(
                        "INSERT INTO alerts(created_at, ad_id, campaign_id, message) VALUES (?,?,?,?)",
                        (now(), nid, cur, f"Nowy wariant w obserwowanej kampanii #{cur} (reklama #{nid})"))


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
    pmap = {p["id"]: p for p in all_persons(conn)}
    return {
        "ad": ad,
        "persons": [pmap[p] for p in ad["persons"] if p in pmap],
        "campaign": {"cluster_id": ad["cluster_id"], "name": camp.get("name"), "size": len(members),
                     "members": members, "known": len(members) > 1},
        "matches": similarity.best_matches(ad, all_ads(conn)),
        "watched": bool(conn.execute("SELECT 1 FROM campaign_watches WHERE campaign_id=?",
                                     (ad["cluster_id"],)).fetchone()),
    }
