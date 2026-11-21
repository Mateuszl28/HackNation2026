"""Potok analizy: wejście -> ekstrakcja sygnałów -> zapis -> ponowne klastrowanie -> alerty."""
import json
import uuid

from . import similarity
from .db import DATA_DIR, connect, now, row_to_dict
from .extract import (analyze_url, dhash, domain_age_days, extract_keywords, find_urls, match_persons,
                      ocr_image, registrable_domain, risk_score)

UPLOADS = DATA_DIR / "uploads"
UPLOADS.mkdir(exist_ok=True)


def all_ads(conn=None) -> list[dict]:
    conn = conn or connect()
    return [row_to_dict(r) for r in conn.execute("SELECT * FROM ads ORDER BY id")]


def all_persons(conn=None) -> list[dict]:
    conn = conn or connect()
    return [row_to_dict(r) for r in conn.execute("SELECT * FROM persons ORDER BY id")]


async def analyze(*, source: str, url: str | None = None, text: str | None = None,
                  image: bytes | None = None, image_name: str | None = None, prefetched: dict | None = None) -> dict:
    """prefetched: dane z biblioteki reklam (np. redirect_chain, title, domain_age_days) – pomija pobieranie sieciowe."""
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
        page.update({k: prefetched.get(k) for k in ("redirect_chain", "title", "description") if k in prefetched})
        page["final_url"] = (prefetched.get("redirect_chain") or [url])[-1]
    elif url:
        page = await analyze_url(url)

    domain = registrable_domain(page["final_url"] or url or "")
    age = prefetched.get("domain_age_days")
    if age is None and domain and "redirect_chain" not in prefetched:
        age = await domain_age_days(domain)

    full_text = " ".join(filter(None, [text, page.get("title"), page.get("description"), page.get("page_text")]))
    persons = all_persons()
    ad = {
        "created_at": now(), "source": source, "input_url": url, "final_url": page["final_url"], "domain": domain,
        "redirect_chain": page["redirect_chain"], "title": page.get("title"), "description": page.get("description"),
        "text": (text or page.get("page_text") or "")[:5000], "keywords": extract_keywords(full_text),
        "persons": match_persons(full_text, persons), "phash": phash, "image_path": image_path,
        "domain_age_days": age,
    }
    ad["risk"], ad["risk_reasons"] = risk_score(ad)
    if page.get("error"):
        ad["risk_reasons"].append(f"nie udało się pobrać strony: {page['error'][:120]}")

    with connect() as conn:
        cols = list(ad.keys())
        vals = [json.dumps(v, ensure_ascii=False) if isinstance(v, list) else v for v in ad.values()]
        cur = conn.execute(f"INSERT INTO ads({','.join(cols)}) VALUES ({','.join('?' * len(cols))})", vals)
        ad_id = cur.lastrowid
    recluster_and_alert(new_ad_id=ad_id)
    return report(ad_id)


def recluster_and_alert(new_ad_id: int | None = None) -> None:
    with connect() as conn:
        ads = all_ads(conn)
        _, clusters = similarity.compute(ads)
        for aid, cid in clusters.items():
            conn.execute("UPDATE ads SET cluster_id=? WHERE id=?", (cid, aid))
        if new_ad_id is None:
            return
        new_cluster = clusters.get(new_ad_id)
        for w in conn.execute("SELECT ad_id FROM watches").fetchall():
            wid = w["ad_id"]
            if wid != new_ad_id and clusters.get(wid) == new_cluster:
                conn.execute(
                    "INSERT INTO alerts(created_at, ad_id, watched_ad_id, message) VALUES (?,?,?,?)",
                    (now(), new_ad_id, wid,
                     f"Nowy wariant w obserwowanej kampanii #{new_cluster} (reklama #{new_ad_id})"),
                )


def report(ad_id: int) -> dict:
    conn = connect()
    ad = row_to_dict(conn.execute("SELECT * FROM ads WHERE id=?", (ad_id,)).fetchone())
    if not ad:
        return {}
    ads = all_ads(conn)
    members = [a["id"] for a in ads if a["cluster_id"] == ad["cluster_id"]]
    pmap = {p["id"]: p for p in all_persons(conn)}
    return {
        "ad": ad,
        "persons": [pmap[p] for p in ad["persons"] if p in pmap],
        "campaign": {"cluster_id": ad["cluster_id"], "size": len(members), "members": members,
                     "known": len(members) > 1},
        "matches": similarity.best_matches(ad, ads),
        "watched": bool(conn.execute("SELECT 1 FROM watches WHERE ad_id=?", (ad_id,)).fetchone()),
    }
