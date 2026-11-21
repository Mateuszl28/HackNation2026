"""Scheduler w tle: cyklicznie skanuje źródła (biblioteki reklam / feedy JSON) i przepuszcza nowe pozycje przez potok."""
import asyncio
import hashlib
import json
from pathlib import Path

import httpx

from . import pipeline
from .db import connect, now, row_to_dict

TICK_S = 5


async def load_feed(target: str) -> list[dict]:
    if target.startswith("http"):
        async with httpx.AsyncClient(timeout=15) as c:
            r = await c.get(target)
            r.raise_for_status()
            return r.json()
    p = Path(target)
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else []


def item_key(item: dict) -> str:
    return item.get("id") or hashlib.sha1(json.dumps(item, sort_keys=True).encode()).hexdigest()


async def run_source(src: dict) -> dict:
    found = new = 0
    try:
        items = await load_feed(src["target"])
        found = len(items)
        conn = connect()
        for it in items:
            key = item_key(it)
            if conn.execute("SELECT 1 FROM seen_items WHERE source_id=? AND item_key=?", (src["id"], key)).fetchone():
                continue
            with conn:
                conn.execute("INSERT INTO seen_items VALUES (?,?)", (src["id"], key))
            prefetched = {k: it[k] for k in ("redirect_chain", "title", "description", "domain_age_days", "phash")
                          if k in it}
            await pipeline.analyze(source=f"scheduler:{src['id']}", url=it.get("url"), text=it.get("text"),
                                   prefetched=prefetched)
            new += 1
        status = f"ok: {found} pozycji, {new} nowych"
    except Exception as e:
        status = f"błąd: {type(e).__name__}: {e}"[:300]
    with connect() as conn:
        conn.execute("UPDATE sources SET last_run=?, last_status=? WHERE id=?", (now(), status, src["id"]))
        conn.execute("INSERT INTO scan_log(created_at, source_id, found, new, message) VALUES (?,?,?,?,?)",
                     (now(), src["id"], found, new, status))
    return {"source_id": src["id"], "found": found, "new": new, "status": status}


async def loop() -> None:
    while True:
        try:
            srcs = [row_to_dict(r) for r in connect().execute("SELECT * FROM sources WHERE enabled=1")]
            for s in srcs:
                if now() - (s["last_run"] or 0) >= s["interval_s"]:
                    await run_source(s)
        except Exception as e:
            print("[scheduler]", e)
        await asyncio.sleep(TICK_S)
