import asyncio
import json
import random
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import pipeline, scheduler, similarity
from .db import DATA_DIR, DEMO_VARIANTS, FEED_PATH, connect, init_db, load_json, now, reset_demo, row_to_dict

STATIC = Path(__file__).resolve().parent.parent / "static"


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    await pipeline.seed_ads()
    task = asyncio.create_task(scheduler.loop())
    yield
    task.cancel()


app = FastAPI(title="FejkRadar", lifespan=lifespan)


# ---------- zgłoszenia ----------
@app.post("/api/submit")
async def submit(url: str = Form(None), text: str = Form(None), file: UploadFile | None = File(None)):
    data = await file.read() if file and file.filename else None
    if not (url or text or data):
        raise HTTPException(400, "Podaj URL, tekst/hasło albo plik")
    return await pipeline.analyze(source="manual", url=url or None, text=text, image=data,
                                  image_name=file.filename if data else None)


@app.post("/share")
async def share_target(title: str = Form(None), text: str = Form(None), url: str = Form(None),
                       files: list[UploadFile] = File(None)):
    """Web Share Target z PWA: 'Udostępnij -> FejkRadar' na telefonie."""
    img = files[0] if files else None
    data = await img.read() if img else None
    rep = await pipeline.analyze(source="share", url=url or None, text=" ".join(filter(None, [title, text])),
                                 image=data, image_name=img.filename if img else None)
    return RedirectResponse(f"/#ad/{rep['ad']['id']}", status_code=303)


@app.get("/api/ads")
def list_ads():
    return pipeline.all_ads()[::-1]


@app.get("/api/ads/{ad_id}")
def get_ad(ad_id: int):
    rep = pipeline.report(ad_id)
    if not rep:
        raise HTTPException(404)
    return rep


# ---------- kampanie / graf ----------
@app.get("/api/graph")
def graph():
    conn = connect()
    ads = pipeline.all_ads(conn)
    persons = {p["id"]: p for p in pipeline.all_persons(conn)}
    edges = [row_to_dict(r) for r in conn.execute("SELECT * FROM similarity_edges")]
    nodes, links = [], []
    for a in ads:
        nodes.append({"id": f"ad{a['id']}", "type": "ad", "label": f"#{a['id']} {(a['title'] or a['text'] or '')[:30]}",
                      "cluster": a["cluster_id"], "risk": a["risk"]})
        if a["domain"]:
            nodes.append({"id": f"d:{a['domain']}", "type": "domain", "label": a["domain"]})
            links.append({"source": f"ad{a['id']}", "target": f"d:{a['domain']}", "type": "domena"})
        for pid in a["persons"]:
            if pid in persons:
                nodes.append({"id": f"p{pid}", "type": "person", "label": persons[pid]["name"]})
                links.append({"source": f"ad{a['id']}", "target": f"p{pid}", "type": "wizerunek"})
        for hop in set(filter(None, (pipeline.registrable_domain(u) for u in a["redirect_chain"][:-1]))):
            if hop != a["domain"] and hop not in similarity.PLATFORM_DOMAINS:
                nodes.append({"id": f"d:{hop}", "type": "domain", "label": hop})
                links.append({"source": f"ad{a['id']}", "target": f"d:{hop}", "type": "przekierowanie"})
    for e in edges:
        links.append({"source": f"ad{e['ad_a']}", "target": f"ad{e['ad_b']}", "type": "podobieństwo",
                      "score": e["score"], "reasons": e["reasons"]})
    uniq = {n["id"]: n for n in nodes}
    return {"nodes": list(uniq.values()), "links": links}


@app.get("/api/clusters")
def clusters():
    conn = connect()
    watched = {r[0] for r in conn.execute("SELECT campaign_id FROM campaign_watches")}
    out = []
    for c in map(row_to_dict, conn.execute("SELECT * FROM campaigns ORDER BY size DESC, max_risk DESC")):
        ads = [r[0] for r in conn.execute("SELECT id FROM ads WHERE cluster_id=? ORDER BY id", (c["id"],))]
        out.append({**c, "cluster_id": c["id"], "ads": ads, "keywords": c["themes"], "watched": c["id"] in watched})
    return out


@app.get("/api/edges/{ad_id}")
def edges(ad_id: int):
    return pipeline.edges_for(ad_id)


# ---------- obserwowanie kampanii i alerty ----------
@app.post("/api/campaigns/{cid}/watch")
def watch(cid: int):
    with connect() as conn:
        conn.execute("INSERT OR IGNORE INTO campaign_watches VALUES (?,?)", (cid, now()))
    return {"ok": True}


@app.delete("/api/campaigns/{cid}/watch")
def unwatch(cid: int):
    with connect() as conn:
        conn.execute("DELETE FROM campaign_watches WHERE campaign_id=?", (cid,))
    return {"ok": True}


@app.get("/api/alerts")
def alerts(unseen: bool = False):
    q = "SELECT * FROM alerts" + (" WHERE seen=0" if unseen else "") + " ORDER BY id DESC LIMIT 50"
    return [dict(r) for r in connect().execute(q)]


@app.post("/api/alerts/seen")
def alerts_seen():
    with connect() as conn:
        conn.execute("UPDATE alerts SET seen=1")
    return {"ok": True}


# ---------- baza referencyjna osób ----------
class PersonIn(BaseModel):
    name: str
    role: str | None = None
    aliases: list[str] = []


@app.get("/api/persons")
def persons():
    return pipeline.all_persons()


@app.post("/api/persons")
def add_person(p: PersonIn):
    with connect() as conn:
        conn.execute("INSERT INTO persons(name, role, aliases) VALUES (?,?,?)",
                     (p.name, p.role, json.dumps(p.aliases, ensure_ascii=False)))
    return {"ok": True}


@app.delete("/api/persons/{pid}")
def del_person(pid: int):
    with connect() as conn:
        conn.execute("DELETE FROM persons WHERE id=?", (pid,))
    return {"ok": True}


# ---------- scheduler ----------
class SourceIn(BaseModel):
    target: str
    interval_s: int = 60
    kind: str = "json_feed"


@app.get("/api/sources")
def sources():
    conn = connect()
    return {"sources": [row_to_dict(r) for r in conn.execute("SELECT * FROM sources")],
            "log": [dict(r) for r in conn.execute("SELECT * FROM scan_log ORDER BY id DESC LIMIT 20")]}


@app.post("/api/sources")
def add_source(s: SourceIn):
    with connect() as conn:
        conn.execute("INSERT INTO sources(kind, target, interval_s, last_run) VALUES (?,?,?,0)",
                     (s.kind, s.target, s.interval_s))
    return {"ok": True}


@app.post("/api/sources/{sid}/toggle")
def toggle_source(sid: int):
    with connect() as conn:
        conn.execute("UPDATE sources SET enabled = 1 - enabled WHERE id=?", (sid,))
    return {"ok": True}


@app.post("/api/sources/{sid}/run")
async def run_source(sid: int):
    src = row_to_dict(connect().execute("SELECT * FROM sources WHERE id=?", (sid,)).fetchone())
    if not src:
        raise HTTPException(404)
    return await scheduler.run_source(src)


@app.post("/api/demo/inject")
def demo_inject():
    """Demo: dopisuje do feedu nowy wariant istniejącej kampanii – scheduler go wyłapie i wyśle alert."""
    feed = load_json(FEED_PATH)
    existing = {i.get("id") for i in feed}
    pending = [v for v in load_json(DEMO_VARIANTS) if v["id"] not in existing]
    if not pending:
        return {"ok": False, "message": "Wszystkie warianty demo już wstrzyknięte"}
    item = random.choice(pending)
    feed.append(item)
    FEED_PATH.write_text(json.dumps(feed, ensure_ascii=False, indent=2), encoding="utf-8")
    return {"ok": True, "injected": item["id"]}


@app.post("/api/demo/reset")
async def demo_reset():
    """Przywraca stan początkowy: 7 reklam demo, pusty dziennik, feed bez wstrzykniętych wariantów."""
    reset_demo()
    n = await pipeline.seed_ads()
    return {"ok": True, "seeded": n}


# ---------- frontend (PWA) ----------
app.mount("/uploads", StaticFiles(directory=DATA_DIR / "uploads"), name="uploads")
app.mount("/static", StaticFiles(directory=STATIC), name="static")


@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")


@app.get("/manifest.webmanifest")
def manifest():
    return FileResponse(STATIC / "manifest.webmanifest", media_type="application/manifest+json")


@app.get("/sw.js")
def sw():
    return FileResponse(STATIC / "sw.js", media_type="application/javascript")
