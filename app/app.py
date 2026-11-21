"""FejkRadar – serwer FastAPI.

Uruchomienie:  uvicorn app.app:app --host 0.0.0.0 --port 8000

Sekcje API:
  analiza      POST /api/submit, POST /share (Web Share Target z PWA), GET /api/ads[/{id}]
  kampanie     GET /api/campaigns, GET /api/graph (format Cytoscape.js), GET /api/edges/{ad_id}, POST /api/rebuild
  osoby        GET/POST /api/persons, PUT/DELETE /api/persons/{id}  (zmiana bazy => ponowne dopasowanie i klastrowanie)
  scheduler    GET /api/scheduler, GET/POST /api/sources, POST /api/sources/{id}/run|toggle   (domyślnie co 30 s)
  alerty       POST/DELETE /api/campaigns/{id}/watch, GET /api/alerts, POST /api/alerts/seen
  demo         POST /api/demo/inject[?scan=true], POST /api/demo/reset
"""
import asyncio
import json
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, Query, UploadFile
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator

from . import pipeline, scheduler
from .analyzer import PLATFORM_DOMAINS, registrable_domain
from .clustering import THRESHOLD
from .db import DATA_DIR, DEMO_VARIANTS, FEED_PATH, connect, init_db, load_json, now, reset_demo, row_to_dict

STATIC = Path(__file__).resolve().parent.parent / "static"
DEFAULT_INTERVAL_S = 30


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    await pipeline.seed_ads()
    task = asyncio.create_task(scheduler.loop())
    yield
    task.cancel()


app = FastAPI(title="FejkRadar", description="Wykrywanie i łączenie w kampanie fałszywych reklam", lifespan=lifespan)


def _get_or_404(sql: str, params: tuple, what: str) -> dict:
    row = row_to_dict(connect().execute(sql, params).fetchone())
    if not row:
        raise HTTPException(404, f"Nie znaleziono: {what}")
    return row


@app.get("/api/health")
def health():
    conn = connect()
    count = lambda t: conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]  # noqa: E731
    return {"ok": True, "ads": count("ads"), "campaigns": count("campaigns"), "persons": count("persons"),
            "unseen_alerts": conn.execute("SELECT COUNT(*) FROM alerts WHERE seen=0").fetchone()[0]}


# =========================================================== analiza
@app.post("/api/submit")
async def submit(url: str = Form(None), text: str = Form(None), file: UploadFile | None = File(None)):
    """Zgłoszenie: URL i/lub tekst/hasło/nazwa produktu i/lub zrzut ekranu. Zwraca szybki raport."""
    data = await file.read() if file and file.filename else None
    url = (url or "").strip() or None
    if url and "://" not in url:
        url = "https://" + url
    if not (url or (text or "").strip() or data):
        raise HTTPException(400, "Podaj URL, tekst/hasło albo plik")
    return await pipeline.analyze(source="manual", url=url, text=text, image=data,
                                  image_name=file.filename if data else None)


@app.post("/share")
async def share_target(title: str = Form(None), text: str = Form(None), url: str = Form(None),
                       files: list[UploadFile] = File(None)):
    """Web Share Target z PWA: 'Udostępnij -> FejkRadar' na telefonie."""
    img = files[0] if files else None
    data = await img.read() if img else None
    if not (url or text or title or data):
        return RedirectResponse("/", status_code=303)
    rep = await pipeline.analyze(source="share", url=url or None, text=" ".join(filter(None, [title, text])),
                                 image=data, image_name=img.filename if img else None)
    return RedirectResponse(f"/#ad/{rep['ad']['id']}", status_code=303)


@app.get("/api/ads")
def list_ads(limit: int = Query(200, ge=1, le=1000)):
    return pipeline.all_ads()[::-1][:limit]


@app.get("/api/ads/{ad_id}")
def get_ad(ad_id: int):
    rep = pipeline.report(ad_id)
    if not rep:
        raise HTTPException(404, "Nie znaleziono reklamy")
    rep["edges"] = pipeline.edges_for(ad_id)
    return rep


# =========================================================== kampanie i graf
def _campaigns(conn) -> list[dict]:
    watched = {r[0] for r in conn.execute("SELECT campaign_id FROM campaign_watches")}
    out = []
    for c in map(row_to_dict, conn.execute("SELECT * FROM campaigns ORDER BY size DESC, max_risk DESC, id")):
        ads = [r[0] for r in conn.execute("SELECT id FROM ads WHERE cluster_id=? ORDER BY id", (c["id"],))]
        out.append({**c, "cluster_id": c["id"], "ads": ads, "keywords": c["themes"], "watched": c["id"] in watched})
    return out


@app.get("/api/campaigns")
def campaigns():
    return _campaigns(connect())


app.add_api_route("/api/clusters", campaigns, methods=["GET"], include_in_schema=False)  # zgodność wsteczna


@app.get("/api/graph")
def graph(campaign: int | None = None, min_size: int = Query(1, ge=1)):
    """Graf powiązań w formacie Cytoscape.js: {elements: {nodes: [{data}], edges: [{data}]}}.

    Węzły: reklamy (ad), domeny docelowe i pośrednie (domain), osoby (person).
    Krawędzie: reklama–domena (domena / przekierowanie), reklama–osoba (wizerunek),
               reklama–reklama (podobieństwo, z wynikiem i powodami).
    """
    conn = connect()
    sizes = {r["id"]: r["size"] for r in conn.execute("SELECT id, size FROM campaigns")}
    names = {r["id"]: r["name"] for r in conn.execute("SELECT id, name FROM campaigns")}
    ads = [a for a in pipeline.all_ads(conn)
           if (campaign is None or a["cluster_id"] == campaign) and sizes.get(a["cluster_id"], 1) >= min_size]
    ad_ids = {a["id"] for a in ads}
    persons = {p["id"]: p for p in pipeline.all_persons(conn)}
    nodes: dict[str, dict] = {}
    edges: list[dict] = []

    def node(nid: str, **data):
        nodes.setdefault(nid, {"data": {"id": nid, **data}, "classes": data["type"]})

    def edge(src: str, dst: str, etype: str, **data):
        edges.append({"data": {"id": f"{etype}:{src}->{dst}", "source": src, "target": dst, "type": etype, **data},
                      "classes": etype})

    for a in ads:
        aid = f"ad{a['id']}"
        node(aid, type="ad", ad_id=a["id"], label=f"#{a['id']} {(a['title'] or a['text'] or '')[:30]}",
             campaign=a["cluster_id"], campaign_name=names.get(a["cluster_id"]), risk=a["risk"], domain=a["domain"])
        if a["domain"]:
            node(f"d:{a['domain']}", type="domain", label=a["domain"])
            edge(aid, f"d:{a['domain']}", "domena")
        for hop in sorted({registrable_domain(u) for u in a["redirect_chain"][:-1]} - {None, a["domain"]}):
            if hop not in PLATFORM_DOMAINS:
                node(f"d:{hop}", type="domain", label=hop)
                edge(aid, f"d:{hop}", "przekierowanie")
        for pid in a["persons"]:
            if pid in persons:
                node(f"p{pid}", type="person", label=persons[pid]["name"], role=persons[pid]["role"])
                edge(aid, f"p{pid}", "wizerunek")
    for e in map(row_to_dict, conn.execute("SELECT * FROM similarity_edges")):
        if e["ad_a"] in ad_ids and e["ad_b"] in ad_ids:
            edge(f"ad{e['ad_a']}", f"ad{e['ad_b']}", "podobieństwo", score=e["score"], reasons=e["reasons"])
    for n in nodes.values():  # stopień węzła – przydatny do rozmiaru w UI
        n["data"]["degree"] = sum(n["data"]["id"] in (e["data"]["source"], e["data"]["target"]) for e in edges)
    return {"elements": {"nodes": list(nodes.values()), "edges": edges},
            "meta": {"threshold": THRESHOLD, "ads": len(ads), "campaigns": len({a["cluster_id"] for a in ads})}}


@app.get("/api/edges/{ad_id}")
def edges_of(ad_id: int):
    return pipeline.edges_for(ad_id)


@app.post("/api/rebuild")
def rebuild():
    """Pełne przeliczenie krawędzi i kampanii (np. po zmianie wag lub progu)."""
    pipeline.rebuild()
    return {"ok": True, "campaigns": connect().execute("SELECT COUNT(*) FROM campaigns").fetchone()[0]}


# =========================================================== obserwowanie i alerty
@app.post("/api/campaigns/{cid}/watch")
def watch(cid: int):
    _get_or_404("SELECT * FROM campaigns WHERE id=?", (cid,), f"kampania #{cid}")
    with connect() as conn:
        conn.execute("INSERT OR IGNORE INTO campaign_watches VALUES (?,?)", (cid, now()))
    return {"ok": True, "watching": cid}


@app.delete("/api/campaigns/{cid}/watch")
def unwatch(cid: int):
    with connect() as conn:
        conn.execute("DELETE FROM campaign_watches WHERE campaign_id=?", (cid,))
    return {"ok": True}


@app.get("/api/alerts")
def alerts(unseen: bool = False, limit: int = Query(50, ge=1, le=500)):
    q = ("SELECT al.*, a.title AS ad_title, a.domain AS ad_domain, c.name AS campaign_name FROM alerts al "
         "LEFT JOIN ads a ON a.id = al.ad_id LEFT JOIN campaigns c ON c.id = al.campaign_id"
         + (" WHERE al.seen=0" if unseen else "") + " ORDER BY al.id DESC LIMIT ?")
    return [dict(r) for r in connect().execute(q, (limit,))]


@app.post("/api/alerts/seen")
def alerts_seen():
    with connect() as conn:
        conn.execute("UPDATE alerts SET seen=1")
    return {"ok": True}


# =========================================================== baza referencyjna osób
class PersonIn(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    role: str | None = Field(None, max_length=200)
    aliases: list[str] = []

    @field_validator("aliases")
    @classmethod
    def _clean(cls, v: list[str]) -> list[str]:
        return [a.strip() for a in v if a and a.strip()]


@app.get("/api/persons")
def persons():
    conn = connect()
    usage = {}
    for a in pipeline.all_ads(conn):
        for p in a["persons"]:
            usage[p] = usage.get(p, 0) + 1
    return [{**p, "ads": usage.get(p["id"], 0)} for p in pipeline.all_persons(conn)]


@app.post("/api/persons", status_code=201)
def add_person(p: PersonIn):
    with connect() as conn:
        pid = conn.execute("INSERT INTO persons(name, role, aliases) VALUES (?,?,?)",
                           (p.name.strip(), p.role, json.dumps(p.aliases, ensure_ascii=False))).lastrowid
    return {"ok": True, "id": pid, "rematched_ads": pipeline.rematch_persons()}


@app.put("/api/persons/{pid}")
def update_person(pid: int, p: PersonIn):
    _get_or_404("SELECT * FROM persons WHERE id=?", (pid,), f"osoba #{pid}")
    with connect() as conn:
        conn.execute("UPDATE persons SET name=?, role=?, aliases=? WHERE id=?",
                     (p.name.strip(), p.role, json.dumps(p.aliases, ensure_ascii=False), pid))
    return {"ok": True, "rematched_ads": pipeline.rematch_persons()}


@app.delete("/api/persons/{pid}")
def del_person(pid: int):
    with connect() as conn:
        conn.execute("DELETE FROM persons WHERE id=?", (pid,))
    return {"ok": True, "rematched_ads": pipeline.rematch_persons()}


# =========================================================== scheduler
class SourceIn(BaseModel):
    target: str = Field(min_length=3)
    interval_s: int = Field(DEFAULT_INTERVAL_S, ge=5, le=86400)
    kind: str = "json_feed"


@app.get("/api/scheduler")
def scheduler_status():
    conn = connect()
    srcs = [row_to_dict(r) for r in conn.execute("SELECT * FROM sources")]
    t = now()
    for s in srcs:
        s["next_run_in_s"] = max(0, round((s["last_run"] or 0) + s["interval_s"] - t)) if s["enabled"] else None
    return {"tick_s": scheduler.TICK_S, "sources": srcs,
            "log": [dict(r) for r in conn.execute("SELECT * FROM scan_log ORDER BY id DESC LIMIT 20")]}


app.add_api_route("/api/sources", scheduler_status, methods=["GET"], include_in_schema=False)


@app.post("/api/sources", status_code=201)
def add_source(s: SourceIn):
    if s.kind != "json_feed":
        raise HTTPException(400, "Obsługiwany typ źródła: json_feed")
    with connect() as conn:
        sid = conn.execute("INSERT INTO sources(kind, target, interval_s, last_run) VALUES (?,?,?,0)",
                           (s.kind, s.target.strip(), s.interval_s)).lastrowid
    return {"ok": True, "id": sid}


@app.post("/api/sources/{sid}/toggle")
def toggle_source(sid: int):
    _get_or_404("SELECT * FROM sources WHERE id=?", (sid,), f"źródło #{sid}")
    with connect() as conn:
        conn.execute("UPDATE sources SET enabled = 1 - enabled WHERE id=?", (sid,))
    return {"ok": True}


@app.post("/api/sources/{sid}/run")
async def run_source(sid: int):
    return await scheduler.run_source(_get_or_404("SELECT * FROM sources WHERE id=?", (sid,), f"źródło #{sid}"))


# =========================================================== demo
@app.post("/api/demo/inject")
async def demo_inject(scan: bool = False):
    """Dopisuje do fikcyjnej biblioteki reklam kolejny wariant znanej kampanii.
    Scheduler wyłapie go przy najbliższym skanie (≤ 30 s); scan=true skanuje od razu."""
    feed = load_json(FEED_PATH)
    existing = {i.get("id") for i in feed}
    pending = [v for v in load_json(DEMO_VARIANTS) if v["id"] not in existing]
    if not pending:
        return {"ok": False, "message": "Wszystkie warianty demo już wstrzyknięte – użyj Reset demo"}
    item = pending[0]  # stała kolejność = powtarzalna prezentacja
    feed.append(item)
    FEED_PATH.write_text(json.dumps(feed, ensure_ascii=False, indent=2), encoding="utf-8")
    res = {"ok": True, "injected": item["id"], "remaining": len(pending) - 1}
    if scan:
        src = row_to_dict(connect().execute("SELECT * FROM sources WHERE target=?", (str(FEED_PATH),)).fetchone())
        if src:
            res["scan"] = await scheduler.run_source(src)
    return res


@app.post("/api/demo/reset")
async def demo_reset():
    """Stan początkowy: 7 reklam demo, feed bez wstrzykniętych wariantów, bez alertów i obserwacji."""
    reset_demo()
    return {"ok": True, "seeded": await pipeline.seed_ads()}


# =========================================================== frontend (PWA)
app.mount("/uploads", StaticFiles(directory=DATA_DIR / "uploads"), name="uploads")
app.mount("/static", StaticFiles(directory=STATIC), name="static")


@app.get("/", include_in_schema=False)
def index():
    return FileResponse(STATIC / "index.html")


@app.get("/manifest.webmanifest", include_in_schema=False)
def manifest():
    return FileResponse(STATIC / "manifest.webmanifest", media_type="application/manifest+json")


@app.get("/sw.js", include_in_schema=False)
def sw():
    return FileResponse(STATIC / "sw.js", media_type="application/javascript")
