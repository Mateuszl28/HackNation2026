"""Ważone podobieństwo wielocechowe + klastrowanie kampanii (spójne składowe grafu powyżej progu)."""
import math
import re
from collections import Counter

from .extract import PLATFORM_DOMAINS, normalize, registrable_domain

WEIGHTS = {
    "same_domain": 0.55,
    "shared_redirect_hop": 0.4,
    "same_title": 0.3,
    "text": 0.6,          # * cosine podobieństwa narracji
    "keywords": 0.3,      # * jaccard haseł
    "person": 0.35,
    "visual": 0.45,       # ten sam szablon graficzny (dHash)
}
THRESHOLD = 0.6
TEXT_MIN = 0.25


def _ngrams(text: str, n: int = 3) -> Counter:
    t = re.sub(r"[^\w ]+", " ", normalize(text))
    t = re.sub(r"\s+", " ", t).strip()
    return Counter(t[i:i + n] for i in range(max(0, len(t) - n + 1)))


def cosine(a: Counter, b: Counter) -> float:
    if not a or not b:
        return 0.0
    dot = sum(v * b.get(k, 0) for k, v in a.items())
    na = math.sqrt(sum(v * v for v in a.values()))
    nb = math.sqrt(sum(v * v for v in b.values()))
    return dot / (na * nb) if na and nb else 0.0


def hamming_hex(a: str, b: str) -> int:
    return bin(int(a, 16) ^ int(b, 16)).count("1")


def _hop_domains(ad: dict) -> set[str]:
    doms = {registrable_domain(u) for u in ad.get("redirect_chain") or []}
    return {d for d in doms if d and d not in PLATFORM_DOMAINS}


def pair_score(a: dict, b: dict, ngram_cache: dict) -> tuple[float, list[str]]:
    score, reasons = 0.0, []
    da, db = a.get("domain"), b.get("domain")
    if da and da == db and da not in PLATFORM_DOMAINS:
        score += WEIGHTS["same_domain"]
        reasons.append(f"ta sama domena {da}")
    else:
        shared = (_hop_domains(a) & _hop_domains(b)) - {da, db}
        if shared:
            score += WEIGHTS["shared_redirect_hop"]
            reasons.append("wspólne przekierowanie przez " + ", ".join(sorted(shared)))
    if a.get("title") and a.get("title") == b.get("title"):
        score += WEIGHTS["same_title"]
        reasons.append("identyczny tytuł strony docelowej")
    sim = cosine(ngram_cache[a["id"]], ngram_cache[b["id"]])
    if sim >= TEXT_MIN:
        score += WEIGHTS["text"] * sim
        reasons.append(f"zbliżona narracja ({sim:.2f})")
    ka, kb = set(a.get("keywords") or []), set(b.get("keywords") or [])
    if ka and kb:
        j = len(ka & kb) / len(ka | kb)
        if j > 0:
            score += WEIGHTS["keywords"] * j
            reasons.append(f"wspólne hasła ({len(ka & kb)})")
    pa, pb = set(a.get("persons") or []), set(b.get("persons") or [])
    if pa & pb:
        score += WEIGHTS["person"]
        reasons.append("ten sam wizerunek osoby")
    if a.get("phash") and b.get("phash"):
        d = hamming_hex(a["phash"], b["phash"])
        if d <= 10:
            score += WEIGHTS["visual"] * (1 - d / 16)
            reasons.append(f"podobny szablon graficzny (odległość {d}/64)")
    return round(score, 3), reasons


def compute(ads: list[dict]) -> tuple[list[dict], dict[int, int]]:
    """Zwraca krawędzie (pary powyżej progu) i mapę ad_id -> cluster_id (najmniejsze id w klastrze)."""
    cache = {a["id"]: _ngrams(" ".join(filter(None, [a.get("text"), a.get("title"), a.get("description")])))
             for a in ads}
    parent = {a["id"]: a["id"] for a in ads}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    edges = []
    for i in range(len(ads)):
        for j in range(i + 1, len(ads)):
            s, reasons = pair_score(ads[i], ads[j], cache)
            if s >= THRESHOLD:
                edges.append({"source": ads[i]["id"], "target": ads[j]["id"], "score": s, "reasons": reasons})
                ra, rb = find(ads[i]["id"]), find(ads[j]["id"])
                if ra != rb:
                    parent[max(ra, rb)] = min(ra, rb)
    return edges, {aid: find(aid) for aid in parent}


def best_matches(target: dict, ads: list[dict], k: int = 5) -> list[dict]:
    pool = [a for a in ads if a["id"] != target["id"]]
    cache = {a["id"]: _ngrams(" ".join(filter(None, [a.get("text"), a.get("title"), a.get("description")])))
             for a in pool + [target]}
    scored = []
    for a in pool:
        s, r = pair_score(target, a, cache)
        if s > 0:
            scored.append({"ad_id": a["id"], "score": s, "reasons": r, "cluster_id": a.get("cluster_id")})
    return sorted(scored, key=lambda x: -x["score"])[:k]
