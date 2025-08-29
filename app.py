# app.py
import os
import time
import json
from typing import List, Dict, Any, Optional, Tuple, Set

import httpx
from fastapi import FastAPI, Response, Request
from pydantic import BaseModel

# --- Prometheus metrics ---
from prometheus_client import (
    Counter, Histogram, Gauge, CollectorRegistry, CONTENT_TYPE_LATEST, generate_latest
)
try:
    from prometheus_client import multiprocess  # optional
except Exception:
    multiprocess = None

REGISTRY = CollectorRegistry()
if multiprocess:
    try:
        multiprocess.MultiProcessCollector(REGISTRY)
    except Exception:
        pass

HTTP_REQS = Counter(
    "webhook_http_requests_total", "HTTP requests total",
    ["method", "path", "code"], registry=REGISTRY
)
HTTP_LAT = Histogram(
    "webhook_http_request_latency_seconds", "HTTP request latency",
    ["method", "path"], buckets=(0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5), registry=REGISTRY
)
REG_API_CALLS = Counter(
    "regru_api_calls_total", "Reg.ru API calls", ["method"], registry=REGISTRY
)
REG_API_ERRORS = Counter(
    "regru_api_errors_total", "Reg.ru API errors", ["method"], registry=REGISTRY
)
REG_API_LAT = Histogram(
    "regru_api_latency_seconds", "Reg.ru API latency", ["method"], registry=REGISTRY
)
CACHE_HITS = Counter(
    "cache_hits_total", "Cache hits", ["zone"], registry=REGISTRY
)
CACHE_MISSES = Counter(
    "cache_misses_total", "Cache misses", ["zone"], registry=REGISTRY
)
CACHE_ZONES = Gauge(
    "cache_zones_count", "Number of zones in cache", registry=REGISTRY
)
CACHE_RECORDS = Gauge(
    "cache_records_count", "Total records cached", registry=REGISTRY
)
APPLY_ADDS = Counter(
    "apply_changes_added_total", "Records scheduled to add", ["zone", "type"], registry=REGISTRY
)
APPLY_DELS = Counter(
    "apply_changes_deleted_total", "Records scheduled to delete", ["zone", "type"], registry=REGISTRY
)
APPLY_NOOP = Counter(
    "apply_noop_total", "Apply no-op decisions", registry=REGISTRY
)

# --- Config ---
REG_API_URL = os.getenv("REGRU_API_URL", "https://api.reg.ru/api/regru2")
REG_USERNAME = os.getenv("REGRU_USERNAME")
REG_PASSWORD = os.getenv("REGRU_PASSWORD")
DOMAIN_FILTERS = [z.strip().lower() for z in os.getenv("DOMAIN_FILTERS", "").split(",") if z.strip()]
DEFAULT_TTL = int(os.getenv("DEFAULT_TTL", "300"))
CACHE_TTL_SECONDS = int(os.getenv("CACHE_TTL_SECONDS", "60"))
CACHE_MAX_ZONES = int(os.getenv("CACHE_MAX_ZONES", "100"))

SUPPORTED_TYPES = {"A", "AAAA", "CNAME", "TXT", "MX", "SRV", "CAA", "NS", "HTTPS"}

# --- Models (ExternalDNS) ---
class Endpoint(BaseModel):
    dnsName: str
    targets: List[str]
    recordTTL: Optional[int] = None
    recordType: str

class Changes(BaseModel):
    Create: List[Endpoint] = []
    UpdateNew: List[Endpoint] = []
    UpdateOld: List[Endpoint] = []
    Delete: List[Endpoint] = []

app = FastAPI()

# --- HTTP metrics middleware ---
@app.middleware("http")
async def _metrics_middleware(request: Request, call_next):
    path = request.url.path
    method = request.method
    with HTTP_LAT.labels(method, path).time():
        resp = await call_next(request)
    HTTP_REQS.labels(method, path, str(resp.status_code)).inc()
    return resp

# ------------------ Utils ------------------
def _norm_fqdn(s: str) -> str:
    return s.rstrip(".").lower()

def _split_name(name: str) -> Tuple[str, str]:
    name = _norm_fqdn(name)
    for z in sorted(DOMAIN_FILTERS, key=len, reverse=True):
        if name.endswith(z):
            sub = name[:-len(z)].rstrip(".")
            return (sub if sub else "@", z)
    parts = name.split(".")
    if len(parts) >= 2:
        zone = ".".join(parts[-2:])
        sub = ".".join(parts[:-2]) or "@"
        return sub, zone
    return "@", name

def _fqdn(sub: str, zone: str) -> str:
    return zone if sub in ("@", "") else f"{sub}.{zone}"

def _ttl_to_seconds(t: Any) -> int:
    try:
        t = str(t).strip().lower()
        if t.endswith("d"):
            return int(float(t[:-1]) * 86400)
        if t.endswith("h"):
            return int(float(t[:-1]) * 3600)
        return int(t)
    except Exception:
        return DEFAULT_TTL

# ---- presentation parsers (targets as strings) ----
# MX:    "10 mail.example.com"
# SRV:   "0 5 5060 sip.example.com"
# CAA:   "0 issue letsencrypt.org"
# HTTPS: "1 . alpn=h3,h2 ipv4hint=192.0.2.1,192.0.2.2"
def parse_mx(s: str) -> Tuple[int, str]:
    parts = s.split()
    if len(parts) < 2:
        raise ValueError("MX content must be 'priority host'")
    prio = int(parts[0])
    host = _norm_fqdn(parts[1])
    return prio, host

def parse_srv(s: str) -> Tuple[int, int, int, str]:
    parts = s.split()
    if len(parts) < 4:
        raise ValueError("SRV content must be 'priority weight port target'")
    prio = int(parts[0]); weight = int(parts[1]); port = int(parts[2]); target = _norm_fqdn(parts[3])
    return prio, weight, port, target

def parse_caa(s: str) -> Tuple[int, str, str]:
    parts = s.split(maxsplit=2)
    if len(parts) < 3:
        raise ValueError("CAA content must be 'flags tag value'")
    flags = int(parts[0]); tag = parts[1].lower(); value = parts[2]
    return flags, tag, value

def parse_https(s: str) -> Tuple[int, str, str]:
    parts = s.split(maxsplit=2)
    if len(parts) < 3:
        raise ValueError("HTTPS content must be 'priority target params'")
    prio = int(parts[0]); target = parts[1]; params = parts[2]
    return prio, target, params

# ------------------ Reg.ru API ------------------
async def reg_call(path: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    REG_API_CALLS.labels(path).inc()
    with REG_API_LAT.labels(path).time():
        data = {
            "username": REG_USERNAME,
            "password": REG_PASSWORD,
            "input_format": "json",
            "output_format": "json",
            "input_data": json.dumps(payload, ensure_ascii=False),
        }
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                r = await client.post(f"{REG_API_URL}/{path}", data=data)
                r.raise_for_status()
                return r.json()
        except Exception:
            REG_API_ERRORS.labels(path).inc()
            raise

# ------------------ Cache ------------------
# _cache["example.com"] = {
#   "fetched_at": <ts>,
#   "records": List[Endpoint],
#   "index": { (sub, type): {"targets": set[str], "ttl": int} }
# }
_cache: Dict[str, Dict[str, Any]] = {}

def _recalc_cache_gauges():
    CACHE_ZONES.set(len(_cache))
    total = sum(len(item.get("records", [])) for item in _cache.values())
    CACHE_RECORDS.set(total)

def _cache_get_valid(zone: str) -> Optional[Dict[str, Any]]:
    item = _cache.get(zone)
    if not item:
        CACHE_MISSES.labels(zone).inc()
        return None
    if time.time() - item["fetched_at"] > CACHE_TTL_SECONDS:
        CACHE_MISSES.labels(zone).inc()
        return None
    CACHE_HITS.labels(zone).inc()
    return item

def _cache_put_zone(zone: str, endpoints: List[Endpoint]) -> None:
    if len(_cache) >= CACHE_MAX_ZONES and zone not in _cache:
        victim = min(_cache.items(), key=lambda kv: kv[1]["fetched_at"])[0]
        _cache.pop(victim, None)
    index: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for ep in endpoints:
        sub, z = _split_name(ep.dnsName)
        if z != zone:
            continue
        key = (sub, ep.recordType.upper())
        entry = index.setdefault(key, {"targets": set(), "ttl": ep.recordTTL or DEFAULT_TTL})
        entry["targets"].update(_norm_fqdn(t) for t in ep.targets)
    _cache[zone] = {"fetched_at": time.time(), "records": endpoints, "index": index}
    _recalc_cache_gauges()

def _index_lookup(zone: str, sub: str, rectype: str) -> Dict[str, Any]:
    item = _cache.get(zone)
    if not item:
        return {"targets": set(), "ttl": DEFAULT_TTL}
    return item["index"].get((sub, rectype.upper()), {"targets": set(), "ttl": DEFAULT_TTL})

async def _fetch_zone_records(zone: str) -> List[Endpoint]:
    payload = {"domains": [{"dname": zone}]}
    resp = await reg_call("zone/get_resource_records", payload)
    endpoints: List[Endpoint] = []
    for d in resp.get("answer", {}).get("domains", []):
        if d.get("result") != "success":
            continue
        z = d["dname"].lower()
        soa_ttl = _ttl_to_seconds(d.get("soa", {}).get("ttl") or DEFAULT_TTL)
        for rr in d.get("rrs", []):
            rectype = rr.get("rectype", "").upper()
            if rectype not in SUPPORTED_TYPES:
                continue
            sub = rr.get("subname", "@")
            ttl = _ttl_to_seconds(rr.get("ttl") or soa_ttl)

            content = rr.get("content", "")
            if rectype == "MX":
                prio = rr.get("prio") or rr.get("priority")
                host = rr.get("mail_server") or rr.get("target") or (content.split()[-1] if content else "")
                if prio is not None and host:
                    content = f"{int(prio)} {host}"
            elif rectype == "SRV":
                prio = rr.get("priority") or 0
                weight = rr.get("weight") or 0
                port = rr.get("port") or 0
                target = rr.get("target") or (content.split()[-1] if content else "")
                if target:
                    content = f"{int(prio)} {int(weight)} {int(port)} {target}"
            elif rectype == "CAA":
                flags = rr.get("flags")
                tag = rr.get("tag")
                value = rr.get("value")
                if flags is not None and tag and value is not None:
                    content = f"{int(flags)} {tag} {value}"
            elif rectype == "HTTPS":
                prio = rr.get("priority") or 1
                target = rr.get("target") or "."
                val = rr.get("value") or ""
                content = f"{int(prio)} {target} {val}"

            endpoints.append(Endpoint(
                dnsName=_fqdn(sub, z),
                targets=[content] if content else [],
                recordTTL=ttl,
                recordType=rectype,
            ))
    return endpoints

async def _ensure_zone_cached(zone: str) -> None:
    if _cache_get_valid(zone) is not None:
        return
    endpoints = await _fetch_zone_records(zone)
    _cache_put_zone(zone, endpoints)

# ------------------ HTTP: health & metrics ------------------
@app.get("/healthz")
async def healthz():
    return {"ok": True, "zones_cached": list(_cache.keys())}

@app.get("/metrics")
async def metrics():
    data = generate_latest(REGISTRY)
    return Response(content=data, media_type=CONTENT_TYPE_LATEST)

# ------------------ HTTP: records (GET/POST) ------------------
@app.get("/records")
async def records():
    result: List[Endpoint] = []
    if not DOMAIN_FILTERS:
        return result
    for zone in DOMAIN_FILTERS:
        await _ensure_zone_cached(zone)
        item = _cache.get(zone)
        if item:
            result.extend(item["records"])
    return result

@app.post("/adjustendpoints")
async def adjust(endpoints: List[Endpoint]):
    seen: Set[Tuple[str, str, str]] = set()  # (dnsName, rectype, target)
    out: List[Endpoint] = []
    for e in endpoints:
        ttl = e.recordTTL or DEFAULT_TTL
        rt = e.recordType.upper()
        unique_targets: List[str] = []
        for tgt in e.targets:
            key = (_norm_fqdn(e.dnsName), rt, _norm_fqdn(tgt))
            if key not in seen:
                seen.add(key)
                unique_targets.append(tgt)
        if unique_targets:
            out.append(Endpoint(
                dnsName=_norm_fqdn(e.dnsName),
                targets=unique_targets,
                recordTTL=ttl,
                recordType=rt
            ))
    return out

@app.post("/records")
async def apply(changes: Changes, response: Response):
    desired_additions: Dict[Tuple[str, str, str], Set[str]] = {}
    desired_removals: Dict[Tuple[str, str, str], Set[str]] = {}

    def add_to(dct: Dict[Tuple[str, str, str], Set[str]], ep: Endpoint):
        sub, zone = _split_name(ep.dnsName)
        key = (zone, sub, ep.recordType.upper())
        bucket = dct.setdefault(key, set())
        for t in ep.targets:
            bucket.add(_norm_fqdn(t))

    for ep in changes.Create:
        add_to(desired_additions, ep)
    for ep in changes.UpdateNew:
        add_to(desired_additions, ep)
    for ep in changes.UpdateOld:
        add_to(desired_removals, ep)
    for ep in changes.Delete:
        add_to(desired_removals, ep)

    touched_zones = {k[0] for k in list(desired_additions.keys()) + list(desired_removals.keys())}
    for zone in touched_zones:
        await _ensure_zone_cached(zone)

    add_actions: List[Dict[str, Any]] = []
    del_actions: List[Dict[str, Any]] = []

    def queue_add(zone: str, sub: str, rectype: str, targets: Set[str], ttl: int):
        for tgt in sorted(targets):
            if rectype == "A":
                add_actions.append({"action": "add_alias", "dname": zone, "subdomain": sub, "ipaddr": tgt, "ttl": ttl})
            elif rectype == "AAAA":
                add_actions.append({"action": "add_aaaa", "dname": zone, "subdomain": sub, "ipaddr": tgt, "ttl": ttl})
            elif rectype == "CNAME":
                add_actions.append({"action": "add_cname", "dname": zone, "subdomain": sub, "canonical_name": tgt, "ttl": ttl})
            elif rectype == "TXT":
                add_actions.append({"action": "add_txt", "dname": zone, "subdomain": sub, "text": tgt, "ttl": ttl})
            elif rectype == "NS":
                add_actions.append({"action": "add_ns", "dname": zone, "subdomain": sub, "dns_server": tgt, "ttl": ttl})
            elif rectype == "MX":
                prio, host = parse_mx(tgt)
                add_actions.append({"action": "add_mx", "dname": zone, "subdomain": sub, "mail_server": host, "priority": prio, "ttl": ttl})
            elif rectype == "SRV":
                prio, weight, port, target = parse_srv(tgt)
                # Для REG.RU SRV принимает "service" как owner-name части (_sip._udp[.sub])
                service = sub  # здесь sub обычно уже "_sip._udp" или "_sip._udp.sub"
                add_actions.append({"action": "add_srv", "dname": zone, "service": service,
                                    "priority": prio, "weight": weight, "port": port, "target": target, "ttl": ttl})
            elif rectype == "CAA":
                flags, tag, value = parse_caa(tgt)
                add_actions.append({"action": "add_caa", "dname": zone, "subdomain": sub, "flags": flags, "tag": tag, "value": value, "ttl": ttl})
            elif rectype == "HTTPS":
                prio, target, params = parse_https(tgt)
                add_actions.append({"action": "add_https", "dname": zone, "subdomain": sub, "priority": prio, "target": target, "value": params, "ttl": ttl})
            else:
                add_actions.append({"action": "add_custom", "dname": zone, "subdomain": sub, "record_type": rectype, "content": tgt, "ttl": ttl})
            APPLY_ADDS.labels(zone, rectype).inc()

    def queue_del(zone: str, sub: str, rectype: str, targets: Optional[Set[str]]):
        if targets:
            for tgt in sorted(targets):
                del_actions.append({
                    "action": "remove",
                    "dname": zone,
                    "subdomain": sub,
                    "record_type": rectype,
                    "content": tgt,
                })
                APPLY_DELS.labels(zone, rectype).inc()
        else:
            del_actions.append({
                "action": "remove",
                "dname": zone,
                "subdomain": sub,
                "record_type": rectype,
            })
            APPLY_DELS.labels(zone, rectype).inc()

    keys = set(desired_additions.keys()) | set(desired_removals.keys())
    for (zone, sub, rectype) in keys:
        cur = _index_lookup(zone, sub, rectype)
        current_targets: Set[str] = set(cur.get("targets", set()))
        ttl = cur.get("ttl", DEFAULT_TTL)

        to_add = desired_additions.get((zone, sub, rectype), set()) - current_targets
        to_del_specific = desired_removals.get((zone, sub, rectype), set()) & current_targets

        remove_all = (
            (zone, sub, rectype) in desired_removals and
            len(desired_removals[(zone, sub, rectype)]) == 0 and
            not desired_additions.get((zone, sub, rectype))
        )

        if to_add:
            queue_add(zone, sub, rectype, to_add, ttl)
        if remove_all:
            queue_del(zone, sub, rectype, None)
        elif to_del_specific:
            queue_del(zone, sub, rectype, to_del_specific)

    if not add_actions and not del_actions:
        APPLY_NOOP.inc()
        return {"status": "noop"}

    action_list = add_actions + del_actions
    try:
        await reg_call("zone/update_records", {"action_list": action_list})
        _patch_cache_after_apply(add_actions, del_actions)
    except httpx.HTTPStatusError:
        await _fallback_apply(add_actions, del_actions)
        _patch_cache_after_apply(add_actions, del_actions)

    return {"status": "ok", "added": len(add_actions), "removed": len(del_actions)}

def _patch_cache_after_apply(add_actions: List[Dict[str, Any]], del_actions: List[Dict[str, Any]]):
    affected: Set[str] = {a["dname"] for a in add_actions + del_actions}
    for zone in affected:
        _cache.pop(zone, None)
    _recalc_cache_gauges()

async def _fallback_apply(add_actions: List[Dict[str, Any]], del_actions: List[Dict[str, Any]]):
    # Deletes first
    for act in del_actions:
        payload = {
            "domains": [{"dname": act["dname"]}],
            "subdomain": act["subdomain"],
            "record_type": act["record_type"],
        }
        if "content" in act:
            payload["content"] = act["content"]
        await reg_call("zone/remove_record", payload)

    # Adds
    for act in add_actions:
        rt = act.get("record_type") or act["action"].replace("add_", "").upper()
        dname = act["dname"]
        sub = act.get("subdomain")

        method = {
            "A": "zone/add_alias",
            "AAAA": "zone/add_aaaa",
            "CNAME": "zone/add_cname",
            "TXT": "zone/add_txt",
            "NS": "zone/add_ns",
            "MX": "zone/add_mx",
            "SRV": "zone/add_srv",
            "CAA": "zone/add_caa",
            "HTTPS": "zone/add_https",
        }.get(rt)
        if not method:
            continue

        if rt in ("A", "AAAA", "CNAME", "TXT", "NS"):
            key_map = {
                "A": "ipaddr",
                "AAAA": "ipaddr",
                "CNAME": "canonical_name",
                "TXT": "text",
                "NS": "dns_server",
            }
            payload = {
                "domains": [{"dname": dname}],
                "subdomain": sub,
                key_map[rt]: act.get("ipaddr") or act.get("canonical_name") or act.get("text") or act.get("dns_server") or act.get("content"),
                "ttl": act.get("ttl", DEFAULT_TTL),
            }
        elif rt == "MX":
            payload = {
                "domains": [{"dname": dname}],
                "subdomain": sub,
                "mail_server": act.get("mail_server"),
                "priority": act.get("priority", 10),
                "ttl": act.get("ttl", DEFAULT_TTL),
            }
        elif rt == "SRV":
            payload = {
                "domains": [{"dname": dname}],
                "service": act.get("service") or sub,  # e.g. "_sip._udp" or "_sip._udp.sub"
                "priority": act.get("priority", 0),
                "weight": act.get("weight", 0),
                "port": act.get("port", 0),
                "target": act.get("target"),
                "ttl": act.get("ttl", DEFAULT_TTL),
            }
        elif rt == "CAA":
            payload = {
                "domains": [{"dname": dname}],
                "subdomain": sub,
                "flags": act.get("flags", 0),
                "tag": act.get("tag", "issue"),
                "value": act.get("value", ""),
                "ttl": act.get("ttl", DEFAULT_TTL),
            }
        elif rt == "HTTPS":
            payload = {
                "domains": [{"dname": dname}],
                "subdomain": sub,
                "priority": act.get("priority", 1),
                "target": act.get("target", "."),
                "value": act.get("value", ""),
                "ttl": act.get("ttl", DEFAULT_TTL),
            }
        else:
            continue

        await reg_call(method, payload)
