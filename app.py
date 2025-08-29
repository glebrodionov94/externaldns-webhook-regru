# app.py
import os
import re
import time
import json
from typing import Any, Dict, List, Optional, Set, Tuple

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
import logging

# ---------------- Logging ----------------
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("external-dns-regru-webhook")

# ---------------- Config ----------------
# ExternalDNS webhook media type (per spec)
MEDIA_TYPE = "application/external.dns.webhook+json;version=1"

# REG.RU API configuration
REG_API_URL = os.getenv("REGRU_API_URL", "https://api.reg.ru/api/regru2").rstrip("/")
REG_USERNAME = os.getenv("REGRU_USERNAME", "")
REG_PASSWORD = os.getenv("REGRU_PASSWORD", "")
REGRU_TIMEOUT = float(os.getenv("REGRU_TIMEOUT", "10"))
REGRU_RETRIES = int(os.getenv("REGRU_RETRIES", "1"))
REGRU_VERIFY_SSL = os.getenv("REGRU_VERIFY_SSL", "true").lower() not in {"0", "false", "no"}

# ExternalDNS domain filters we expose in negotiate endpoint
DOMAIN_FILTERS = [z.strip().lower() for z in os.getenv("DOMAIN_FILTERS", "").split(",") if z.strip()]

# Cache settings
CACHE_TTL_SECONDS = int(os.getenv("CACHE_TTL_SECONDS", "60"))
CACHE_MAX_ZONES = int(os.getenv("CACHE_MAX_ZONES", "100"))
DEFAULT_TTL = int(os.getenv("DEFAULT_TTL", "300"))

# Record types we handle (REG.RU поддерживает эти типы; HTTPS также есть)
SUPPORTED_TYPES = {"A", "AAAA", "CNAME", "TXT", "MX", "SRV", "CAA", "NS", "HTTPS"}

# ---------------- Models (per webhook.yaml) ----------------
# См. webhook API: endpoints с полями dnsName, recordType, recordTTL, targets
# и Changes объект с списками Create/UpdateNew/UpdateOld/Delete. :contentReference[oaicite:1]{index=1}
class Endpoint(BaseModel):
    dnsName: str
    recordType: str
    targets: List[str] = Field(default_factory=list)
    recordTTL: Optional[int] = None

class Changes(BaseModel):
    Create: List[Endpoint] = Field(default_factory=list)
    UpdateNew: List[Endpoint] = Field(default_factory=list)
    UpdateOld: List[Endpoint] = Field(default_factory=list)
    Delete: List[Endpoint] = Field(default_factory=list)

# ---------------- FastAPI app ----------------
app = FastAPI()

def j(payload) -> JSONResponse:
    return JSONResponse(content=payload, media_type=MEDIA_TYPE)

# ---------------- Utils ----------------
def _norm_fqdn(s: str) -> str:
    return s.rstrip(".").lower()

# external-dns/idna в Go не принимает '*' и '_' в метках -> пропускаем такие записи
_IDNA_BAD = re.compile(r"[^\w\.\-]", re.ASCII)
def _valid_dns_for_externaldns(name: str) -> bool:
    n = _norm_fqdn(name)
    if not n:
        return False
    if "*" in n:
        return False
    if "_" in n:
        return False
    if _IDNA_BAD.search(n.replace("_", "")):
        return False
    return True

def _split_name(name: str) -> Tuple[str, str]:
    """Разбить FQDN на (sub, zone) с учётом DOMAIN_FILTERS; иначе последний 2-октетный суффикс."""
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

# ---- parsers for mixed-content targets (MX/SRV/CAA/HTTPS) ----
def parse_mx(s: str) -> Tuple[int, str]:
    parts = s.split()
    if len(parts) < 2:
        raise ValueError("MX must be 'priority host'")
    return int(parts[0]), _norm_fqdn(parts[1])

def parse_srv(s: str) -> Tuple[int, int, int, str]:
    parts = s.split()
    if len(parts) < 4:
        raise ValueError("SRV must be 'priority weight port target'")
    return int(parts[0]), int(parts[1]), int(parts[2]), _norm_fqdn(parts[3])

def parse_caa(s: str) -> Tuple[int, str, str]:
    parts = s.split(maxsplit=2)
    if len(parts) < 3:
        raise ValueError("CAA must be 'flags tag value'")
    return int(parts[0]), parts[1].lower(), parts[2]

def parse_https(s: str) -> Tuple[int, str, str]:
    parts = s.split(maxsplit=2)
    if len(parts) < 3:
        raise ValueError("HTTPS must be 'priority target params'")
    return int(parts[0]), parts[1], parts[2]

# ---------------- REG.RU API helpers (input_data style) ----------------
def _make_input_data(extra: Dict[str, Any]) -> str:
    data = {
        "username": REG_USERNAME,
        "password": REG_PASSWORD,
        "output_content_type": "json",
    }
    data.update(extra or {})
    return json.dumps(data, ensure_ascii=False)

async def _reg_call(path: str, extra: Dict[str, Any]) -> Dict[str, Any]:
    if not REG_USERNAME or not REG_PASSWORD:
        raise RuntimeError("REGRU_USERNAME/REGRU_PASSWORD are required")

    url = f"{REG_API_URL}/{path.lstrip('/')}"
    form = {
        "username": REG_USERNAME,
        "password": REG_PASSWORD,
        "input_format": "json",
        "input_data": _make_input_data(extra),
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    last_err = None
    for attempt in range(REGRU_RETRIES + 1):
        try:
            async with httpx.AsyncClient(verify=REGRU_VERIFY_SSL, timeout=REGRU_TIMEOUT) as client:
                r = await client.post(url, data=form, headers=headers)
                if logger.isEnabledFor(logging.DEBUG):
                    logger.debug("REG.RU RAW RESPONSE [%s] %s", path, r.text)
                r.raise_for_status()
                return r.json()
        except Exception as e:
            last_err = e
            if attempt < REGRU_RETRIES:
                time.sleep(0.5 * (attempt + 1))
            else:
                logger.error("REG.RU API ERROR %s: %s", path, e, exc_info=True)
                raise

# ---------------- Cache (very small LRU-ish per zone) ----------------
# _cache[zone] = {fetched_at, records: List[Endpoint], index: {(sub, type): {targets:Set[str], ttl:int}}}
_cache: Dict[str, Dict[str, Any]] = {}

def _cache_get(zone: str) -> Optional[Dict[str, Any]]:
    item = _cache.get(zone)
    if not item:
        return None
    if time.time() - item["fetched_at"] > CACHE_TTL_SECONDS:
        return None
    return item

def _cache_put(zone: str, endpoints: List[Endpoint]):
    if len(_cache) >= CACHE_MAX_ZONES and zone not in _cache:
        victim = min(_cache.items(), key=lambda kv: kv[1]["fetched_at"])[0]
        _cache.pop(victim, None)
    index: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for ep in endpoints:
        sub, z = _split_name(ep.dnsName)
        if z != zone:
            continue
        key = (sub, ep.recordType.upper())
        e = index.setdefault(key, {"targets": set(), "ttl": ep.recordTTL or DEFAULT_TTL})
        e["targets"].update(_norm_fqdn(t) for t in ep.targets)
    _cache[zone] = {"fetched_at": time.time(), "records": endpoints, "index": index}

def _index(zone: str, sub: str, rectype: str) -> Dict[str, Any]:
    item = _cache.get(zone)
    if not item:
        return {"targets": set(), "ttl": DEFAULT_TTL}
    return item["index"].get((sub, rectype.upper()), {"targets": set(), "ttl": DEFAULT_TTL})

async def _ensure_zone_cached(zone: str) -> None:
    if _cache_get(zone) is not None:
        return
    endpoints: List[Endpoint] = []
    resp = await _reg_call("zone/get_resource_records", {"domains": [{"dname": zone}]})
    for d in resp.get("answer", {}).get("domains", []):
        if d.get("result") != "success":
            continue
        z = d["dname"].lower()
        soa_ttl = _ttl_to_seconds(d.get("soa", {}).get("ttl") or DEFAULT_TTL)
        for rr in d.get("rrs", []):
            rtype = rr.get("rectype", "").upper()
            if rtype not in SUPPORTED_TYPES:
                continue
            sub = rr.get("subname", "@")
            ttl = _ttl_to_seconds(rr.get("ttl") or soa_ttl)

            content = rr.get("content", "")
            if rtype == "MX":
                prio = rr.get("prio") or rr.get("priority")
                host = rr.get("mail_server") or rr.get("target") or (content.split()[-1] if content else "")
                if prio is not None and host:
                    content = f"{int(prio)} {host}"
            elif rtype == "SRV":
                prio = rr.get("priority") or 0
                weight = rr.get("weight") or 0
                port = rr.get("port") or 0
                target = rr.get("target") or (content.split()[-1] if content else "")
                if target:
                    content = f"{int(prio)} {int(weight)} {int(port)} {target}"
            elif rtype == "CAA":
                flags = rr.get("flags")
                tag = rr.get("tag")
                value = rr.get("value")
                if flags is not None and tag and value is not None:
                    content = f"{int(flags)} {tag} {value}"
            elif rtype == "HTTPS":
                prio = rr.get("priority") or 1
                target = rr.get("target") or "."
                val = rr.get("value") or ""
                content = f"{int(prio)} {target} {val}"

            ep = Endpoint(
                dnsName=_fqdn(sub, z),
                recordType=rtype,
                recordTTL=ttl,
                targets=[content] if content else [],
            )
            if _valid_dns_for_externaldns(ep.dnsName):
                endpoints.append(ep)
            else:
                logger.debug("Skip invalid dnsName for ExternalDNS: %s (%s)", ep.dnsName, ep.recordType)
    _cache_put(zone, endpoints)

# ---------------- HTTP: negotiate / health / metrics ----------------
@app.get("/")
async def negotiate():
    # Важно: возвращаем список фильтров (см. tutorial) :contentReference[oaicite:2]{index=2}
    return j({"filters": DOMAIN_FILTERS})

@app.get("/healthz")
async def healthz():
    return {"ok": True, "zones_cached": list(_cache.keys())}

# ---------------- HTTP: /records (GET -> список эндпоинтов) ----------------
@app.get("/records")
async def records():
    result: List[Endpoint] = []
    # ExternalDNS ожидает здесь список endpoint-объектов, возможно пустой.
    for zone in DOMAIN_FILTERS or []:
        await _ensure_zone_cached(zone)
        item = _cache.get(zone)
        if item:
            result.extend(item["records"])
    return j([e.model_dump() for e in result])

# ---------------- HTTP: /adjustendpoints (опциональная нормализация) ----------------
@app.post("/adjustendpoints")
async def adjust(endpoints: List[Endpoint]):
    seen: Set[Tuple[str, str, str]] = set()
    out: List[Endpoint] = []
    for e in endpoints:
        if not _valid_dns_for_externaldns(e.dnsName):
            logger.debug("Adjust: drop invalid dnsName: %s", e.dnsName)
            continue
        rt = e.recordType.upper()
        ttl = e.recordTTL or DEFAULT_TTL
        uniq_targets: List[str] = []
        for tgt in e.targets:
            key = (_norm_fqdn(e.dnsName), rt, _norm_fqdn(tgt))
            if key not in seen:
                seen.add(key)
                uniq_targets.append(tgt)
        if uniq_targets:
            out.append(Endpoint(
                dnsName=_norm_fqdn(e.dnsName),
                recordType=rt,
                recordTTL=ttl,
                targets=uniq_targets,
            ))
    return j([e.model_dump() for e in out])

# ---------------- HTTP: /records (POST -> применить изменения) ----------------
@app.post("/records", status_code=204)
async def apply(changes: Changes):
    """
    По спецификации Webhook Provider успешный аплай должен вернуть 204 No Content.
    Никакого тела ответа не возвращаем. :contentReference[oaicite:3]{index=3}
    """
    desired_add: Dict[Tuple[str, str, str], Set[str]] = {}
    desired_del: Dict[Tuple[str, str, str], Set[str]] = {}

    def acc(dct: Dict[Tuple[str, str, str], Set[str]], ep: Endpoint):
        sub, zone = _split_name(ep.dnsName)
        key = (zone, sub, ep.recordType.upper())
        bucket = dct.setdefault(key, set())
        for t in ep.targets:
            bucket.add(_norm_fqdn(t))

    for ep in changes.Create:
        acc(desired_add, ep)
    for ep in changes.UpdateNew:
        acc(desired_add, ep)
    for ep in changes.UpdateOld:
        acc(desired_del, ep)
    for ep in changes.Delete:
        acc(desired_del, ep)

    touched = {k[0] for k in list(desired_add.keys()) + list(desired_del.keys())}
    for zone in touched:
        await _ensure_zone_cached(zone)

    add_actions: List[Dict[str, Any]] = []
    del_actions: List[Dict[str, Any]] = []

    def q_add(zone: str, sub: str, rt: str, targets: Set[str], ttl: int):
        for tgt in sorted(targets):
            if rt == "A":
                add_actions.append({"action": "zone/add_alias", "dname": zone, "subdomain": sub, "ipaddr": tgt, "ttl": ttl})
            elif rt == "AAAA":
                add_actions.append({"action": "zone/add_aaaa", "dname": zone, "subdomain": sub, "ipaddr": tgt, "ttl": ttl})
            elif rt == "CNAME":
                add_actions.append({"action": "zone/add_cname", "dname": zone, "subdomain": sub, "canonical_name": tgt, "ttl": ttl})
            elif rt == "TXT":
                add_actions.append({"action": "zone/add_txt", "dname": zone, "subdomain": sub, "text": tgt, "ttl": ttl})
            elif rt == "NS":
                add_actions.append({"action": "zone/add_ns", "dname": zone, "subdomain": sub, "dns_server": tgt, "ttl": ttl})
            elif rt == "MX":
                pr, host = parse_mx(tgt)
                add_actions.append({"action": "zone/add_mx", "dname": zone, "subdomain": sub, "mail_server": host, "priority": pr, "ttl": ttl})
            elif rt == "SRV":
                pr, w, port, target = parse_srv(tgt)
                # REG.RU требует "service" = owner-name для SRV; используем sub как есть
                add_actions.append({"action": "zone/add_srv", "dname": zone, "service": sub, "priority": pr, "weight": w, "port": port, "target": target, "ttl": ttl})
            elif rt == "CAA":
                flags, tag, value = parse_caa(tgt)
                add_actions.append({"action": "zone/add_caa", "dname": zone, "subdomain": sub, "flags": flags, "tag": tag, "value": value, "ttl": ttl})
            elif rt == "HTTPS":
                pr, target, params = parse_https(tgt)
                add_actions.append({"action": "zone/add_https", "dname": zone, "subdomain": sub, "priority": pr, "target": target, "value": params, "ttl": ttl})
            else:
                # fallback для экзотики
                add_actions.append({"action": "zone/add_txt", "dname": zone, "subdomain": sub, "text": f"UNSUPPORTED:{rt}:{tgt}", "ttl": ttl})

    def q_del(zone: str, sub: str, rt: str, targets: Optional[Set[str]]):
        # Удаление в REG.RU через zone/remove_record, важный параметр subname, а не subdomain. :contentReference[oaicite:4]{index=4}
        if targets:
            for tgt in sorted(targets):
                del_actions.append({"action": "zone/remove_record", "dname": zone, "record_type": rt, "subname": sub, "content": tgt})
        else:
            del_actions.append({"action": "zone/remove_record", "dname": zone, "record_type": rt, "subname": sub})

    # вычислить дельту с текущим кэшем
    keys = set(desired_add.keys()) | set(desired_del.keys())
    for (zone, sub, rt) in keys:
        cur = _index(zone, sub, rt)
        have: Set[str] = set(cur.get("targets", set()))
        ttl = cur.get("ttl", DEFAULT_TTL)

        to_add = desired_add.get((zone, sub, rt), set()) - have
        to_del_specific = desired_del.get((zone, sub, rt), set()) & have

        remove_all = (
            (zone, sub, rt) in desired_del and
            len(desired_del[(zone, sub, rt)]) == 0 and
            not desired_add.get((zone, sub, rt))
        )

        if to_add:
            q_add(zone, sub, rt, to_add, ttl)
        if remove_all:
            q_del(zone, sub, rt, None)
        elif to_del_specific:
            q_del(zone, sub, rt, to_del_specific)

    if not add_actions and not del_actions:
        # ничего менять -> 204
        return Response(status_code=204, media_type=MEDIA_TYPE)

    # Попытка «батчем» через гипотетический zone/update_records.
    # Если не поддерживается/ошибка логики — идём построчно.
    try:
        resp = await _reg_call("zone/update_records", {"action_list": add_actions + del_actions})
        if resp.get("result") != "success":
            raise RuntimeError(f"regru logical error: {resp}")
        # invalidate кэш для затронутых зон
        for act in add_actions + del_actions:
            _cache.pop(act["dname"], None)
    except Exception as e:
        logger.warning("Batch update failed or unsupported, fallback per-record: %s", e)
        # DELETEs сначала
        for act in del_actions:
            payload = {
                "domains": [{"dname": act["dname"]}],
                "record_type": act["record_type"],
                "subname": act["subname"],
            }
            if "content" in act:
                payload["content"] = act["content"]
            await _reg_call("zone/remove_record", payload)
        # ADDs
        for act in add_actions:
            path = act["action"]
            # нормализуем полезную нагрузку под конкретный метод
            if path in ("zone/add_alias", "zone/add_aaaa"):
                payload = {"domains": [{"dname": act["dname"]}], "subdomain": act["subdomain"], "ipaddr": act["ipaddr"], "ttl": act.get("ttl", DEFAULT_TTL)}
            elif path == "zone/add_cname":
                payload = {"domains": [{"dname": act["dname"]}], "subdomain": act["subdomain"], "canonical_name": act["canonical_name"], "ttl": act.get("ttl", DEFAULT_TTL)}
            elif path == "zone/add_txt":
                payload = {"domains": [{"dname": act["dname"]}], "subdomain": act["subdomain"], "text": act["text"], "ttl": act.get("ttl", DEFAULT_TTL)}
            elif path == "zone/add_ns":
                payload = {"domains": [{"dname": act["dname"]}], "subdomain": act["subdomain"], "dns_server": act["dns_server"], "ttl": act.get("ttl", DEFAULT_TTL)}
            elif path == "zone/add_mx":
                payload = {"domains": [{"dname": act["dname"]}], "subdomain": act["subdomain"], "mail_server": act["mail_server"], "priority": act["priority"], "ttl": act.get("ttl", DEFAULT_TTL)}
            elif path == "zone/add_srv":
                payload = {"domains": [{"dname": act["dname"]}], "service": act["service"], "priority": act["priority"], "weight": act["weight"], "port": act["port"], "target": act["target"], "ttl": act.get("ttl", DEFAULT_TTL)}
            elif path == "zone/add_caa":
                payload = {"domains": [{"dname": act["dname"]}], "subdomain": act["subdomain"], "flags": act["flags"], "tag": act["tag"], "value": act["value"], "ttl": act.get("ttl", DEFAULT_TTL)}
            elif path == "zone/add_https":
                payload = {"domains": [{"dname": act["dname"]}], "subdomain": act["subdomain"], "priority": act["priority"], "target": act["target"], "value": act["value"], "ttl": act.get("ttl", DEFAULT_TTL)}
            else:
                # unknown -> пропускаем
                continue
            await _reg_call(path, payload)
        # invalidate кэш
        for act in add_actions + del_actions:
            _cache.pop(act["dname"], None)

    # успешный путь -> 204 без тела
    return Response(status_code=204, media_type=MEDIA_TYPE)
