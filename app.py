# app.py
import asyncio
import json
import logging
import os
import re
import time
from collections import OrderedDict
from typing import Any, Dict, List, Optional, Set, Tuple

import httpx
from fastapi import FastAPI
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, ConfigDict, Field, model_validator
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request as StarletteRequest

# ---------------- Logging ----------------
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("external-dns-regru-webhook")

# ---------------- Config ----------------
MEDIA_TYPE = "application/external.dns.webhook+json;version=1"

REG_API_URL = os.getenv("REGRU_API_URL", "https://api.reg.ru/api/regru2").rstrip("/")
REG_USERNAME = os.getenv("REGRU_USERNAME", "")
REG_PASSWORD = os.getenv("REGRU_PASSWORD", "")
REGRU_TIMEOUT = float(os.getenv("REGRU_TIMEOUT", "10"))
REGRU_RETRIES = int(os.getenv("REGRU_RETRIES", "2"))
REGRU_RETRY_BASE_DELAY = float(os.getenv("REGRU_RETRY_BASE_DELAY", "0.5"))
REGRU_VERIFY_SSL = os.getenv("REGRU_VERIFY_SSL", "true").lower() not in {"0", "false", "no"}

DOMAIN_FILTERS = [z.strip().lower().rstrip(".") for z in os.getenv("DOMAIN_FILTERS", "").split(",") if z.strip()]

CACHE_TTL_SECONDS = int(os.getenv("CACHE_TTL_SECONDS", "60"))
CACHE_MAX_ZONES = int(os.getenv("CACHE_MAX_ZONES", "100"))
DEFAULT_TTL = int(os.getenv("DEFAULT_TTL", "300"))
LOG_BODY_MAX = int(os.getenv("LOG_BODY_MAX", "5000"))

# Типы, которые реально маппим на REG.RU
SUPPORTED_TYPES = {"A", "AAAA", "CNAME", "TXT", "MX", "SRV", "CAA", "NS", "HTTPS"}

# Если хотите жестко запретить работу без DOMAIN_FILTERS, включите эту проверку:
REQUIRE_DOMAIN_FILTERS = os.getenv("REQUIRE_DOMAIN_FILTERS", "true").lower() not in {"0", "false", "no"}

# ---------------- Exceptions ----------------
class RegruAPIError(Exception):
    pass


# ---------------- Models ----------------
class Endpoint(BaseModel):
    dnsName: str
    recordType: str
    targets: List[str] = Field(default_factory=list)
    recordTTL: Optional[int] = None


class Changes(BaseModel):
    """
    ExternalDNS historically расходится между OpenAPI spec (lower/camel case)
    и фактическим JSON от Go-структуры (Create/UpdateNew/UpdateOld/Delete).
    Принимаем оба варианта.
    """
    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    Create: List[Endpoint] = Field(default_factory=list)
    UpdateNew: List[Endpoint] = Field(default_factory=list)
    UpdateOld: List[Endpoint] = Field(default_factory=list)
    Delete: List[Endpoint] = Field(default_factory=list)

    @model_validator(mode="before")
    @classmethod
    def accept_both_casings(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data

        mapped = dict(data)

        aliases = {
            "create": "Create",
            "Create": "Create",
            "updateNew": "UpdateNew",
            "UpdateNew": "UpdateNew",
            "updatenew": "UpdateNew",
            "updateOld": "UpdateOld",
            "UpdateOld": "UpdateOld",
            "updateold": "UpdateOld",
            "delete": "Delete",
            "Delete": "Delete",
        }

        result: Dict[str, Any] = {}
        for k, v in mapped.items():
            nk = aliases.get(k, k)
            result[nk] = v
        return result


# ---------------- FastAPI app ----------------
app = FastAPI()


class RequestBodyLoggerMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: StarletteRequest, call_next):
        method = request.method
        path = request.url.path
        query = request.url.query
        client = getattr(request.client, "host", "-")
        ctype = request.headers.get("content-type", "-")
        accept = request.headers.get("accept", "-")

        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(
                "REQUEST %s %s%s from %s | content-type=%s accept=%s",
                method,
                path,
                f"?{query}" if query else "",
                client,
                ctype,
                accept,
            )

            try:
                body_bytes = await request.body()
                body_text = body_bytes.decode("utf-8", errors="replace")
                if len(body_text) > LOG_BODY_MAX:
                    logger.debug("REQUEST BODY (%d bytes, truncated): %s...", len(body_text), body_text[:LOG_BODY_MAX])
                else:
                    logger.debug("REQUEST BODY (%d bytes): %s", len(body_text), body_text)

                async def receive():
                    return {"type": "http.request", "body": body_bytes, "more_body": False}

                request._receive = receive  # noqa: SLF001
            except Exception as e:
                logger.debug("Failed to read request body: %s", e)

        start = time.time()
        response = await call_next(request)

        if logger.isEnabledFor(logging.DEBUG):
            dur_ms = (time.time() - start) * 1000.0
            logger.debug("RESPONSE %s %s -> %s (%.1f ms)", method, path, response.status_code, dur_ms)

        return response


app.add_middleware(RequestBodyLoggerMiddleware)


def j(payload: Any) -> JSONResponse:
    return JSONResponse(content=payload, media_type=MEDIA_TYPE)


# ---------------- Validation / normalization utils ----------------
_IDNA_BAD = re.compile(r"[^\w\.\-\*]", re.ASCII)


def _norm_fqdn(s: str) -> str:
    return s.strip().rstrip(".").lower()


def _ensure_trailing_dot(s: str) -> str:
    s = s.strip()
    return s if s.endswith(".") else s + "."


def _valid_dns_for_externaldns(name: str, record_type: str) -> bool:
    """
    ExternalDNS/IDNA historically плохо переваривает '*' и '_'.
    Но SRV owner-name с '_' нужен по RFC и нужен REG.RU через zone/add_srv.
    Поэтому '_' допускаем только для SRV.
    """
    n = _norm_fqdn(name)
    if not n:
        return False
    if "*" in n:
        return False
    if record_type.upper() != "SRV" and "_" in n:
        return False

    probe = n if record_type.upper() == "SRV" else n.replace("_", "")
    if _IDNA_BAD.search(probe):
        return False
    return True


def _split_name(name: str) -> Tuple[str, str]:
    """
    Разбивает fqdn -> (subdomain/service, zone).
    Надежно работает при заданных DOMAIN_FILTERS.
    Без DOMAIN_FILTERS fallback только по последним двум меткам.
    """
    name = _norm_fqdn(name)

    for z in sorted(DOMAIN_FILTERS, key=len, reverse=True):
        if name == z:
            return "@", z
        if name.endswith("." + z):
            sub = name[: -(len(z) + 1)]
            return sub or "@", z

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
        s = str(t).strip().lower()
        if s.endswith("d"):
            return int(float(s[:-1]) * 86400)
        if s.endswith("h"):
            return int(float(s[:-1]) * 3600)
        if s.endswith("m"):
            return int(float(s[:-1]) * 60)
        return int(float(s))
    except Exception:
        return DEFAULT_TTL


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


def _normalize_target(record_type: str, target: str) -> str:
    rt = record_type.upper()
    t = target.strip()

    if rt in {"A", "AAAA"}:
        return t

    if rt in {"CNAME", "NS"}:
        return _norm_fqdn(t)

    if rt == "TXT":
        if len(t) >= 2 and t.startswith('"') and t.endswith('"'):
            t = t[1:-1]
        return t

    if rt == "MX":
        prio, host = parse_mx(t)
        return f"{prio} {_norm_fqdn(host)}"

    if rt == "SRV":
        prio, weight, port, host = parse_srv(t)
        return f"{prio} {weight} {port} {_norm_fqdn(host)}"

    if rt == "CAA":
        flags, tag, value = parse_caa(t)
        return f"{flags} {tag} {value}"

    if rt == "HTTPS":
        prio, host, params = parse_https(t)
        host = "." if host == "." else _norm_fqdn(host)
        return f"{prio} {host} {params}"

    return t


def _to_regru_delete_content(record_type: str, normalized_target: str) -> str:
    """
    Для remove_record стараемся отправлять content в том же формате,
    который REG.RU обычно показывает/ожидает.
    """
    rt = record_type.upper()

    if rt == "TXT":
        return f'"{normalized_target}"' if " " in normalized_target else normalized_target

    if rt == "CNAME":
        return _ensure_trailing_dot(normalized_target)

    if rt == "NS":
        return normalized_target

    if rt in {"A", "AAAA"}:
        return normalized_target

    if rt == "MX":
        prio, host = parse_mx(normalized_target)
        return f"{prio} {host}"

    if rt == "SRV":
        prio, weight, port, host = parse_srv(normalized_target)
        return f"{prio} {weight} {port} {host}"

    if rt == "CAA":
        return normalized_target

    if rt == "HTTPS":
        return normalized_target

    return normalized_target


# ---------------- REG.RU API helpers ----------------
def _make_input_data(extra: Dict[str, Any]) -> str:
    data = {
        "username": REG_USERNAME,
        "password": REG_PASSWORD,
        "output_content_type": "json",
    }
    data.update(extra or {})
    return json.dumps(data, ensure_ascii=False)


def _sanitize_form_for_log(form: Dict[str, Any]) -> Dict[str, Any]:
    safe = dict(form)
    if "password" in safe:
        safe["password"] = "***"
    if "input_data" in safe:
        safe["input_data"] = "<redacted>"
    return safe


async def _reg_call(path: str, extra: Dict[str, Any]) -> Dict[str, Any]:
    if not REG_USERNAME or not REG_PASSWORD:
        raise RuntimeError("REGRU_USERNAME and REGRU_PASSWORD are required")

    url = f"{REG_API_URL}/{path.lstrip('/')}"
    form = {
        "username": REG_USERNAME,
        "password": REG_PASSWORD,
        "input_format": "json",
        "input_data": _make_input_data(extra),
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    last_err: Optional[Exception] = None
    for attempt in range(REGRU_RETRIES + 1):
        try:
            async with httpx.AsyncClient(verify=REGRU_VERIFY_SSL, timeout=REGRU_TIMEOUT) as client:
                if logger.isEnabledFor(logging.DEBUG):
                    logger.debug("REG.RU Request: %s - %s", url, _sanitize_form_for_log(form))

                r = await client.post(url, data=form, headers=headers)

                if logger.isEnabledFor(logging.DEBUG):
                    logger.debug("REG.RU Response: %s - %s", r.status_code, r.text)

                if r.status_code != 200:
                    raise RegruAPIError(f"HTTP error {r.status_code}: {r.text}")

                try:
                    data = r.json()
                except Exception as e:
                    raise RegruAPIError(f"Invalid JSON response from REG.RU: {e}; body={r.text}") from e

                if data.get("result") != "success":
                    raise RegruAPIError(f"API error: {data}")

                return data

        except Exception as e:
            last_err = e
            logger.warning(
                "REG.RU API call failed path=%s attempt=%d/%d error=%s",
                path,
                attempt + 1,
                REGRU_RETRIES + 1,
                e,
            )
            if attempt >= REGRU_RETRIES:
                raise
            await asyncio.sleep(REGRU_RETRY_BASE_DELAY * (attempt + 1))

    raise last_err or RegruAPIError("Unknown REG.RU call failure")


# ---------------- Cache ----------------
# _cache[zone] = {
#   fetched_at: float,
#   records: List[Endpoint],
#   index: {
#      (sub, type): {
#         "targets": Set[str],
#         "ttl": int,
#      }
#   }
# }
_cache: "OrderedDict[str, Dict[str, Any]]" = OrderedDict()


def _cache_get(zone: str) -> Optional[Dict[str, Any]]:
    item = _cache.get(zone)
    if not item:
        return None
    if time.time() - item["fetched_at"] > CACHE_TTL_SECONDS:
        _cache.pop(zone, None)
        return None
    _cache.move_to_end(zone)
    return item


def _cache_put(zone: str, endpoints: List[Endpoint]) -> None:
    if zone in _cache:
        _cache.pop(zone, None)

    index: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for ep in endpoints:
        sub, z = _split_name(ep.dnsName)
        if z != zone:
            continue
        key = (sub, ep.recordType.upper())
        item = index.setdefault(key, {"targets": set(), "ttl": ep.recordTTL or DEFAULT_TTL})
        for t in ep.targets:
            item["targets"].add(_normalize_target(ep.recordType, t))

    _cache[zone] = {
        "fetched_at": time.time(),
        "records": endpoints,
        "index": index,
    }

    while len(_cache) > CACHE_MAX_ZONES:
        _cache.popitem(last=False)


def _cache_invalidate(zone: str) -> None:
    _cache.pop(zone, None)


def _index(zone: str, sub: str, rectype: str) -> Dict[str, Any]:
    item = _cache_get(zone)
    if not item:
        return {"targets": set(), "ttl": DEFAULT_TTL}
    return item["index"].get((sub, rectype.upper()), {"targets": set(), "ttl": DEFAULT_TTL})


async def _ensure_zone_cached(zone: str) -> None:
    if _cache_get(zone) is not None:
        return

    resp = await _reg_call("zone/get_resource_records", {"domains": [{"dname": zone}]})
    endpoints: List[Endpoint] = []

    for d in resp.get("answer", {}).get("domains", []):
        if d.get("result") != "success":
            continue

        z = _norm_fqdn(d.get("dname", zone))
        soa_ttl = _ttl_to_seconds(d.get("soa", {}).get("ttl") or DEFAULT_TTL)

        for rr in d.get("rrs", []):
            rtype = str(rr.get("rectype", "")).upper()
            if rtype not in SUPPORTED_TYPES:
                continue

            sub = rr.get("subname") or rr.get("subdomain") or "@"
            ttl = _ttl_to_seconds(rr.get("ttl") or soa_ttl)

            content = str(rr.get("content", "") or "").strip()

            if rtype == "TXT":
                if len(content) >= 2 and content.startswith('"') and content.endswith('"'):
                    content = content[1:-1]

            elif rtype == "MX":
                prio = rr.get("prio") or rr.get("priority")
                host = rr.get("mail_server") or rr.get("target")
                if not host and content:
                    parts = content.split()
                    host = parts[-1] if parts else ""
                if prio is not None and host:
                    content = f"{int(prio)} {_norm_fqdn(str(host))}"

            elif rtype == "SRV":
                prio = rr.get("priority") or 0
                weight = rr.get("weight") or 0
                port = rr.get("port") or 0
                target = rr.get("target")
                if not target and content:
                    parts = content.split()
                    target = parts[-1] if parts else ""
                if target:
                    content = f"{int(prio)} {int(weight)} {int(port)} {_norm_fqdn(str(target))}"

            elif rtype == "CAA":
                flags = rr.get("flags")
                tag = rr.get("tag")
                value = rr.get("value")
                if flags is not None and tag and value is not None:
                    content = f"{int(flags)} {str(tag).lower()} {value}"

            elif rtype == "HTTPS":
                prio = rr.get("priority") or 1
                target = rr.get("target") or "."
                value = rr.get("value") or ""
                target_s = "." if str(target).strip() == "." else _norm_fqdn(str(target))
                content = f"{int(prio)} {target_s} {value}".strip()

            elif rtype == "CNAME":
                content = _norm_fqdn(content)

            elif rtype == "NS":
                content = _norm_fqdn(content)

            ep = Endpoint(
                dnsName=_fqdn(sub, z),
                recordType=rtype,
                recordTTL=ttl,
                targets=[content] if content else [],
            )

            if _valid_dns_for_externaldns(ep.dnsName, ep.recordType):
                endpoints.append(ep)
            else:
                logger.debug("Skip invalid dnsName for ExternalDNS: %s (%s)", ep.dnsName, ep.recordType)

    _cache_put(zone, endpoints)


# ---------------- Health / negotiation ----------------
@app.on_event("startup")
async def _startup() -> None:
    if REQUIRE_DOMAIN_FILTERS and not DOMAIN_FILTERS:
        raise RuntimeError("DOMAIN_FILTERS must be set for reliable zone mapping")
    if not REG_USERNAME or not REG_PASSWORD:
        logger.warning("REGRU_USERNAME / REGRU_PASSWORD are not set")


@app.get("/")
async def negotiate():
    return j({"filters": DOMAIN_FILTERS})


@app.get("/healthz")
async def healthz():
    return {"ok": True, "zones_cached": list(_cache.keys())}


# ---------------- /records GET ----------------
@app.get("/records")
async def records():
    result: List[Endpoint] = []
    for zone in DOMAIN_FILTERS:
        await _ensure_zone_cached(zone)
        item = _cache_get(zone)
        if item:
            result.extend(item["records"])
    return j([e.model_dump() for e in result])


# ---------------- /adjustendpoints POST ----------------
@app.post("/adjustendpoints")
async def adjust(endpoints: List[Endpoint]):
    seen: Set[Tuple[str, str, str]] = set()
    out: List[Endpoint] = []

    for e in endpoints:
        rt = e.recordType.upper()

        if rt not in SUPPORTED_TYPES:
            logger.debug("Adjust: drop unsupported type %s for %s", rt, e.dnsName)
            continue

        if not _valid_dns_for_externaldns(e.dnsName, rt):
            logger.debug("Adjust: drop invalid dnsName: %s (%s)", e.dnsName, rt)
            continue

        ttl = e.recordTTL or DEFAULT_TTL
        uniq_targets: List[str] = []

        for tgt in e.targets:
            try:
                nt = _normalize_target(rt, tgt)
            except Exception as ex:
                logger.warning("Adjust: drop invalid target %r for %s %s: %s", tgt, e.dnsName, rt, ex)
                continue

            key = (_norm_fqdn(e.dnsName), rt, nt)
            if key not in seen:
                seen.add(key)
                uniq_targets.append(nt)

        if uniq_targets:
            out.append(
                Endpoint(
                    dnsName=_norm_fqdn(e.dnsName),
                    recordType=rt,
                    recordTTL=ttl,
                    targets=uniq_targets,
                )
            )

    return j([e.model_dump() for e in out])


# ---------------- Apply helpers ----------------
def _make_add_action(zone: str, sub: str, rt: str, target: str, ttl: int) -> Dict[str, Any]:
    if rt == "A":
        return {"action": "add_alias", "subdomain": sub, "ipaddr": target, "ttl": ttl}

    if rt == "AAAA":
        return {"action": "add_aaaa", "subdomain": sub, "ipaddr": target, "ttl": ttl}

    if rt == "CNAME":
        return {
            "action": "add_cname",
            "subdomain": sub,
            "canonical_name": _ensure_trailing_dot(target),
            "ttl": ttl,
        }

    if rt == "TXT":
        text = f'"{target}"' if " " in target else target
        return {"action": "add_txt", "subdomain": sub, "text": text, "ttl": ttl}

    if rt == "NS":
        return {"action": "add_ns", "subdomain": sub, "dns_server": target, "ttl": ttl}

    if rt == "MX":
        prio, host = parse_mx(target)
        return {"action": "add_mx", "subdomain": sub, "mail_server": host, "priority": prio, "ttl": ttl}

    if rt == "SRV":
        prio, weight, port, host = parse_srv(target)
        # REG.RU ожидает service, например "_sip._udp"
        return {
            "action": "add_srv",
            "service": sub,
            "priority": prio,
            "weight": weight,
            "port": port,
            "target": host,
            "ttl": ttl,
        }

    if rt == "CAA":
        flags, tag, value = parse_caa(target)
        return {
            "action": "add_caa",
            "subdomain": sub,
            "flags": flags,
            "tag": tag,
            "value": value,
            "ttl": ttl,
        }

    if rt == "HTTPS":
        prio, host, params = parse_https(target)
        return {
            "action": "add_https",
            "subdomain": sub,
            "priority": prio,
            "target": host,
            "value": params,
            "ttl": ttl,
        }

    raise ValueError(f"Unsupported record type: {rt}")


async def _apply_single_delete(zone: str, sub: str, rt: str, content: Optional[str]) -> None:
    payload: Dict[str, Any] = {
        "domains": [{"dname": zone}],
        "subdomain": sub,
        "record_type": rt,
    }
    if content is not None:
        payload["content"] = content
    await _reg_call("zone/remove_record", payload)


async def _apply_single_add(zone: str, action: Dict[str, Any]) -> None:
    path = f"zone/{action['action']}"
    payload: Dict[str, Any] = {"domains": [{"dname": zone}]}

    for k, v in action.items():
        if k == "action":
            continue
        payload[k] = v

    await _reg_call(path, payload)


# ---------------- /records POST ----------------
@app.post("/records", status_code=204)
async def apply(changes: Changes):
    """
    Успешный apply для ExternalDNS должен отвечать 20x.
    Держим 204 No Content.
    """
    desired_add: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
    desired_del: Dict[Tuple[str, str, str], Set[str]] = {}

    def acc_add(ep: Endpoint) -> None:
        rt = ep.recordType.upper()
        if rt not in SUPPORTED_TYPES:
            return

        sub, zone = _split_name(ep.dnsName)
        key = (zone, sub, rt)
        item = desired_add.setdefault(
            key,
            {
                "targets": set(),
                "ttl": ep.recordTTL or DEFAULT_TTL,
            },
        )

        # Если в одном батче TTL у одного ключа разный, берём TTL последнего desired endpoint.
        item["ttl"] = ep.recordTTL or item["ttl"] or DEFAULT_TTL

        for t in ep.targets:
            item["targets"].add(_normalize_target(rt, t))

    def acc_del(ep: Endpoint) -> None:
        rt = ep.recordType.upper()
        if rt not in SUPPORTED_TYPES:
            return

        sub, zone = _split_name(ep.dnsName)
        key = (zone, sub, rt)
        bucket = desired_del.setdefault(key, set())

        for t in ep.targets:
            bucket.add(_normalize_target(rt, t))

    for ep in changes.Create:
        acc_add(ep)

    for ep in changes.UpdateNew:
        acc_add(ep)

    for ep in changes.UpdateOld:
        acc_del(ep)

    for ep in changes.Delete:
        acc_del(ep)

    touched_zones = {k[0] for k in set(desired_add.keys()) | set(desired_del.keys())}
    for zone in touched_zones:
        await _ensure_zone_cached(zone)

    add_actions_by_zone: Dict[str, List[Dict[str, Any]]] = {}
    del_actions_by_zone: Dict[str, List[Dict[str, Any]]] = {}

    keys = set(desired_add.keys()) | set(desired_del.keys())
    for zone, sub, rt in keys:
        cur = _index(zone, sub, rt)
        have: Set[str] = set(cur.get("targets", set()))

        want_item = desired_add.get((zone, sub, rt))
        want_targets: Set[str] = set(want_item["targets"]) if want_item else set()
        want_ttl: int = int(want_item["ttl"]) if want_item else int(cur.get("ttl", DEFAULT_TTL))

        del_targets = desired_del.get((zone, sub, rt), set())

        # Full remove, если запись есть в Delete/UpdateOld с пустым targets и нет desired add.
        remove_all = ((zone, sub, rt) in desired_del) and len(del_targets) == 0 and not want_targets

        # Для update сценария ExternalDNS обычно шлёт UpdateOld + UpdateNew.
        # Делаем дельту по normalized targets.
        to_add = want_targets - have
        to_del_specific = del_targets & have

        if remove_all:
            del_actions_by_zone.setdefault(zone, []).append(
                {
                    "record_type": rt,
                    "subdomain": sub,
                    "content": None,
                }
            )
            continue

        for tgt in sorted(to_del_specific):
            del_actions_by_zone.setdefault(zone, []).append(
                {
                    "record_type": rt,
                    "subdomain": sub,
                    "content": _to_regru_delete_content(rt, tgt),
                }
            )

        for tgt in sorted(to_add):
            add_actions_by_zone.setdefault(zone, []).append(_make_add_action(zone, sub, rt, tgt, want_ttl))

    if not add_actions_by_zone and not del_actions_by_zone:
        return Response(status_code=204, media_type=MEDIA_TYPE)

    # Сначала пробуем batch через zone/update_records, но только если есть add actions.
    # Документация явно показывает action_list для add_*; remove_record там не задокументирован.
    # Поэтому delete всегда выполняем одиночными вызовами.
    try:
        for zone, actions in add_actions_by_zone.items():
            if not actions:
                continue
            payload = {
                "domains": [
                    {
                        "dname": zone,
                        "action_list": actions,
                    }
                ]
            }
            await _reg_call("zone/update_records", payload)
            _cache_invalidate(zone)
    except Exception as e:
        logger.warning("Batch add via zone/update_records failed, fallback to single add calls: %s", e)
        for zone, actions in add_actions_by_zone.items():
            for act in actions:
                await _apply_single_add(zone, act)
            _cache_invalidate(zone)

    # Удаления выполняем после/или до — тут лучше сначала delete, потом add при одиночном fallback.
    # Но т.к. batch add уже мог пройти, удалим оставшиеся delete отдельно.
    # Если хотите абсолютно предсказуемую replace-семантику, можно всегда делать delete first, add second без batch.
    for zone, actions in del_actions_by_zone.items():
        for act in actions:
            await _apply_single_delete(zone, act["subdomain"], act["record_type"], act["content"])
        _cache_invalidate(zone)

    return Response(status_code=204, media_type=MEDIA_TYPE)
