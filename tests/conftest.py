# conftest.py
import os
import time
import types
import pytest

# ВАЖНО: установить env ДО импорта app
os.environ.setdefault("DOMAIN_FILTERS", "example.com,corp.net")
os.environ.setdefault("DEFAULT_TTL", "300")
os.environ.setdefault("CACHE_TTL_SECONDS", "60")
os.environ.setdefault("CACHE_MAX_ZONES", "100")
os.environ.setdefault("REGRU_USERNAME", "testuser")
os.environ.setdefault("REGRU_PASSWORD", "testpass")

# Импортируем приложение
import app as webhook_app
from fastapi.testclient import TestClient

class FakeRegRu:
    """
    Мини-эмулятор REG.RU API.
    Держит состояние зон в памяти и симулирует:
      - zone/get_resource_records
      - zone/update_records (batch)
      - zone/remove_record
      - zone/add_* (A, AAAA, CNAME, TXT, NS, MX, SRV, CAA, HTTPS)
    Формат хранения:
      zones = {
        "example.com": [
           {"subname":"@", "rectype":"A", "content":"1.2.3.4", "ttl":300},
           {"subname":"mail", "rectype":"MX", "prio":10, "mail_server":"mx.example.com", "ttl":300},
           ...
        ],
      }
    """
    def __init__(self):
        self.zones = {}
        self.calls = []  # журнал вызовов ("method", payload)

    def _ensure_zone(self, z):
        self.zones.setdefault(z, [])

    def _match_rr(self, rr, sub=None, rectype=None, content=None):
        if sub is not None and rr.get("subname", "@") != sub:
            return False
        if rectype is not None and rr.get("rectype", "").upper() != rectype.upper():
            return False
        if content is not None:
            # для remove по content — сравниваем по строке content, если у типа его нет — собираем presentation
            if "content" in rr:
                return rr["content"] == content
            # MX/SRV/CAA/HTTPS presentation fallback
            if rr.get("rectype") == "MX":
                pres = f'{int(rr.get("prio", 10))} {rr.get("mail_server")}'
                return pres == content
            if rr.get("rectype") == "SRV":
                pres = f'{int(rr.get("priority",0))} {int(rr.get("weight",0))} {int(rr.get("port",0))} {rr.get("target","")}'
                return pres == content
            if rr.get("rectype") == "CAA":
                pres = f'{int(rr.get("flags",0))} {rr.get("tag","issue")} {rr.get("value","")}'
                return pres == content
            if rr.get("rectype") == "HTTPS":
                pres = f'{int(rr.get("priority",1))} {rr.get("target",".")} {rr.get("value","")}'
                return pres == content
        return True

    def _add_rr(self, zone, rr):
        self._ensure_zone(zone)
        self.zones[zone].append(rr)

    def _remove_rr(self, zone, sub, rectype, content=None):
        self._ensure_zone(zone)
        new = []
        removed = 0
        for rr in self.zones[zone]:
            if self._match_rr(rr, sub, rectype, content):
                removed += 1
                continue
            new.append(rr)
        self.zones[zone] = new
        return removed

    # ---- API methods ----
    def call(self, method, payload):
        self.calls.append((method, payload))
        if method == "zone/get_resource_records":
            # payload: {"domains":[{"dname":"example.com"}]}
            out_domains = []
            for d in payload.get("domains", []):
                z = d["dname"].lower()
                self._ensure_zone(z)
                out_domains.append({
                    "result": "success",
                    "dname": z,
                    "soa": {"ttl": 300},
                    "rrs": self.zones[z],
                })
            return {"result": "success", "answer": {"domains": out_domains}}

        if method == "zone/remove_record":
            zone = payload["domains"][0]["dname"].lower()
            sub = payload.get("subdomain", "@")
            rectype = payload.get("record_type")
            content = payload.get("content")
            self._remove_rr(zone, sub, rectype, content)
            return {"result": "success"}

        if method == "zone/update_records":
            # batch: {"action_list":[ {...}, ... ]}
            for act in payload.get("action_list", []):
                action = act.get("action")
                z = act["dname"].lower()
                if action == "remove":
                    self._remove_rr(z, act.get("subdomain","@"), act.get("record_type"), act.get("content"))
                elif action.startswith("add_"):
                    self._apply_add(z, action, act)
            return {"result": "success"}

        # individual add_* fallbacks
        if method.startswith("zone/add_"):
            z = payload["domains"][0]["dname"].lower()
            action = method.replace("zone/", "")
            self._apply_add(z, action, payload)
            return {"result": "success"}

        raise RuntimeError(f"Unknown method {method}")

    def _apply_add(self, zone, action, data):
        # map add_* into stored rr dicts
        ttl = int(data.get("ttl", 300))
        if action in ("add_alias",):
            self._add_rr(zone, {"subname": data.get("subdomain","@"), "rectype":"A", "content": data["ipaddr"], "ttl": ttl})
        elif action in ("add_aaaa",):
            self._add_rr(zone, {"subname": data.get("subdomain","@"), "rectype":"AAAA", "content": data["ipaddr"], "ttl": ttl})
        elif action in ("add_cname",):
            self._add_rr(zone, {"subname": data.get("subdomain","@"), "rectype":"CNAME", "content": data["canonical_name"], "ttl": ttl})
        elif action in ("add_txt",):
            self._add_rr(zone, {"subname": data.get("subdomain","@"), "rectype":"TXT", "content": data["text"], "ttl": ttl})
        elif action in ("add_ns",):
            self._add_rr(zone, {"subname": data.get("subdomain","@"), "rectype":"NS", "content": data["dns_server"], "ttl": ttl})
        elif action in ("add_mx",):
            self._add_rr(zone, {"subname": data.get("subdomain","@"), "rectype":"MX",
                                "prio": int(data.get("priority",10)), "mail_server": data["mail_server"], "ttl": ttl})
        elif action in ("add_srv",):
            # здесь service уже включает _sip._udp[.sub]
            service = data.get("service","_srv")
            self._add_rr(zone, {"subname": service, "rectype":"SRV",
                                "priority": int(data.get("priority",0)),
                                "weight": int(data.get("weight",0)),
                                "port": int(data.get("port",0)),
                                "target": data["target"], "ttl": ttl})
        elif action in ("add_caa",):
            self._add_rr(zone, {"subname": data.get("subdomain","@"), "rectype":"CAA",
                                "flags": int(data.get("flags",0)),
                                "tag": data.get("tag","issue"),
                                "value": data.get("value",""), "ttl": ttl})
        elif action in ("add_https",):
            self._add_rr(zone, {"subname": data.get("subdomain","@"), "rectype":"HTTPS",
                                "priority": int(data.get("priority",1)),
                                "target": data.get("target","."),
                                "value": data.get("value",""), "ttl": ttl})
        else:
            raise RuntimeError(f"Unsupported add action {action}")

@pytest.fixture(autouse=True)
def fake_regru(monkeypatch):
    """
    Подменяем app.reg_call на заглушку, которая обращается к FakeRegRu.
    Сбиваем кэш между тестами.
    """
    fake = FakeRegRu()

    async def _fake_reg_call(path, payload):
        return fake.call(path, payload)

    # сброс кэша
    webhook_app._cache.clear()

    monkeypatch.setattr(webhook_app, "reg_call", _fake_reg_call)
    return fake

@pytest.fixture
def client():
    return TestClient(webhook_app.app)
