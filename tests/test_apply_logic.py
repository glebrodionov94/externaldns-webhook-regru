from copy import deepcopy

def _endpoint(dns, rtype, targets, ttl=300):
    return {"dnsName": dns, "recordTTL": ttl, "recordType": rtype, "targets": targets}

def test_noop_when_same_record(client, fake_regru):
    # Установим начальное состояние: A @ -> 1.2.3.4
    fake_regru.zones["example.com"] = [
        {"subname":"@", "rectype":"A", "content":"1.2.3.4", "ttl":300},
    ]

    # Сначала прогреть кэш GET'ом
    assert client.get("/records").status_code == 200

    body = {
        "Create": [_endpoint("example.com", "A", ["1.2.3.4"])],
        "UpdateNew": [], "UpdateOld": [], "Delete": []
    }
    resp = client.post("/records", json=body)
    assert resp.status_code == 200
    assert resp.json()["status"] == "noop"

    # Никаких zone/update_records не должно быть (или add/remove)
    assert not any(c[0].startswith("zone/update_records") for c in fake_regru.calls if c[0].startswith("zone/"))

def test_add_then_delete_mixed(client, fake_regru):
    # пустая зона
    fake_regru.zones["example.com"] = []

    # прогреть кэш
    client.get("/records")

    # добавляем A и MX
    body_add = {
        "Create": [
            _endpoint("www.example.com", "A", ["1.2.3.9"]),
            _endpoint("example.com", "MX", ["10 mx.example.com"]),
        ],
        "UpdateNew": [], "UpdateOld": [], "Delete": []
    }
    r1 = client.post("/records", json=body_add)
    assert r1.status_code == 200
    assert r1.json()["status"] == "ok"

    # кэш инвалидация — следующий GET увидит 2 записи
    g = client.get("/records").json()
    assert len(g) == 2
    assert any(e["recordType"] == "A" and e["dnsName"] == "www.example.com" for e in g)
    assert any(e["recordType"] == "MX" and e["targets"] == ["10 mx.example.com"] for e in g)

    # теперь удалим A (точечно) и добавим TXT
    body_mix = {
        "Create": [_endpoint("example.com", "TXT", ["hello"])],
        "UpdateNew": [], "UpdateOld": [],
        "Delete": [_endpoint("www.example.com", "A", ["1.2.3.9"])],
    }
    r2 = client.post("/records", json=body_mix)
    assert r2.status_code == 200
    assert r2.json()["status"] == "ok"

    # проверим состояние: остался MX и появился TXT, A исчез
    final = client.get("/records").json()
    types = sorted([(e["dnsName"], e["recordType"], tuple(e["targets"])) for e in final])
    assert ("example.com", "TXT", ("hello",)) in types
    assert any(t[1] == "MX" for t in types)
    assert not any(t[0] == "www.example.com" and t[1] == "A" for t in types)

def test_srv_caa_https_roundtrip(client, fake_regru):
    # пустая зона
    fake_regru.zones["corp.net"] = []

    # прогреть кэш
    client.get("/records")

    body = {
        "Create": [
            _endpoint("_sip._udp.corp.net", "SRV", ["0 5 5060 sipserver.corp.net"]),
            _endpoint("corp.net", "CAA", ["0 issue letsencrypt.org"]),
            _endpoint("corp.net", "HTTPS", ["1 . alpn=h3,h2 ipv4hint=192.0.2.1,192.0.2.2"]),
        ],
        "UpdateNew": [], "UpdateOld": [], "Delete": []
    }
    r = client.post("/records", json=body)
    assert r.status_code == 200

    # чтение
    eps = client.get("/records").json()
    # должны появиться 3 записи
    cnt = 0
    for e in eps:
        if e["recordType"] in ("SRV","CAA","HTTPS") and (e["dnsName"].endswith("corp.net")):
            cnt += 1
    assert cnt == 3

    # удалим SRV
    body_del = {
        "Create": [],
        "UpdateNew": [], "UpdateOld": [],
        "Delete": [_endpoint("_sip._udp.corp.net", "SRV", ["0 5 5060 sipserver.corp.net"])],
    }
    r2 = client.post("/records", json=body_del)
    assert r2.status_code == 200

    # убедимся, что SRV исчез
    eps2 = client.get("/records").json()
    assert not any(e for e in eps2 if e["recordType"]=="SRV" and e["dnsName"]=="_sip._udp.corp.net")
