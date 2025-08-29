import time
import app as webhook_app

def test_records_get_and_cache(client, fake_regru):
    # начальное состояние зоны
    fake_regru.zones["example.com"] = [
        {"subname":"@", "rectype":"A", "content":"1.2.3.4", "ttl":300},
        {"subname":"mail", "rectype":"MX", "prio":10, "mail_server":"mx.example.com", "ttl":300},
    ]

    # первый GET -> читает из API, кладёт в кэш
    r1 = client.get("/records")
    assert r1.status_code == 200
    eps1 = r1.json()
    # ожидаем 2 записи
    assert len(eps1) == 2
    # MX должен быть в presentation виде
    assert any(e["recordType"]=="MX" and e["targets"]==["10 mx.example.com"] for e in eps1)

    # Меняем состояние у "регру", но кэш ещё свежий — должен вернуть старые данные
    fake_regru.zones["example.com"].append({"subname":"@", "rectype":"TXT", "content":"hello", "ttl":300})
    r2 = client.get("/records")
    eps2 = r2.json()
    assert len(eps2) == 2  # TXT не появился из-за кэша

    # Протухаем кэш вручную
    zc = webhook_app._cache["example.com"]
    zc["fetched_at"] = time.time() - 999999

    r3 = client.get("/records")
    eps3 = r3.json()
    assert len(eps3) == 3  # теперь TXT увидели
    assert any(e["recordType"]=="TXT" and e["targets"]==["hello"] for e in eps3)
