import app as webhook_app

def test_parse_mx():
    pr, host = webhook_app.parse_mx("10 mail.example.com")
    assert pr == 10 and host == "mail.example.com"

def test_parse_srv():
    pr, w, p, tgt = webhook_app.parse_srv("0 5 5060 sip.example.com")
    assert (pr, w, p, tgt) == (0, 5, 5060, "sip.example.com")

def test_parse_caa():
    flags, tag, val = webhook_app.parse_caa("0 issue letsencrypt.org")
    assert flags == 0 and tag == "issue" and val == "letsencrypt.org"

def test_parse_https():
    pr, tgt, params = webhook_app.parse_https("1 . alpn=h3,h2 ipv4hint=192.0.2.1,192.0.2.2")
    assert pr == 1 and tgt == "." and "alpn=h3,h2" in params

def test_split_name_with_filters():
    sub, zone = webhook_app._split_name("www.api.example.com")
    assert (sub, zone) == ("www.api", "example.com")

    sub2, zone2 = webhook_app._split_name("login.corp.net")
    # DOMAIN_FILTERS не содержит corp.net => fallback на двухуровневую эвристику
    assert zone2 in ("corp.net", "net")
