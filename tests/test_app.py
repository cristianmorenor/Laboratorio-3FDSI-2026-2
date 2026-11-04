import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))
os.environ["NETOPS_DB"] = os.path.join(tempfile.mkdtemp(), "t.db")
os.environ["NETOPS_ADMIN_PASSWORD"] = "admin123"

import app as netops  # noqa: E402

netops.init_db()


def login(c):
    return c.post("/login", data={"username": "admin", "password": "admin123"})


def test_health_and_headers():
    r = netops.app.test_client().get("/health")
    assert r.get_json() == {"status": "ok"}
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert "Content-Security-Policy" in r.headers


def test_login_ok_and_fail():
    c = netops.app.test_client()
    assert login(c).status_code == 200
    assert c.post("/login", data={"username": "admin", "password": "x"}).status_code == 401


def test_sqli_blocked():
    c = netops.app.test_client()
    assert c.post("/login", data={"username": "admin' --", "password": "x"}).status_code == 401
    assert c.get("/devices?q=' OR '1'='1").get_json() == []


def test_protected_routes_need_auth():
    c = netops.app.test_client()
    for url in ("/ping?host=127.0.0.1", "/logs"):
        assert c.get(url).status_code == 401
    assert c.post("/import", data="a: 1").status_code == 401


def test_command_injection_blocked():
    c = netops.app.test_client()
    login(c)
    assert c.get("/ping?host=127.0.0.1;id").status_code == 400


def test_xss_escaped():
    body = netops.app.test_client().get("/search?q=<script>alert(1)</script>").get_data(as_text=True)
    assert "<script>alert(1)</script>" not in body


def test_path_traversal_blocked():
    c = netops.app.test_client()
    login(c)
    assert c.get("/logs?file=../app.py").status_code == 404
    assert c.get("/logs").status_code == 200


def test_yaml_unsafe_tag_rejected():
    c = netops.app.test_client()
    login(c)
    assert c.post("/import", data="!!python/object/apply:os.system ['id']").status_code == 400
