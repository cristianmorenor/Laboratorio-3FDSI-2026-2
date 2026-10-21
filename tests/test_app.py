import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))
os.environ["NETOPS_DB"] = os.path.join(tempfile.mkdtemp(), "t.db")

import app as netops  # noqa: E402

netops.init_db()
client = netops.app.test_client()


def test_health():
    assert client.get("/health").get_json() == {"status": "ok"}


def test_devices_list():
    assert len(client.get("/devices").get_json()) == 3


def test_login_ok_and_fail():
    assert client.post("/login", data={"username": "admin", "password": "admin123"}).status_code == 200
    assert client.post("/login", data={"username": "admin", "password": "x"}).status_code == 401
