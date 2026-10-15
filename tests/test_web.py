import re

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("HSDOC_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("HSDOC_ADMIN_USER", "admin")
    monkeypatch.setenv("HSDOC_ADMIN_PASSWORD", "pw-test")
    from hsdoc.web.app import create_app

    return TestClient(create_app())


def _token(html: str) -> str:
    return re.search(r'name="token" value="([^"]+)"', html).group(1)


def _login(client):
    r = client.get("/login")
    r = client.post("/login", data={"username": "admin", "password": "pw-test", "next": "/", "token": _token(r.text)})
    assert r.status_code == 200 and "Snapshots" in r.text
    return _token(r.text)


def test_requires_login(client):
    r = client.get("/", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith("/login")
    assert client.get("/healthz").json()["ok"]


def test_bad_password(client):
    r = client.get("/login")
    r = client.post("/login", data={"username": "admin", "password": "nope", "token": _token(r.text)})
    assert "Wrong username or password" in r.text


def test_csrf_enforced(client):
    _login(client)
    r = client.post("/logout", data={"token": "bogus"})
    assert r.status_code == 400


def test_upload_render_download(client, tmp_path):
    token = _login(client)
    cfg = ("version 17.9\nhostname web-sw01\n!\nenable secret 9 $9$supersecret\n!\n"
           "interface GigabitEthernet1/0/1\n switchport mode access\n switchport access vlan 10\n!\nend\n")
    r = client.post("/upload", data={"driver": "auto", "customer": "Example AB", "token": token},
                    files=[("files", ("web-sw01.txt", cfg.encode(), "text/plain"))])
    if "Nothing imported" in r.text:
        pytest.skip("cisco_ios driver not available")
    assert "web-sw01" in r.text
    sid = re.search(r"/s/([a-f0-9]{12})", str(r.url)).group(1)
    assert "supersecret" not in (tmp_path / "snapshots" / f"{sid}.json").read_text()
    r = client.get(f"/s/{sid}/preview/summary")
    assert r.status_code == 200 and "Infrastructure Summary" in r.text
    r = client.post(f"/s/{sid}/render", data={"token": token})
    assert "Documents generated" in r.text, r.text[:2000]
    names = re.findall(rf"/s/{sid}/files/([^\"]+)", r.text)
    assert len(names) == 6
    assert client.get(f"/s/{sid}/files/{names[0]}").status_code == 200
    assert client.get(f"/s/{sid}/files/..%2Fsnapshots").status_code == 404
