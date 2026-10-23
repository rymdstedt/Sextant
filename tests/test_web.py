import re

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("SEXTANT_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SEXTANT_ADMIN_USER", "admin")
    monkeypatch.setenv("SEXTANT_ADMIN_PASSWORD", "pw-test")
    from sextant.web.app import create_app

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


def test_add_other_vendor_and_capture_to_existing(client, tmp_path):
    """One documentation, several uploads: a FortiGate joins the Cisco switch, and the switch's later
    'show spanning-tree' capture completes it instead of replacing it."""
    token = _login(client)
    cfg = ("web-sw01#show running-config\nBuilding configuration...\nversion 17.9\nhostname web-sw01\n!\n"
           "interface GigabitEthernet1/0/1\n switchport mode trunk\n!\n"
           "snmp-server user mon grp v3 auth sha AuthKey123 priv aes 128 PrivKey456\nend\n\nweb-sw01#\n")
    r = client.post("/upload", data={"driver": "auto", "customer": "Example AB", "token": token},
                    files=[("files", ("web-sw01.txt", cfg.encode(), "text/plain"))])
    sid = re.search(r"/s/([a-f0-9]{12})", str(r.url)).group(1)
    stp = ("web-sw01#show spanning-tree\n\nVLAN0001\n  Spanning tree enabled protocol rstp\n"
           "  Root ID    Priority    4097\n             Address     0011.aa00.0001\n"
           "             This bridge is the root\n\n"
           "  Bridge ID  Priority    4097  (priority 4096 sys-id-ext 1)\n             Address     0011.aa00.0001\n\n"
           "Interface           Role Sts Cost      Prio.Nbr Type\n"
           "------------------- ---- --- --------- -------- --------------------------------\n"
           "Gi1/0/1             Desg FWD 4         128.1    P2p\n\nweb-sw01#\n")
    fgt = "#config-version=FGVM64-7.4.5-FW-build2702-240611:opmode=0:vdom=0\nconfig system global\n    set hostname \"fw01\"\nend\n"
    r = client.post(f"/s/{sid}/add", data={"driver": "auto", "token": token},
                    files=[("files", ("web-sw01-stp.log", stp.encode(), "text/plain")),
                           ("files", ("fw01.conf", fgt.encode(), "text/plain"))])
    assert "Added 2 device(s); 2 in total" in r.text and "web-sw01: added to the earlier import" in r.text
    from sextant.pipeline import load_snapshot

    path = tmp_path / "snapshots" / f"{sid}.json"
    snap = load_snapshot(path)
    by = {d.hostname: d for d in snap.devices}
    assert set(by) == {"web-sw01", "fw01"} and by["fw01"].platform == "fortigate"
    sw = by["web-sw01"]
    assert any(i.name == "GigabitEthernet1/0/1" for i in sw.interfaces)  # config kept
    assert sw.spanning_tree.instances and sw.spanning_tree.instances[0].is_root  # capture added
    text = path.read_text()
    assert "AuthKey123" not in text and "PrivKey456" not in text  # raw outputs are redacted too
    assert snap.info.customer == "Example AB"
