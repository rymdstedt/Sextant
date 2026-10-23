"""Web UI: upload configs or snapshots, run collection, preview and download documents.

Security model
- Login with SEXTANT_ADMIN_USER / SEXTANT_ADMIN_PASSWORD (or SEXTANT_TRUSTED_USER_HEADER behind an
  authenticating reverse proxy such as oauth2-proxy). Session cookie is signed, HttpOnly, SameSite=strict.
- Every POST carries a per-session CSRF token.
- Device credentials typed into the collect form live only in memory for the duration of the job.
- Uploaded configs are redacted before anything is written to the data directory.
"""

from __future__ import annotations

import hmac
import logging
import os
import re
import secrets
import shutil
import threading
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

import yaml
from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from sextant import __version__
from sextant.analysis import analyze
from sextant.builders.common import ROLE_LABEL, device_status, fleet_totals, sorted_devices
from sextant.drivers import Credentials, load_all
from sextant.model import DocumentInfo, Snapshot
from sextant.pipeline import (
    Inventory,
    add_to_snapshot,
    collect_inventory,
    import_many,
    load_snapshot,
    save_snapshot,
)
from sextant.theme import available as available_themes
from sextant.theme import load_theme

log = logging.getLogger(__name__)
HERE = Path(__file__).parent
ID_RE = re.compile(r"^[a-f0-9]{12}$")
MAX_UPLOAD = 50 * 1024 * 1024


@dataclass
class Job:
    id: str
    status: str = "running"  # running | done | failed
    progress: list[str] = field(default_factory=list)
    snapshot_id: str | None = None
    error: str | None = None
    started: datetime = field(default_factory=lambda: datetime.now(UTC))


class Store:
    """Snapshots and rendered documents on disk under SEXTANT_DATA_DIR."""

    def __init__(self, root: Path):
        self.root = root
        (root / "snapshots").mkdir(parents=True, exist_ok=True)
        (root / "documents").mkdir(parents=True, exist_ok=True)

    def path(self, sid: str) -> Path:
        if not ID_RE.match(sid):
            raise HTTPException(404)
        return self.root / "snapshots" / f"{sid}.json"

    def docs_dir(self, sid: str) -> Path:
        self.path(sid)
        return self.root / "documents" / sid

    def save(self, snap: Snapshot, sid: str | None = None) -> str:
        sid = sid or uuid.uuid4().hex[:12]
        save_snapshot(snap, self.path(sid))
        return sid

    def load(self, sid: str) -> Snapshot:
        p = self.path(sid)
        if not p.exists():
            raise HTTPException(404, "Snapshot not found")
        return load_snapshot(p)

    def delete(self, sid: str) -> None:
        self.path(sid).unlink(missing_ok=True)
        shutil.rmtree(self.docs_dir(sid), ignore_errors=True)

    def list(self) -> list[tuple[str, Snapshot]]:
        out = []
        for p in sorted((self.root / "snapshots").glob("*.json"), key=lambda x: -x.stat().st_mtime):
            try:
                out.append((p.stem, load_snapshot(p)))
            except Exception:  # noqa: BLE001
                log.warning("unreadable snapshot %s", p)
        return out


def create_app() -> FastAPI:
    data_dir = Path(os.environ.get("SEXTANT_DATA_DIR", "./data")).resolve()
    store = Store(data_dir)
    admin_user = os.environ.get("SEXTANT_ADMIN_USER", "admin")
    admin_password = os.environ.get("SEXTANT_ADMIN_PASSWORD")
    trusted_header = os.environ.get("SEXTANT_TRUSTED_USER_HEADER")
    if not admin_password and not trusted_header:
        admin_password = secrets.token_urlsafe(12)
        log.warning("SEXTANT_ADMIN_PASSWORD not set; generated one-time password for '%s': %s", admin_user,
                    admin_password)
        print(f"sextant web: login '{admin_user}' / '{admin_password}' (set SEXTANT_ADMIN_PASSWORD to fix)", flush=True)
    secret_key = os.environ.get("SEXTANT_SECRET_KEY") or secrets.token_urlsafe(32)

    app = FastAPI(title="Sextant", version=__version__, docs_url=None, redoc_url=None, openapi_url=None)
    app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")
    templates = Jinja2Templates(directory=HERE / "templates")
    theme = load_theme()  # web UI branding: $SEXTANT_THEME (documents can use another theme per snapshot)
    templates.env.globals["theme"] = theme
    jobs: dict[str, Job] = {}

    # ----------------------------------------------------------------- auth helpers
    def current_user(request: Request) -> str | None:
        if trusted_header and request.headers.get(trusted_header):
            return request.headers[trusted_header]
        return request.session.get("user")

    def csrf(request: Request) -> str:
        tok = request.session.get("csrf")
        if not tok:
            tok = request.session["csrf"] = secrets.token_urlsafe(24)
        return tok

    def check_csrf(request: Request, token: str) -> None:
        if not token or not hmac.compare_digest(token, request.session.get("csrf", "")):
            raise HTTPException(400, "Invalid form token, reload the page and try again.")

    def page(request: Request, name: str, **ctx) -> HTMLResponse:
        return templates.TemplateResponse(request, name, {
            "user": current_user(request), "csrf": csrf(request), "version": __version__,
            "flash": request.session.pop("flash", None), **ctx})

    def flash(request: Request, text: str, kind: str = "success") -> None:
        request.session["flash"] = {"text": text, "kind": kind}

    @app.middleware("http")
    async def require_login(request: Request, call_next):
        path = request.url.path
        if path.startswith(("/static", "/theme", "/login", "/healthz")) or current_user(request):
            response = await call_next(request)  # /theme only serves logos, fonts and colours
        else:
            return RedirectResponse(f"/login?next={path}", status_code=303)
        response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "same-origin")
        return response

    # ----------------------------------------------------------------- routes
    @app.get("/theme.css")
    def theme_css():
        faces = "".join(
            f'@font-face {{ font-family: "{theme.fonts.family}"; font-weight: {w}; font-style: {st}; '
            f'src: url("/theme/{rel}"); }}\n' for w, st, rel in theme.font_faces())
        c = theme.colors
        gradient = (f"linear-gradient(180deg, {c.primary}, {c.accent})" if theme.cover_gradient else c.primary)
        css = (f"{faces}:root {{ {c.css_vars()}; --font: {theme.fonts.stack}; "
               f"--brand-gradient: {gradient}; }}\n")
        return Response(css, media_type="text/css", headers={"Cache-Control": "max-age=300"})

    @app.get("/theme/{rel:path}")
    def theme_asset(rel: str):
        allowed = {theme.logos.color, theme.logos.white, theme.logos.symbol, *theme.fonts.files.values()}
        path = theme.asset(rel) if rel in allowed else None
        if not path:
            raise HTTPException(404)
        return FileResponse(path)

    @app.get("/healthz")
    def healthz():
        return {"ok": True, "version": __version__}

    @app.get("/login", response_class=HTMLResponse)
    def login_form(request: Request, next: str = "/"):
        return page(request, "login.html", next=next if next.startswith("/") and not next.startswith("//") else "/")

    @app.post("/login")
    def login(request: Request, username: str = Form(...), password: str = Form(...), next: str = Form("/"),
              token: str = Form("")):
        check_csrf(request, token)
        ok = admin_password is not None and hmac.compare_digest(username, admin_user) and hmac.compare_digest(
            password.encode(), admin_password.encode())
        if not ok:
            log.warning("failed login for %r from %s", username, request.client.host if request.client else "?")
            return page(request, "login.html", next=next, error="Wrong username or password.")
        request.session.clear()
        request.session["user"] = username
        return RedirectResponse(next if next.startswith("/") and not next.startswith("//") else "/", 303)

    @app.post("/logout")
    def logout(request: Request, token: str = Form("")):
        check_csrf(request, token)
        request.session.clear()
        return RedirectResponse("/login", 303)

    @app.get("/", response_class=HTMLResponse)
    def index(request: Request):
        rows = []
        for sid, snap in store.list():
            t = fleet_totals(snap)
            rows.append({"id": sid, "snap": snap, "totals": t})
        return page(request, "index.html", rows=rows, nav="snapshots")

    @app.get("/new", response_class=HTMLResponse)
    def new(request: Request, tab: str = "upload"):
        drivers = sorted(load_all().values(), key=lambda d: d.label)
        return page(request, "new.html", tab=tab, drivers=drivers, nav="new")

    def _info(customer: str, site: str, author: str) -> DocumentInfo:
        return DocumentInfo(customer=customer.strip() or "Internal", site=site.strip() or None,
                            author=author.strip() or None)

    async def ingest(files: list[UploadFile], driver: str, snap: Snapshot, keep_info: bool) -> tuple[int, list[str]]:
        """Import uploaded files (any vendor mix, zips, snapshot JSON) into `snap`. Returns (devices
        imported, notes about devices merged into or replacing earlier imports)."""
        tmp = store.root / "tmp" / uuid.uuid4().hex
        tmp.mkdir(parents=True)
        count, notes = 0, []
        try:
            saved: list[Path] = []
            for i, f in enumerate(files):
                content = await f.read(MAX_UPLOAD + 1)
                if len(content) > MAX_UPLOAD:
                    raise HTTPException(413, f"{f.filename} is larger than 50 MB")
                name = Path(f.filename or "upload.txt").name
                text = content.decode("utf-8", errors="replace")
                if name.endswith(".json") and '"schema_version"' in text[:2000] and '"devices"' in text:
                    other = Snapshot.model_validate_json(text)  # an uploaded snapshot from an on-prem run
                    notes += add_to_snapshot(snap, other.devices, other.errors)
                    count += len(other.devices)
                    if not keep_info:
                        snap.info = other.info
                    continue
                p = tmp / f"{i:04d}-{name}"  # zips are read in memory by import_many, never extracted
                p.write_bytes(content)
                saved.append(p)
            if saved:
                done: set[str] = set()
                devices, errors = import_many(saved, None if driver == "auto" else driver, snap.info.site,
                                              progress=lambda f, _d, _h: done.add(re.sub(r"^\d{4}-", "", f)))
                notes += add_to_snapshot(snap, devices, [re.sub(r"^\d{4}-", "", e) for e in errors], done)
                count += len(devices)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        return count, notes

    @app.post("/upload")
    async def upload(request: Request, files: list[UploadFile] = File(...), driver: str = Form("auto"),
                     customer: str = Form(""), site: str = Form(""), author: str = Form(""),
                     token: str = Form("")):
        check_csrf(request, token)
        snap = Snapshot(info=_info(customer, site, author))
        await ingest(files, driver, snap, keep_info=bool(customer))
        if not snap.devices:
            flash(request, "Nothing imported. " + "; ".join(snap.errors), "error")
            return RedirectResponse("/new", 303)
        sid = store.save(analyze(snap))
        flash(request, f"Imported {len(snap.devices)} device(s).", "warning" if snap.errors else "success")
        return RedirectResponse(f"/s/{sid}", 303)

    @app.post("/s/{sid}/add")
    async def add_files(request: Request, sid: str, files: list[UploadFile] = File(...),
                        driver: str = Form("auto"), token: str = Form("")):
        """More files for an existing documentation: another vendor, more switches, or a missing capture."""
        check_csrf(request, token)
        snap = store.load(sid)
        before = len(snap.errors)
        count, notes = await ingest(files, driver, snap, keep_info=True)
        store.save(analyze(snap), sid)
        stale = " Generate the documents again to include them." if store.docs_dir(sid).exists() else ""
        if count:
            text = f"Added {count} device(s); {len(snap.devices)} in total." + (f" {'; '.join(notes)}." if notes
                                                                                 else "") + stale
            flash(request, text, "warning" if len(snap.errors) > before else "success")
        else:
            flash(request, "Nothing imported. " + "; ".join(snap.errors[before:]), "error")
        return RedirectResponse(f"/s/{sid}", 303)

    @app.post("/collect")
    def collect(request: Request, inventory: str = Form(...), username: str = Form(""), password: str = Form(""),
                enable_secret: str = Form(""), api_token: str = Form(""), snmp_community: str = Form(""),
                token: str = Form("")):
        check_csrf(request, token)
        try:
            data = yaml.safe_load(inventory) or {}
            if "credentials" in data:
                raise ValueError("Do not put credentials in the inventory here; use the credential fields.")
            inv = Inventory.model_validate(data)
        except Exception as exc:  # noqa: BLE001
            flash(request, f"Invalid inventory: {exc}", "error")
            return RedirectResponse("/new?tab=collect", 303)
        creds = Credentials(username=username or None, password=password or None,
                            enable_secret=enable_secret or None, api_token=api_token or None,
                            snmp_community=snmp_community or None)
        for t in inv.targets:  # every target uses the credentials typed in the form
            t.credentials = "form"
            t.file = None
            if t.method == "file":
                t.method = "ssh"
        job = Job(id=uuid.uuid4().hex[:12])
        jobs[job.id] = job

        def run() -> None:
            try:
                snap = collect_inventory(inv, extra_creds={"form": creds},
                                         progress=lambda n, s: job.progress.append(f"{n}: {s}"))
                job.snapshot_id = store.save(snap)
                job.status = "done"
            except Exception as exc:  # noqa: BLE001
                log.exception("collection job failed")
                job.status, job.error = "failed", f"{exc.__class__.__name__}: {exc}"

        threading.Thread(target=run, daemon=True).start()
        return RedirectResponse(f"/jobs/{job.id}", 303)

    @app.get("/jobs/{jid}", response_class=HTMLResponse)
    def job_page(request: Request, jid: str):
        job = jobs.get(jid)
        if not job:
            raise HTTPException(404)
        if job.status == "done":
            return RedirectResponse(f"/s/{job.snapshot_id}", 303)
        return page(request, "job.html", job=job, nav="new")

    @app.get("/s/{sid}", response_class=HTMLResponse)
    def snapshot_page(request: Request, sid: str, tab: str = "devices"):
        snap = store.load(sid)
        devices = []
        for d in sorted_devices(snap):
            status, label = device_status(d)
            devices.append({"d": d, "role": ROLE_LABEL[d.role], "status": status, "label": label})
        findings = sorted(((f, d.hostname) for d in snap.devices for f in d.findings),
                          key=lambda x: -x[0].severity.rank)
        docs_dir = store.docs_dir(sid)
        documents = sorted(p.name for p in docs_dir.glob("*")) if docs_dir.exists() else []
        return page(request, "snapshot.html", sid=sid, snap=snap, devices=devices, findings=findings,
                    totals=fleet_totals(snap), documents=documents, tab=tab, nav="snapshots",
                    themes=available_themes(),
                    drivers=sorted(load_all().values(), key=lambda d: d.label))

    @app.post("/s/{sid}/info")
    def update_info(request: Request, sid: str, customer: str = Form(""), project: str = Form(""),
                    site: str = Form(""), author: str = Form(""), reviewer: str = Form(""),
                    version: str = Form("1.0"), classification: str = Form("Internal"), theme_name: str = Form(""),
                    token: str = Form("")):
        check_csrf(request, token)
        snap = store.load(sid)
        snap.info = snap.info.model_copy(update={
            "customer": customer or "Internal", "project": project or snap.info.project, "site": site or None,
            "author": author or None, "reviewer": reviewer or None, "version": version or "1.0",
            "classification": classification or "Internal",
            "theme": theme_name if theme_name in available_themes() else None})
        store.save(snap, sid)
        flash(request, "Document details saved.")
        return RedirectResponse(f"/s/{sid}?tab=generate", 303)

    @app.post("/s/{sid}/render")
    def render_docs(request: Request, sid: str, include_raw: str = Form(""), token: str = Form("")):
        check_csrf(request, token)
        from sextant.render import render_all

        snap = store.load(sid)
        out = store.docs_dir(sid)
        shutil.rmtree(out, ignore_errors=True)
        try:
            render_all(snap, out, include_raw=bool(include_raw))
            flash(request, "Documents generated.")
        except Exception as exc:  # noqa: BLE001
            log.exception("render failed")
            flash(request, f"Rendering failed: {exc.__class__.__name__}: {exc}", "error")
        return RedirectResponse(f"/s/{sid}?tab=generate", 303)

    @app.get("/s/{sid}/files/{name}")
    def download(sid: str, name: str):
        out = store.docs_dir(sid)
        p = (out / name).resolve()
        if p.parent != out.resolve() or not p.exists():
            raise HTTPException(404)
        return FileResponse(p, filename=name)

    @app.get("/s/{sid}/snapshot.json")
    def download_snapshot(sid: str):
        return FileResponse(store.path(sid), filename=f"snapshot-{sid}.json", media_type="application/json")

    @app.get("/s/{sid}/preview/{kind}", response_class=HTMLResponse)
    def preview(sid: str, kind: str):
        from sextant.builders.asbuilt import build_asbuilt
        from sextant.builders.summary import build_summary
        from sextant.render.html import render_html

        if kind not in ("summary", "asbuilt"):
            raise HTTPException(404)
        snap = store.load(sid)
        doc = build_summary(snap) if kind == "summary" else build_asbuilt(snap)
        html = render_html(doc, load_theme(snap.info.theme) if snap.info.theme else None, standalone=True)
        return HTMLResponse(html)

    @app.post("/s/{sid}/delete")
    def delete(request: Request, sid: str, token: str = Form("")):
        check_csrf(request, token)
        store.delete(sid)
        flash(request, "Snapshot deleted.")
        return RedirectResponse("/", 303)

    @app.get("/favicon.ico")
    def favicon():
        return Response(status_code=204)

    # added last so it is the outermost middleware and the login check can read the session
    app.add_middleware(SessionMiddleware, secret_key=secret_key, same_site="strict",
                       https_only=os.environ.get("SEXTANT_HTTPS_ONLY", "0") == "1", max_age=8 * 3600,
                       session_cookie="sextant_session")
    return app
