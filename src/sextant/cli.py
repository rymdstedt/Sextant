"""sextant command line: collect, import, render, web."""

from __future__ import annotations

import logging
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from sextant import __version__

app = typer.Typer(add_completion=False, no_args_is_help=True,
                  help="Sextant: infrastructure documentation from live devices or config files.")
console = Console()


def _setup_logging(verbose: bool) -> None:
    logging.basicConfig(level=logging.DEBUG if verbose else logging.WARNING,
                        format="%(levelname)s %(name)s: %(message)s")


def _print_snapshot(snap) -> None:
    from sextant.builders.common import ROLE_LABEL, device_status, sorted_devices

    t = Table(title=f"{len(snap.devices)} device(s)")
    for c in ("Device", "Role", "Platform", "Version", "Findings", "Status"):
        t.add_column(c)
    for d in sorted_devices(snap):
        _, label = device_status(d)
        t.add_row(d.hostname, ROLE_LABEL[d.role], d.platform or "", d.os_version or "", str(len(d.findings)), label)
    console.print(t)
    for e in snap.errors:
        console.print(f"[red]Not collected:[/red] {e}")


@app.command()
def collect(
    inventory: Path = typer.Option(..., "--inventory", "-i", exists=True, help="inventory.yaml"),
    out: Path = typer.Option(Path("snapshot.json"), "--out", "-o", help="Snapshot JSON to write"),
    credentials: Path | None = typer.Option(None, help="credentials.yaml (default: next to the inventory)"),
    only: list[str] = typer.Option(None, "--only", help="Collect only these target names"),
    workers: int = typer.Option(8, help="Parallel connections"),
    render_to: Path | None = typer.Option(None, "--render", help="Also render documents into this folder"),
    keep_raw: bool = typer.Option(False, help="Keep redacted raw command outputs in the snapshot"),
    verbose: bool = typer.Option(False, "-v"),
):
    """Collect from every target in the inventory (read-only) and save a redacted snapshot."""
    _setup_logging(verbose)
    from sextant.pipeline import collect_inventory, load_inventory, save_snapshot

    inv = load_inventory(inventory, credentials)
    with console.status("Collecting…") as status:
        snap = collect_inventory(inv, workers=workers, only=only or None, keep_raw=keep_raw,
                                 progress=lambda name, st: status.update(f"{name}: {st}"))
    save_snapshot(snap, out)
    _print_snapshot(snap)
    console.print(f"Snapshot written to [bold]{out}[/bold]")
    if render_to:
        _render(snap, render_to, ["pdf", "docx", "html"], ["asbuilt", "summary"], False)


@app.command("import")
def import_(
    paths: list[Path] = typer.Argument(..., exists=True,
                                       help="Config files, folders (recursive) or .zip archives"),
    driver: str | None = typer.Option(None, "--driver", "-d", help="Driver id; default: detect per file"),
    out: Path = typer.Option(Path("snapshot.json"), "--out", "-o"),
    append: bool = typer.Option(False, help="Add to an existing snapshot instead of replacing it"),
    site: str | None = typer.Option(None),
    customer: str | None = typer.Option(None),
):
    """Import exported config files, e.g. a folder of 20 switch configs (no device access needed)."""
    from sextant.analysis import analyze
    from sextant.model import Snapshot
    from sextant.pipeline import import_many, load_snapshot, save_snapshot

    snap = load_snapshot(out) if append and out.exists() else Snapshot()
    if customer:
        snap.info.customer = customer
    if site:
        snap.info.site = site
    with console.status("Importing…") as status:
        devices, errors = import_many(paths, driver, site,
                                      progress=lambda f, d, h: status.update(f"{f} → {h} ({d})"))
    names = {d.hostname for d in devices}
    snap.devices = [d for d in snap.devices if d.hostname not in names] + devices
    snap.errors = [e for e in snap.errors if e.split(":")[0] not in names] + errors
    save_snapshot(analyze(snap), out)
    _print_snapshot(snap)
    console.print(f"Snapshot written to [bold]{out}[/bold]")


def _render(snap, out: Path, formats: list[str], kinds: list[str], include_raw: bool,
            theme: str | None = None) -> None:
    from sextant.render import render_all

    with console.status("Rendering…"):
        paths = render_all(snap, out, tuple(formats), tuple(kinds), include_raw=include_raw, theme=theme)
    for p in paths:
        console.print(f"  [green]✓[/green] {p}")


@app.command()
def render(
    snapshots: list[Path] = typer.Argument(..., exists=True, help="One or more snapshot JSON files (merged)"),
    out: Path = typer.Option(Path("out"), "--out", "-o", help="Output folder"),
    fmt: list[str] = typer.Option(["pdf", "docx", "html"], "--format", "-f", help="pdf, docx and/or html"),
    kind: list[str] = typer.Option(["asbuilt", "summary"], "--kind", "-k", help="asbuilt and/or summary"),
    customer: str | None = typer.Option(None),
    site: str | None = typer.Option(None),
    author: str | None = typer.Option(None),
    doc_version: str | None = typer.Option(None, "--doc-version"),
    include_raw: bool = typer.Option(False, help="Append redacted configs as an appendix"),
    theme: str | None = typer.Option(None, "--theme", "-t", help="Theme name or folder (see `sextant themes`)"),
):
    """Render As-Built and Summary documents (PDF, Word, HTML) from snapshot(s)."""
    from sextant.pipeline import load_snapshot, merge

    snap = merge([load_snapshot(p) for p in snapshots])
    for key, val in (("customer", customer), ("site", site), ("author", author), ("version", doc_version)):
        if val:
            setattr(snap.info, key, val)
    _render(snap, out, fmt, kind, include_raw, theme)


@app.command()
def themes():
    """List available branding themes."""
    from sextant.theme import available, load_theme, search_dirs

    t = Table()
    for c in ("Theme", "Name", "Company", "Folder"):
        t.add_column(c)
    for name in available():
        th = load_theme(name)
        t.add_row(name, th.name, th.company, str(th.path))
    console.print(t)
    console.print(f"Search path: {', '.join(str(d) for d in search_dirs())} (set SEXTANT_THEMES_DIR to add one)")


@app.command("theme-init")
def theme_init(
    name: str = typer.Argument(..., help="New theme name, e.g. a customer short name"),
    base: str = typer.Option("hybrid", "--from", help="Theme to copy"),
    directory: Path = typer.Option(Path("themes"), "--dir", help="Where to create the theme folder"),
):
    """Create a new theme folder to edit (theme.yaml + logos + fonts)."""
    from sextant.theme import init_theme

    dest = init_theme(name, directory, base)
    console.print(f"Created [bold]{dest}[/bold]. Edit theme.yaml and replace the logo files, then render with "
                  f"`sextant render snapshot.json --theme {dest}` or set SEXTANT_THEMES_DIR={directory.resolve()}.")


@app.command()
def drivers():
    """List available drivers."""
    from sextant.drivers import load_all

    t = Table()
    for c in ("Driver id", "Platform", "Methods"):
        t.add_column(c)
    for d in sorted(load_all().values(), key=lambda x: x.id):
        t.add_row(d.id, d.label, ", ".join(d.methods))
    console.print(t)


@app.command()
def web(host: str = typer.Option("0.0.0.0"), port: int = typer.Option(8080), reload: bool = False):
    """Start the web UI (needs SEXTANT_ADMIN_USER / SEXTANT_ADMIN_PASSWORD)."""
    import uvicorn

    uvicorn.run("sextant.web.app:create_app", factory=True, host=host, port=port, reload=reload,
                proxy_headers=True)


@app.command()
def version():
    console.print(f"sextant {__version__}")


if __name__ == "__main__":
    app()
