"""Themes: every brand-specific value (names, colours, fonts, logos) lives in a theme folder.

A theme is a directory with a `theme.yaml` and its assets:

    themes/acme/
      theme.yaml        # see themes/hybrid/theme.yaml for every key
      logo-color.png    # logo for light backgrounds (cover, page header)
      logo-white.png    # optional, logo for dark backgrounds (web top bar, HTML sidebar)
      fonts/*.ttf       # optional, embedded in PDF/HTML

Lookup order for a theme reference: an existing directory path, then
$SEXTANT_THEMES_DIR/<name>, then the built-in themes. Asset paths in theme.yaml are
relative to the theme folder, falling back to the shared `themes/_fonts` folder.
Run `sextant theme-init <name>` to start a new theme from an existing one.
"""

from __future__ import annotations

import os
import shutil
from functools import cache
from pathlib import Path

import yaml
from pydantic import BaseModel, Field

BUILTIN = Path(__file__).parent / "themes"
SHARED = BUILTIN / "_fonts"
DEFAULT = "hybrid"


class Colors(BaseModel):
    primary: str = "#1d2542"  # headings, cover, table captions, web top bar
    accent: str = "#0099d4"  # gradient end, focus ring, links
    highlight: str = "#eb5e1d"  # thin accent bands, active navigation (never body text)
    text: str = "#2c2d2d"
    on_primary: str = "#ffffff"  # text on primary/gradient surfaces
    on_primary_muted: str = "#d9dce6"
    gray_50: str = "#f5f6f9"  # table headers, subtle surfaces
    gray_100: str = "#eceef3"
    gray_200: str = "#dcdfe7"  # dividers
    gray_500: str = "#6b7387"  # control borders
    gray_600: str = "#4e566a"  # muted text
    gray_700: str = "#363d50"
    success: str = "#1e7a46"
    success_bg: str = "#e6f4ec"
    warning: str = "#8f5e00"
    warning_bg: str = "#fdf3dc"
    warning_border: str = "#d99a00"
    error: str = "#b42318"
    error_bg: str = "#fdecea"
    info: str = "#00709c"
    info_bg: str = "#e5f4fb"

    def css_vars(self) -> str:
        return "; ".join(f"--{k.replace('_', '-')}: {v}" for k, v in self.model_dump().items())

    def hex(self, name: str) -> str:
        """'primary' -> '1D2542' (for python-docx)."""
        return getattr(self, name).lstrip("#").upper()


class Fonts(BaseModel):
    family: str = "Open Sans"
    fallback: str = "Helvetica, Arial, sans-serif"
    mono: str = "DejaVu Sans Mono"
    # weight[-italic] -> font file, e.g. {"400": "fonts/OpenSans-Regular.ttf", "400-italic": ...}
    files: dict[str, str] = Field(default_factory=dict)
    word_body_pt: float = 10
    word_heading_pt: list[float] = Field(default_factory=lambda: [20, 18, 14, 12])

    @property
    def stack(self) -> str:
        return f'"{self.family}", {self.fallback}'


class Logos(BaseModel):
    color: str | None = None  # on light backgrounds
    white: str | None = None  # on dark backgrounds
    symbol: str | None = None  # favicon / small mark


class Theme(BaseModel):
    id: str = DEFAULT
    name: str = "Hybrid Solutions"
    company: str = "Hybrid Solutions AB"  # document author / owner
    product: str = "Sextant"  # web UI name
    tagline: str = "Know exactly where your infrastructure stands."
    colors: Colors = Field(default_factory=Colors)
    fonts: Fonts = Field(default_factory=Fonts)
    logos: Logos = Field(default_factory=Logos)
    cover_gradient: bool = True  # primary -> accent; False = flat primary
    path: Path | None = Field(default=None, exclude=True)

    def asset(self, rel: str | None) -> Path | None:
        """Resolve an asset path from theme.yaml (theme folder first, then shared fonts)."""
        if not rel:
            return None
        for base in filter(None, [self.path, SHARED]):
            p = (base / rel).resolve()
            if p.is_file() and (base.resolve() in p.parents):
                return p
        return None

    def font_faces(self) -> list[tuple[str, str, str]]:
        """[(weight, style, relative file)] for files that exist."""
        out = []
        for key, rel in self.fonts.files.items():
            weight, _, style = key.partition("-")
            if self.asset(rel):
                out.append((weight, style or "normal", rel))
        return out


def search_dirs() -> list[Path]:
    dirs = []
    if os.environ.get("SEXTANT_THEMES_DIR"):
        dirs.append(Path(os.environ["SEXTANT_THEMES_DIR"]))
    dirs.append(BUILTIN)
    return dirs


def _find(ref: str) -> Path:
    p = Path(ref).expanduser()
    if (p / "theme.yaml").is_file():
        return p
    if "/" not in ref and "\\" not in ref:
        for d in search_dirs():
            if (d / ref / "theme.yaml").is_file():
                return d / ref
    raise FileNotFoundError(f"Theme '{ref}' not found. Available: {', '.join(available()) or 'none'}")


@cache
def _load(path: str) -> Theme:
    p = Path(path)
    data = yaml.safe_load((p / "theme.yaml").read_text()) or {}
    data.setdefault("id", p.name)
    theme = Theme.model_validate(data)
    theme.path = p
    return theme


def load_theme(ref: str | Path | None = None) -> Theme:
    """Theme by folder path or name; default from $SEXTANT_THEME, else 'hybrid'."""
    ref = str(ref or os.environ.get("SEXTANT_THEME") or DEFAULT)
    return _load(str(_find(ref).resolve()))


def available() -> list[str]:
    names: list[str] = []
    for d in search_dirs():
        if d.is_dir():
            names += [c.name for c in sorted(d.iterdir()) if (c / "theme.yaml").is_file() and c.name not in names]
    return names


def init_theme(name: str, dest_dir: Path, base: str = DEFAULT) -> Path:
    """Copy a theme (including shared fonts it uses) into dest_dir/name as a self-contained starting point."""
    src = load_theme(base)
    assert src.path
    dest = dest_dir / name
    if dest.exists():
        raise FileExistsError(f"{dest} already exists")
    shutil.copytree(src.path, dest)
    for rel in src.fonts.files.values():
        f = src.asset(rel)
        if f and not (dest / rel).exists():
            (dest / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(f, dest / rel)
    text = (dest / "theme.yaml").read_text()
    lines = [ln for ln in text.splitlines() if not ln.startswith("id:")]
    (dest / "theme.yaml").write_text(f"id: {name}\n" + "\n".join(lines) + "\n")
    return dest
