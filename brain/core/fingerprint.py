"""Hata parmak izi (fingerprint) ve stack trace ayrıştırıcı.

Aynı hatanın binlerce kez gelmesi durumunda:
- Değişken sayıları, bellek adresleri ve zaman damgaları normalize edilir.
- Sabit bir 12 karakterlik SHA-256 parmak izi üretilir.
- Python ve Node.js traceback'lerinden etkilenen dosya, satır ve modül (`cogs/<modül>.py`) çıkarılır.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

# Python: File "/app/cogs/vs_talep.py", line 88, in callback
_PY_FRAME = re.compile(r'File "([^"]+)", line (\d+), in ([^\s\n]+)')
# Node.js: at Object.<anonymous> (/app/src/guards/channelGuard.js:42:15)
_NODE_FRAME = re.compile(r"at (?:([^\s(]+) \()?([^():\s]+\.(?:js|ts|mjs|cjs)):(\d+)(?::\d+)?\)?")
# Cog adı: cogs/vs_talep.py veya cogs.vs_talep
_COG_PATH = re.compile(r"(?:cogs[/\\.]|modules[/\\.])([a-zA-Z0-9_]+?)(?:\.py|\.js|\b)")

_HEX_ADDR = re.compile(r"0x[0-9a-fA-F]+")
_ISO_TS = re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b")
_NUMBERS = re.compile(r"\b\d+\b")
_WHITESPACE = re.compile(r"\s+")

# Standart kütüphane / paket yolları (uygulama kodunu bulmak için atlanır)
_IGNORE_PATH_PARTS = (
    "site-packages",
    "dist-packages",
    "node_modules",
    "/usr/lib/python",
    "\\lib\\python",
    "<frozen ",
    "internal/modules",
    "node:internal",
)


@dataclass
class TraceLocation:
    file: str
    line: int
    func: str | None = None
    module: str | None = None

    def short(self) -> str:
        return f"{self.file}:{self.line}"


def _clean_repo_path(raw_path: str) -> str:
    p = raw_path.replace("\\", "/")
    for marker in ("/app/", "/workspace/", "/src/"):
        if marker in p:
            idx = p.rfind(marker)
            p = p[idx + 1 :] if marker == "/src/" else p[idx + len(marker) :]
    # Yerel tam yollarda repo kökünden sonrasını al
    for folder in ("cogs/", "src/", "utils/", "core/"):
        if folder in p and not p.startswith(folder):
            p = p[p.rfind(folder) :]
            break
    return p.lstrip("/")


def extract_location(text: str) -> TraceLocation | None:
    """Stack trace içinden uygulama koduna ait en son (en iç) dosya ve satırı bulur."""
    if not text:
        return None

    candidates: list[TraceLocation] = []

    for m in _PY_FRAME.finditer(text):
        raw_file, line_str, func = m.group(1), m.group(2), m.group(3)
        if any(ign in raw_file for ign in _IGNORE_PATH_PARTS):
            continue
        clean = _clean_repo_path(raw_file)
        mod_match = _COG_PATH.search(clean)
        candidates.append(
            TraceLocation(
                file=clean,
                line=int(line_str),
                func=func,
                module=mod_match.group(1) if mod_match else None,
            )
        )

    for m in _NODE_FRAME.finditer(text):
        func, raw_file, line_str = m.group(1), m.group(2), m.group(3)
        if any(ign in raw_file for ign in _IGNORE_PATH_PARTS):
            continue
        clean = _clean_repo_path(raw_file)
        candidates.append(
            TraceLocation(
                file=clean,
                line=int(line_str),
                func=func,
                module=None,
            )
        )

    return candidates[-1] if candidates else None


def infer_module(text: str, known_modules: list[str] | None = None) -> str | None:
    """Log veya traceback metninden ilgili cog/modül adını çıkarır."""
    if not text:
        return None
    m = _COG_PATH.search(text)
    if m:
        cand = m.group(1)
        if not known_modules or cand in known_modules:
            return cand
    if known_modules:
        lower = text.lower()
        for mod in known_modules:
            if f"{mod}.py" in lower or f"cogs.{mod}" in lower or f"/{mod}" in lower:
                return mod
    return None


def normalize_for_fingerprint(text: str) -> str:
    s = _ISO_TS.sub("", text or "")
    s = _HEX_ADDR.sub("0x?", s)
    s = _NUMBERS.sub("#", s)
    s = _WHITESPACE.sub(" ", s).strip().lower()
    return s[:600]


def make_fingerprint(bot: str, category: str, text: str, location: TraceLocation | None = None) -> str:
    """Bot + kategori + (varsa dosya:satır, yoksa normalize metin) üzerinden 12 haneli parmak izi."""
    loc_part = f"{location.file}:{location.line}" if location else normalize_for_fingerprint(text)[:240]
    raw = f"{bot}|{category}|{loc_part}"
    return hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()[:12]
