"""GitHub Salt-Okuma İnceleyici.

Hata stack trace'inde geçen dosya ve satırı GitHub'dan okur,
ayrıca son commit zamanını ve mesajını çekerek "hata şu commit'ten sonra başladı"
teşhisini mümkün kılar. Yalnızca GET istekleri yapar.
"""
from __future__ import annotations

import base64
import logging
import time
from typing import Any

import aiohttp

from brain.config.settings import Settings

log = logging.getLogger("brain.github")


class GitHubInspector:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._cache: dict[str, tuple[float, Any]] = {}
        self._ttl = 300  # 5 dakika önbellek

    def _headers(self) -> dict[str, str]:
        h = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "PiyadeRP-BrainBot/1.0",
        }
        if self.settings.github_token:
            h["Authorization"] = f"Bearer {self.settings.github_token}"
        return h

    def _get_cached(self, key: str) -> Any | None:
        item = self._cache.get(key)
        if item and (time.time() - item[0]) < self._ttl:
            return item[1]
        return None

    def _set_cached(self, key: str, val: Any) -> None:
        self._cache[key] = (time.time(), val)

    async def fetch_snippet(
        self,
        repo: str | None,
        file_path: str | None,
        line: int | None,
        *,
        context: int = 10,
    ) -> str | None:
        if not repo or not file_path or not line:
            return None
        clean_path = file_path.lstrip("/")
        cache_key = f"snip:{repo}:{clean_path}:{line}"
        cached = self._get_cached(cache_key)
        if cached is not None:
            return cached

        url = f"https://api.github.com/repos/{repo}/contents/{clean_path}"
        params = {"ref": self.settings.github_branch}
        timeout = aiohttp.ClientTimeout(total=8)
        try:
            async with aiohttp.ClientSession(timeout=timeout, headers=self._headers()) as session:
                async with session.get(url, params=params) as resp:
                    if resp.status != 200:
                        return None
                    data = await resp.json()
                    content_b64 = data.get("content") or ""
                    raw_text = base64.b64decode(content_b64).decode("utf-8", errors="replace")
                    lines = raw_text.splitlines()
                    start = max(1, line - context)
                    end = min(len(lines), line + context)
                    out_lines = []
                    for idx in range(start, end + 1):
                        marker = ">>>" if idx == line else "   "
                        out_lines.append(f"{marker} {idx:4d} | {lines[idx - 1]}")
                    snippet = "\n".join(out_lines)
                    self._set_cached(cache_key, snippet)
                    return snippet
        except Exception as exc:
            log.debug("GitHub dosya okuma hatası (%s/%s): %s", repo, clean_path, exc)
            return None

    async def fetch_latest_commit(self, repo: str | None) -> str | None:
        if not repo:
            return None
        cache_key = f"commit:{repo}"
        cached = self._get_cached(cache_key)
        if cached is not None:
            return cached

        url = f"https://api.github.com/repos/{repo}/commits"
        params = {"per_page": "1", "sha": self.settings.github_branch}
        timeout = aiohttp.ClientTimeout(total=8)
        try:
            async with aiohttp.ClientSession(timeout=timeout, headers=self._headers()) as session:
                async with session.get(url, params=params) as resp:
                    if resp.status != 200:
                        return None
                    arr = await resp.json()
                    if not isinstance(arr, list) or not arr:
                        return None
                    c = arr[0]
                    sha = str(c.get("sha") or "")[:7]
                    commit_obj = c.get("commit") or {}
                    msg = str(commit_obj.get("message") or "").splitlines()[0][:140]
                    date_str = str((commit_obj.get("author") or {}).get("date") or "")
                    summary = f"`{sha}` — {msg} ({date_str})"
                    self._set_cached(cache_key, summary)
                    return summary
        except Exception as exc:
            log.debug("GitHub son commit okuma hatası (%s): %s", repo, exc)
            return None
