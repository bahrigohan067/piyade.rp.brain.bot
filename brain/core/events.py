"""Olay (Event) ve olay kaydı (Incident) veri yapıları."""
from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any

SEVERITIES = ("info", "warning", "critical")
SEV_ORDER = {"info": 0, "warning": 1, "critical": 2}
SEV_EMOJI = {"info": "🟡", "warning": "🟠", "critical": "🔴"}
SEV_LABEL = {"info": "Bilgi", "warning": "Uyarı", "critical": "Kritik"}


def max_sev(a: str, b: str) -> str:
    return a if SEV_ORDER.get(a, 0) >= SEV_ORDER.get(b, 0) else b


@dataclass
class Event:
    """Bir toplayıcının ürettiği tek gözlem."""

    source: str  # railway | agent | heartbeat | web | discord | security | brain
    bot: str  # registry anahtarı, "site", "guild", "erlc" ...
    kind: str  # log | exception | deploy | status | metric | http | audit | raid ...
    message: str
    severity: str = "info"
    ts: float = field(default_factory=time.time)
    data: dict[str, Any] = field(default_factory=dict)

    # Kurallar / analiz tarafından doldurulur
    category: str | None = None
    module: str | None = None
    fingerprint: str | None = None
    title: str | None = None
    cause: str | None = None
    suggestion: str | None = None
    min_count: int = 1
    window: int = 300

    # Durum tabanlı kontroller (nabız, site, ses) için
    incident_key: str | None = None
    resolves: bool = False  # True ise bu olay ilgili kaydı kapatır
    sticky: bool = False  # True ise sessizlikle otomatik kapanmaz


@dataclass
class Incident:
    """Aynı sorunun tekilleştirilmiş kaydı. DM tek mesaj olarak güncellenir."""

    id: int
    key: str
    bot: str
    category: str
    title: str
    severity: str
    first_seen: float
    last_seen: float
    module: str | None = None
    fingerprint: str | None = None
    cause: str | None = None
    suggestion: str | None = None
    count: int = 1
    status: str = "open"  # open | resolved
    sticky: bool = False
    root_id: int | None = None
    children: list[int] = field(default_factory=list)
    shared_note: str | None = None
    dm_message_id: int | None = None
    ai: dict[str, Any] | None = None
    ai_pending: bool = False
    resolution: str | None = None
    resolved_at: float | None = None
    samples: deque = field(default_factory=lambda: deque(maxlen=8))
    data: dict[str, Any] = field(default_factory=dict)
    pause_module: str | None = None
    action_taken: str | None = None
    dismissed: bool = False
    muted_until: float = 0.0
    last_dm_edit: float = 0.0
    dm_dirty: bool = False

    @property
    def is_open(self) -> bool:
        return self.status == "open"
