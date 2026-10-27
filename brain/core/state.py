"""Beyin'in çalışma zamanı canlı durum deposu (WorldState).

Tüm toplayıcılar gözlemlerini buraya yazar; `/durum`, `/bot`, `/rapor` komutları ve
korelasyon motoru buradan okur.
"""
from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any

from brain.core.events import Incident


@dataclass
class BotHealth:
    key: str
    name: str
    # Railway durumu: SUCCESS | BUILDING | CRASHED | FAILED | DEPLOYING | UNKNOWN
    deploy_status: str = "UNKNOWN"
    last_deploy_ts: float = 0.0
    last_deploy_id: str | None = None
    last_commit_sha: str | None = None
    restart_timestamps: deque = field(default_factory=lambda: deque(maxlen=20))

    # Discord & Ajan nabzı
    discord_online: bool | None = None
    last_heartbeat_ts: float = 0.0
    ping_ms: float | None = None
    ram_mb: float | None = None
    loop_lag_ms: float | None = None
    loaded_cogs: list[str] = field(default_factory=list)
    failed_cogs: dict[str, str] = field(default_factory=dict)
    paused_modules: set[str] = field(default_factory=set)
    queue_size: int = 0
    last_command_ts: float = 0.0

    # Ses ve periyodik görev izleme
    in_expected_voice: bool | None = None
    voice_miss_count: int = 0
    periodic_last_seen: dict[str, float] = field(default_factory=dict)
    scheduled_last_seen: dict[str, str] = field(default_factory=dict)  # name -> "YYYY-MM-DD"

    # Log tamponu (son 200 satır, temizlenmiş) ve sayaçlar
    recent_logs: deque = field(default_factory=lambda: deque(maxlen=200))
    error_timestamps: deque = field(default_factory=lambda: deque(maxlen=500))
    rate_limit_timestamps: deque = field(default_factory=lambda: deque(maxlen=200))
    last_error_text: str | None = None
    last_error_ts: float = 0.0

    def record_log(self, line: str) -> None:
        self.recent_logs.append(line)

    def record_error(self, msg: str, now: float | None = None) -> None:
        ts = now or time.time()
        self.error_timestamps.append(ts)
        self.last_error_text = msg[:300]
        self.last_error_ts = ts

    def record_restart(self, now: float | None = None) -> int:
        ts = now or time.time()
        self.restart_timestamps.append(ts)
        cutoff = ts - 600
        return sum(1 for t in self.restart_timestamps if t >= cutoff)

    def errors_last_hour(self, now: float | None = None) -> int:
        cutoff = (now or time.time()) - 3600
        return sum(1 for t in self.error_timestamps if t >= cutoff)

    def errors_last_24h(self, now: float | None = None) -> int:
        cutoff = (now or time.time()) - 86400
        return sum(1 for t in self.error_timestamps if t >= cutoff)

    def overall_badge(self, heartbeat_timeout: int = 90) -> tuple[str, str]:
        """(emoji, durum_metni) döndürür."""
        now = time.time()
        if self.deploy_status in ("CRASHED", "FAILED"):
            return "🔴", f"Çöktü ({self.deploy_status})"
        if self.last_heartbeat_ts > 0 and (now - self.last_heartbeat_ts) > heartbeat_timeout:
            return "🔴", f"Nabız yok ({int(now - self.last_heartbeat_ts)} sn)"
        if self.discord_online is False:
            return "🔴", "Discord'da çevrimdışı"
        if self.failed_cogs:
            return "🟠", f"{len(self.failed_cogs)} modül yüklenemedi"
        if self.paused_modules:
            return "🟠", f"{len(self.paused_modules)} modül duraklatıldı"
        if self.loop_lag_ms and self.loop_lag_ms > 500:
            return "🟠", f"Gecikme ({int(self.loop_lag_ms)} ms)"
        if self.deploy_status == "BUILDING":
            return "🟡", "Derleniyor (BUILDING)"
        if self.last_heartbeat_ts > 0 or self.discord_online is True or self.deploy_status == "SUCCESS":
            return "🟢", "Normal"
        return "⚪", "Veri bekleniyor"


@dataclass
class EndpointResult:
    name: str
    path: str
    ok: bool
    status_code: int
    latency_ms: float
    checked_at: float
    error: str | None = None


@dataclass
class SiteHealth:
    base_url: str
    endpoints: dict[str, EndpointResult] = field(default_factory=dict)
    ssl_days_left: int | None = None
    consecutive_failures: int = 0
    last_check_ts: float = 0.0

    def overall_badge(self) -> tuple[str, str]:
        if not self.endpoints:
            return "⚪", "Kontrol edilmedi"
        bad = [e for e in self.endpoints.values() if not e.ok]
        if bad:
            names = ", ".join(e.name for e in bad[:3])
            return ("🔴" if self.consecutive_failures >= 2 else "🟠"), f"Hata: {names}"
        avg_ms = sum(e.latency_ms for e in self.endpoints.values()) / len(self.endpoints)
        if self.ssl_days_left is not None and self.ssl_days_left < 7:
            return "🟠", f"SSL {self.ssl_days_left} gün kaldı"
        return "🟢", f"Normal ({int(avg_ms)} ms)"


@dataclass
class ErlcHealth:
    connected: bool | None = None
    current_players: int = 0
    max_players: int = 0
    queue_count: int = 0
    rate_limit_hits: deque = field(default_factory=lambda: deque(maxlen=200))
    last_429_ts: float = 0.0
    last_check_ts: float = 0.0

    def record_429(self, now: float | None = None) -> int:
        ts = now or time.time()
        self.last_429_ts = ts
        self.rate_limit_hits.append(ts)
        cutoff = ts - 180
        return sum(1 for t in self.rate_limit_hits if t >= cutoff)

    def hits_last_3m(self, now: float | None = None) -> int:
        cutoff = (now or time.time()) - 180
        return sum(1 for t in self.rate_limit_hits if t >= cutoff)


class WorldState:
    """Tüm ekosistemin anlık durumu."""

    def __init__(self, bot_specs: dict[str, Any], site_base_url: str = "") -> None:
        self.started_at = time.time()
        self.bots: dict[str, BotHealth] = {
            k: BotHealth(key=k, name=spec.name) for k, spec in bot_specs.items()
        }
        self.site = SiteHealth(base_url=site_base_url)
        self.erlc = ErlcHealth()
        self.incidents: dict[str, Incident] = {}  # incident.key -> Incident
        self.incidents_by_id: dict[int, Incident] = {}
        self.unmatched_railway_services: set[str] = set()
        self.maintenance_until: float = 0.0
        self.quiet_until: float = 0.0
        self.auto_action_timestamps: deque = field(default_factory=Deque) if False else deque(maxlen=100)

    def bot(self, key: str) -> BotHealth:
        if key not in self.bots:
            self.bots[key] = BotHealth(key=key, name=key)
        return self.bots[key]

    @property
    def in_maintenance(self) -> bool:
        return time.time() < self.maintenance_until

    @property
    def is_quiet(self) -> bool:
        return time.time() < self.quiet_until

    def open_incidents(self) -> list[Incident]:
        return [inc for inc in self.incidents.values() if inc.is_open]
