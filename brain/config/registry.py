"""registry.yaml dosyasını tipli nesnelere çevirir."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass
class ScheduledMessage:
    name: str
    channel_id: int
    time: str  # "HH:MM" TSİ
    grace_minutes: int = 5
    contains: list[str] = field(default_factory=list)
    module: str | None = None


@dataclass
class PeriodicLog:
    name: str
    pattern: str
    every_minutes: int
    grace_minutes: int = 10


@dataclass
class BotSpec:
    key: str
    name: str
    repo: str | None = None
    lang: str = "python"
    railway_service: str | None = None
    discord_bot_id: int | None = None
    agent_installed: bool = False  # Varsayılan False: brain_agent.py eklenmeden donma alarmı üretilmez
    expects_volume: bool = False   # data/ klasöründe kalıcı veri tutuyorsa True
    modules: list[str] = field(default_factory=list)
    critical: list[str] = field(default_factory=list)
    auto_pausable: list[str] = field(default_factory=list)
    startup_markers: list[str] = field(default_factory=list)
    dependencies: list[str] = field(default_factory=list)
    voice_presence: dict[str, Any] | None = None
    scheduled_messages: list[ScheduledMessage] = field(default_factory=list)
    expect_periodic: list[PeriodicLog] = field(default_factory=list)
    ticket_contract: dict[str, Any] | None = None
    ram_limit_mb: int = 450

    def is_critical(self, module: str | None) -> bool:
        if "*" in self.critical:
            return True
        return bool(module) and module in self.critical

    def can_auto_pause(self, module: str | None) -> bool:
        return bool(module) and module in self.auto_pausable and not self.is_critical(module)


@dataclass
class SiteCheck:
    name: str
    path: str
    expect: list[int] = field(default_factory=lambda: [200])
    expect_not_5xx: bool = False
    critical: bool = False
    json_erlc: bool = False


@dataclass
class SiteSpec:
    key: str
    name: str
    base_url: str
    repo: str | None = None
    railway_service: str | None = None
    checks: list[SiteCheck] = field(default_factory=list)


@dataclass
class Registry:
    bots: dict[str, BotSpec]
    site: SiteSpec | None

    def get(self, key: str) -> BotSpec | None:
        return self.bots.get(key)

    def display(self, key: str) -> str:
        if key in self.bots:
            return self.bots[key].name
        if self.site and key == self.site.key:
            return self.site.name
        return {"guild": "Discord Sunucusu", "erlc": "ER:LC API", "brain": "Beyin", "railway": "Railway"}.get(key, key)

    def by_discord_id(self, user_id: int) -> BotSpec | None:
        for b in self.bots.values():
            if b.discord_bot_id and b.discord_bot_id == user_id:
                return b
        return None

    def by_railway_service(self, name: str) -> str | None:
        n = name.strip().lower()
        for b in self.bots.values():
            if b.railway_service and b.railway_service.strip().lower() == n:
                return b.key
        if self.site and self.site.railway_service and self.site.railway_service.strip().lower() == n:
            return self.site.key
        return None

    def repo_of(self, key: str) -> str | None:
        if key in self.bots:
            return self.bots[key].repo
        if self.site and key == self.site.key:
            return self.site.repo
        return None

    def known_bot_ids(self) -> set[int]:
        return {b.discord_bot_id for b in self.bots.values() if b.discord_bot_id}


def _opt_int(v: Any) -> int | None:
    try:
        return int(v) if v not in (None, "", 0) else None
    except (TypeError, ValueError):
        return None


def load_registry(path: str) -> Registry:
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    bots: dict[str, BotSpec] = {}
    for key, b in (raw.get("bots") or {}).items():
        b = b or {}
        bots[key] = BotSpec(
            key=key,
            name=b.get("name") or key,
            repo=b.get("repo"),
            lang=b.get("lang", "python"),
            railway_service=b.get("railway_service"),
            discord_bot_id=_opt_int(b.get("discord_bot_id")),
            agent_installed=bool(b.get("agent_installed", False)),
            expects_volume=bool(b.get("expects_volume", False)),
            modules=list(b.get("modules") or []),
            critical=list(b.get("critical") or []),
            auto_pausable=list(b.get("auto_pausable") or []),
            startup_markers=list(b.get("startup_markers") or []),
            dependencies=list(b.get("dependencies") or []),
            voice_presence=b.get("voice_presence"),
            scheduled_messages=[ScheduledMessage(**m) for m in (b.get("scheduled_messages") or [])],
            expect_periodic=[PeriodicLog(**p) for p in (b.get("expect_periodic") or [])],
            ticket_contract=b.get("ticket_contract"),
            ram_limit_mb=int(b.get("ram_limit_mb") or 450),
        )

    site = None
    s = raw.get("site")
    if s:
        site = SiteSpec(
            key="site",
            name=s.get("name") or "Site",
            base_url=(s.get("base_url") or "").rstrip("/"),
            repo=s.get("repo"),
            railway_service=s.get("railway_service"),
            checks=[SiteCheck(**c) for c in (s.get("checks") or [])],
        )
    return Registry(bots=bots, site=site)
