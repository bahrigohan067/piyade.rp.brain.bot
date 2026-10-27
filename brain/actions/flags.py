"""Modüler Bayrak (Feature Flag) ve 3-Durumlu Devre Kesici (Circuit Breaker) Sistemi.

Devre Kesici Mantığı (Bölüm 5.2):
- `CLOSED` (Normal) -> 2 dakikada 5 hata -> `OPEN` (Duraklatıldı / `PAUSED`)
- `OPEN` -> 5 dakika bekle (`cooldown`) -> `HALF_OPEN` (Tek deneme / `ACTIVE`)
- `HALF_OPEN` -> 60 saniye hatasız geçerse -> `CLOSED` (Normal)
- `HALF_OPEN` -> Deneme sırasında hata gelirse -> `OPEN` (Bekleme süresi 2 katına çıkar: 5dk -> 10dk -> 20dk, maks 60dk)

Ajansız Bot Dürüstlük Kontrolü:
- Bir botta `brain_agent.py` henüz kurulu değilse (`last_heartbeat_ts == 0` ve `agent_installed == False`),
  `set_flag` bayrağı Redis/DB'ye yazar ancak yanıt mesajında açıkça
  "Bu botta henüz ajan aktif olmadığı için bot bayrağı okumuyor" uyarısını döndürür.
"""
from __future__ import annotations

import json
import logging
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any

from brain.config.registry import Registry
from brain.config.settings import Settings
from brain.core.state import WorldState
from brain.memory.db import BrainDB

log = logging.getLogger("brain.flags")


@dataclass
class CircuitBreakerState:
    bot: str
    module: str
    state: str = "CLOSED"  # CLOSED | OPEN | HALF_OPEN
    error_timestamps: deque[float] = field(default_factory=lambda: deque(maxlen=20))
    opened_at: float = 0.0
    half_opened_at: float = 0.0
    cooldown_seconds: float = 300.0  # Başlangıç: 5 dakika (300 sn)
    base_cooldown: float = 300.0
    max_cooldown: float = 3600.0     # Tavan: 60 dakika
    trial_window: float = 60.0       # Yarı açık deneme süresi: 60 sn


class FlagStore:
    def __init__(self, settings: Settings, registry: Registry, db: BrainDB, state: WorldState) -> None:
        self.settings = settings
        self.registry = registry
        self.db = db
        self.state = state
        self._redis: Any = None
        self.redis_connected: bool = False
        # (bot, module) -> "ACTIVE" | "PAUSED"
        self._cache: dict[tuple[str, str], str] = {}
        # (bot, module) -> CircuitBreakerState
        self.breakers: dict[tuple[str, str], CircuitBreakerState] = {}

    def has_active_agent(self, bot: str) -> bool:
        spec = self.registry.get(bot)
        bh = self.state.bots.get(bot)
        return bool((bh and bh.last_heartbeat_ts > 0) or (spec and spec.agent_installed))

    async def connect(self) -> None:
        db_flags = await self.db.get_flags_db()
        for bot_key, mods in db_flags.items():
            for mod, st in mods.items():
                self._cache[(bot_key, mod)] = st
                if st == "PAUSED":
                    self.state.bot(bot_key).paused_modules.add(mod)

        if not self.settings.redis_url:
            return

        try:
            import redis.asyncio as aioredis  # type: ignore

            self._redis = aioredis.from_url(
                self.settings.redis_url,
                decode_responses=True,
                socket_connect_timeout=5,
                socket_timeout=5,
            )
            await self._redis.ping()
            self.redis_connected = True
            log.info("Redis bağlantısı kuruldu (modül bayrakları aktif).")
            for (bot_key, mod), st in list(self._cache.items()):
                await self._redis.set(self._key(bot_key, mod), st)
        except Exception as exc:
            log.warning("Redis bağlantısı kurulamadı (%s), veritabanı/HTTP bayrak modu kullanılacak.", exc)
            self._redis = None
            self.redis_connected = False

    async def close(self) -> None:
        if self._redis is not None:
            try:
                await self._redis.aclose()
            except Exception:
                pass
            self._redis = None
            self.redis_connected = False

    @staticmethod
    def _key(bot: str, module: str) -> str:
        return f"module:{bot}:{module}"

    async def get_state(self, bot: str, module: str) -> str:
        if self._redis is not None and self.redis_connected:
            try:
                val = await self._redis.get(self._key(bot, module))
                if val in ("ACTIVE", "PAUSED"):
                    self._cache[(bot, module)] = val
                    return val
            except Exception:
                pass
        return self._cache.get((bot, module), "ACTIVE")

    async def get_bot_flags(self, bot: str) -> dict[str, str]:
        spec = self.registry.get(bot)
        modules = list(spec.modules) if spec else []
        for b, m in self._cache:
            if b == bot and m not in modules:
                modules.append(m)
        out: dict[str, str] = {}
        for mod in modules:
            out[mod] = await self.get_state(bot, mod)
        return out

    def can_auto_act(self) -> bool:
        now = time.time()
        cutoff = now - 3600
        recent = [t for t in self.state.auto_action_timestamps if t >= cutoff]
        return len(recent) < self.settings.max_auto_actions_per_hour

    async def set_flag(
        self,
        bot: str,
        module: str,
        state: str,
        *,
        actor: str,
        reason: str = "",
        incident_id: int | None = None,
        force: bool = False,
    ) -> tuple[bool, str]:
        """Modül bayrağını `PAUSED` veya `ACTIVE` yapar."""
        state = state.upper().strip()
        if state not in ("ACTIVE", "PAUSED"):
            return False, "Geçersiz durum (ACTIVE veya PAUSED olmalı)."

        spec = self.registry.get(bot)
        if state == "PAUSED" and not force:
            if actor == "auto":
                if not self.settings.auto_actions:
                    return False, "Otomatik eylem modu kapalı (AUTO_ACTIONS=false / Sadece Öner modu)."
                if not spec or not spec.can_auto_pause(module):
                    return False, f"`{bot}:{module}` otomatik duraklatma beyaz listesinde değil."
                if not self.can_auto_act():
                    return False, "Saatlik otomatik eylem sınırına ulaşıldı."
                self.state.auto_action_timestamps.append(time.time())
            elif spec and "*" in spec.critical:
                return False, f"**{spec.name}** kritik koruma altında olduğu için duraklatılamaz."

        self._cache[(bot, module)] = state
        bh = self.state.bot(bot)
        if state == "PAUSED":
            bh.paused_modules.add(module)
        else:
            bh.paused_modules.discard(module)

        if self._redis is not None and self.redis_connected:
            try:
                await self._redis.set(self._key(bot, module), state)
                payload = json.dumps(
                    {
                        "bot": bot,
                        "module": module,
                        "state": state,
                        "reason": reason[:200],
                        "actor": actor,
                        "ts": time.time(),
                    },
                    ensure_ascii=False,
                )
                await self._redis.set(f"module_meta:{bot}:{module}", payload)
            except Exception as exc:
                log.warning("Redis bayrak yazımı başarısız (%s), DB'ye kaydedildi.", exc)

        await self.db.set_flag_db(bot, module, state, reason=reason, updated_by=actor)
        await self.db.log_action(
            actor=actor,
            action="pause_module" if state == "PAUSED" else "resume_module",
            target=f"{bot}:{module}",
            reason=reason,
            incident_id=incident_id,
        )
        action_tr = "duraklatıldı" if state == "PAUSED" else "etkinleştirildi"
        msg = f"`{bot}` → `{module}` modülü **{action_tr}**."
        if not self.has_active_agent(bot):
            msg += (
                f"\n⚠️ **Not:** `{bot}` üzerinde henüz `brain_agent.py` nabzı görülmedi (Salt Okuma Modu). "
                "Bayrak veritabanına/Redis'e yazıldı ancak bota ajan eklenene kadar bot bu bayrağı okumaz."
            )
        return True, msg

    # ── 3-Durumlu Devre Kesici (CLOSED -> OPEN -> HALF_OPEN -> CLOSED) ──
    async def record_circuit_error(
        self,
        bot: str,
        module: str,
        *,
        reason: str,
        incident_id: int | None = None,
        now: float | None = None,
    ) -> tuple[bool, str]:
        """Bir modülde hata oluştuğunda devre kesici durum makinesini ilerletir.

        - `HALF_OPEN` iken hata gelirse bekleme süresi 2 katına çıkarılarak tekrar `OPEN` (`PAUSED`) yapılır.
        - `CLOSED` iken 2 dakikada (120 sn) 5 hata birikirse `OPEN` (`PAUSED`) yapılır.
        """
        ts = now or time.time()
        cb = self.breakers.get((bot, module))
        if cb is None:
            cb = CircuitBreakerState(bot=bot, module=module)
            self.breakers[(bot, module)] = cb

        # YARI AÇIK (HALF_OPEN) denemesinde hata geldiyse -> Bekleme 2 katına çıkar ve tekrar AÇIK olur
        if cb.state == "HALF_OPEN":
            cb.cooldown_seconds = min(cb.cooldown_seconds * 2.0, cb.max_cooldown)
            cb.state = "OPEN"
            cb.opened_at = ts
            ok, msg = await self.set_flag(
                bot,
                module,
                "PAUSED",
                actor="auto",
                reason=f"Yarı-açık deneme başarısız (yeni bekleme: {int(cb.cooldown_seconds // 60)} dk) — {reason}",
                incident_id=incident_id,
            )
            return ok, msg

        if cb.state == "OPEN":
            return False, "Devre kesici zaten AÇIK (OPEN)."

        # KAPALI (CLOSED) -> Son 2 dakikadaki (120 sn) hataları say
        cb.error_timestamps.append(ts)
        cutoff = ts - 120.0
        while cb.error_timestamps and cb.error_timestamps[0] < cutoff:
            cb.error_timestamps.popleft()

        if len(cb.error_timestamps) >= 5:
            cb.state = "OPEN"
            cb.opened_at = ts
            cb.cooldown_seconds = cb.base_cooldown
            ok, msg = await self.set_flag(
                bot,
                module,
                "PAUSED",
                actor="auto",
                reason=f"Devre kesici: 2 dk'da {len(cb.error_timestamps)} hata — {reason}",
                incident_id=incident_id,
            )
            if not ok:
                # Otomatik eylem kapalıysa ("Sadece Öner" modu) durumu CLOSED'da bırak
                cb.state = "CLOSED"
            return ok, msg

        return False, "Hata eşiği (5 hata / 2 dk) henüz dolmadı."

    async def tick_circuit_breakers(self, now: float | None = None) -> list[str]:
        """Periyodik olarak çağrılır:
        - `OPEN` süresi (`cooldown_seconds`) dolan devre kesicileri `HALF_OPEN` (deneme) durumuna alır (`ACTIVE`).
        - `HALF_OPEN` durumunda `trial_window` (60 sn) boyunca hata almayanları `CLOSED` (tam normal) yapar.
        """
        ts = now or time.time()
        transitions: list[str] = []

        for (bot, mod), cb in list(self.breakers.items()):
            if cb.state == "OPEN" and (ts - cb.opened_at) >= cb.cooldown_seconds:
                cb.state = "HALF_OPEN"
                cb.half_opened_at = ts
                await self.set_flag(
                    bot,
                    mod,
                    "ACTIVE",
                    actor="auto",
                    reason=f"Devre kesici YARI AÇIK (HALF_OPEN): {int(cb.cooldown_seconds // 60)} dk bekleme doldu, tek deneme.",
                    force=True,
                )
                transitions.append(f"{bot}:{mod} -> HALF_OPEN")

            elif cb.state == "HALF_OPEN" and (ts - cb.half_opened_at) >= cb.trial_window:
                cb.state = "CLOSED"
                cb.cooldown_seconds = cb.base_cooldown
                cb.error_timestamps.clear()
                transitions.append(f"{bot}:{mod} -> CLOSED")

        return transitions

    async def read_redis_heartbeats(self) -> dict[str, dict[str, Any]]:
        """Ajanlar Redis'e `heartbeat:<bot>` yazıyorsa onları okur."""
        if self._redis is None or not self.redis_connected:
            return {}
        out: dict[str, dict[str, Any]] = {}
        for bot_key in self.registry.bots:
            try:
                raw = await self._redis.get(f"heartbeat:{bot_key}")
                if raw:
                    data = json.loads(raw)
                    if isinstance(data, dict):
                        out[bot_key] = data
            except Exception:
                continue
        return out
