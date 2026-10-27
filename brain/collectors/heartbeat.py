"""Heartbeat (Nabız) HTTP Sunucusu ve Donma (Freeze) Tespitçisi.

Güvenlik ve Doğrulama:
- `/agent/heartbeat`, `/agent/event` ve `/agent/flags/{bot}` uç noktalarının TAMAMI
  `X-Brain-Key` başlığıyla korunur (`hmac.compare_digest` ile sabit zamanlı karşılaştırma).
- Hem bot bazlı anahtarlar (`AGENT_KEYS=ana-bot:anahtar1,...`) hem de ortak gizli anahtar
  (`BRAIN_SHARED_SECRET`) desteklenir. En az 16 karakter olmayan anahtarlar kabul edilmez.
- Bir bota ait anahtar başka bir bot adına nabız/olay gönderemez (`403 Forbidden`).

Ajansız Bot Koruması (Yanlış Alarm Önlemi):
- `registry.yaml` içinde `agent_installed: false` (varsayılan) olan ve henüz hiç nabız göndermemiş
  (`last_heartbeat_ts == 0`) botlar için 90 saniyelik donma kontrolü **tamamen kapalıdır**.
- Böylece diğer botlara `brain_agent.py` eklenmediği sürece hiçbir zaman sahte "Donmuş" alarmı üretilmez.
"""
from __future__ import annotations

import hmac
import logging
import time
from typing import TYPE_CHECKING, Any

from aiohttp import web

from brain.core.events import Event
from brain.core.fingerprint import make_fingerprint
from brain.core.redactor import redact

if TYPE_CHECKING:
    from brain.engine import BrainEngine

log = logging.getLogger("brain.heartbeat")


class BrainHttpServer:
    def __init__(self, engine: "BrainEngine") -> None:
        self.engine = engine
        self.settings = engine.settings
        self.state = engine.state
        self._runner: web.AppRunner | None = None

    def _authenticate(self, request: web.Request) -> str | None:
        """`X-Brain-Key` başlığını sabit zamanlı karşılaştırmayla doğrular.

        Dönüş:
        - Bot bazlı anahtar eşleşirse: ilgili botun anahtarı (örn. `"ana-bot"`)
        - `BRAIN_SHARED_SECRET` eşleşirse: `"*"` (tüm botlar için yetkili ortak sır)
        - Eşleşme yoksa veya anahtar tanımlı değilse: `None`
        """
        provided = (request.headers.get("X-Brain-Key") or "").strip()
        if len(provided) < 16:
            return None
        prov_bytes = provided.encode("utf-8")

        for key, bot_name in self.settings.agent_keys.items():
            if hmac.compare_digest(prov_bytes, key.encode("utf-8")):
                return bot_name

        if self.settings.brain_shared_secret:
            if hmac.compare_digest(prov_bytes, self.settings.brain_shared_secret.encode("utf-8")):
                return "*"

        return None

    def create_app(self) -> web.Application:
        app = web.Application(client_max_size=256 * 1024)  # 256 KB girdi sınırı
        app.router.add_get("/", self.handle_health)
        app.router.add_get("/health", self.handle_health)
        app.router.add_post("/agent/heartbeat", self.handle_heartbeat)
        app.router.add_post("/agent/event", self.handle_agent_event)
        app.router.add_get("/agent/flags/{bot}", self.handle_get_flags)
        return app

    async def start(self) -> None:
        app = self.create_app()
        self._runner = web.AppRunner(app, access_log=None)
        await self._runner.setup()
        site = web.TCPSite(self._runner, host="0.0.0.0", port=self.settings.port)
        await site.start()
        log.info("Beyin HTTP/Nabız sunucusu dinleniyor: 0.0.0.0:%s", self.settings.port)

    async def stop(self) -> None:
        if self._runner is not None:
            await self._runner.cleanup()
            self._runner = None

    async def handle_health(self, _request: web.Request) -> web.Response:
        uptime = int(time.time() - self.state.started_at)
        return web.json_response(
            {
                "ok": True,
                "service": "piyade-rp-brain",
                "mode": "auto" if self.settings.auto_actions else "suggest_only",
                "uptime_seconds": uptime,
                "open_incidents": len(self.state.open_incidents()),
                "maintenance": self.state.in_maintenance,
            }
        )

    async def handle_heartbeat(self, request: web.Request) -> web.Response:
        authed_bot = self._authenticate(request)
        if not authed_bot:
            return web.json_response({"ok": False, "error": "unauthorized"}, status=401)

        try:
            payload = await request.json()
        except Exception:
            return web.json_response({"ok": False, "error": "invalid_json"}, status=400)

        requested_bot = str(payload.get("bot") or "").strip()
        if authed_bot != "*" and requested_bot and requested_bot != authed_bot:
            return web.json_response({"ok": False, "error": "forbidden_bot_mismatch"}, status=403)

        bot_key = requested_bot or authed_bot
        if bot_key == "*":
            return web.json_response({"ok": False, "error": "missing_bot_field"}, status=400)

        await self.apply_heartbeat(bot_key, payload)
        flags = await self.engine.flags.get_bot_flags(bot_key)
        return web.json_response({"ok": True, "bot": bot_key, "flags": flags})

    async def handle_agent_event(self, request: web.Request) -> web.Response:
        authed_bot = self._authenticate(request)
        if not authed_bot:
            return web.json_response({"ok": False, "error": "unauthorized"}, status=401)

        try:
            payload = await request.json()
        except Exception:
            return web.json_response({"ok": False, "error": "invalid_json"}, status=400)

        requested_bot = str(payload.get("bot") or "").strip()
        if authed_bot != "*" and requested_bot and requested_bot != authed_bot:
            return web.json_response({"ok": False, "error": "forbidden_bot_mismatch"}, status=403)

        bot_key = requested_bot if authed_bot == "*" else authed_bot
        if not bot_key or bot_key == "*":
            return web.json_response({"ok": False, "error": "missing_bot_field"}, status=400)

        msg = redact(str(payload.get("message") or "")[:3000])
        if not msg:
            return web.json_response({"ok": False, "error": "empty_message"}, status=400)

        self.state.bot(bot_key).record_log(msg)
        await self.engine.ingest(
            Event(
                source="agent",
                bot=bot_key,
                kind=str(payload.get("kind") or "exception"),
                message=msg,
                module=payload.get("module"),
            )
        )
        return web.json_response({"ok": True})

    async def handle_get_flags(self, request: web.Request) -> web.Response:
        authed_bot = self._authenticate(request)
        if not authed_bot:
            return web.json_response({"ok": False, "error": "unauthorized"}, status=401)
        bot_key = request.match_info.get("bot") or authed_bot
        if authed_bot != "*" and bot_key != authed_bot:
            return web.json_response({"ok": False, "error": "forbidden"}, status=403)
        flags = await self.engine.flags.get_bot_flags(bot_key)
        return web.json_response({"ok": True, "bot": bot_key, "flags": flags})

    async def apply_heartbeat(self, bot_key: str, data: dict[str, Any]) -> None:
        now = time.time()
        bh = self.state.bot(bot_key)
        was_stale = bh.last_heartbeat_ts > 0 and (now - bh.last_heartbeat_ts) > self.settings.heartbeat_timeout
        bh.last_heartbeat_ts = float(data.get("ts") or now)

        if data.get("ping_ms") is not None:
            bh.ping_ms = float(data["ping_ms"])
        if data.get("ram_mb") is not None:
            bh.ram_mb = float(data["ram_mb"])
        if data.get("loop_lag_ms") is not None:
            bh.loop_lag_ms = float(data["loop_lag_ms"])
        if isinstance(data.get("loaded_cogs"), list):
            bh.loaded_cogs = [str(x) for x in data["loaded_cogs"][:50]]
        if data.get("queue_size") is not None:
            bh.queue_size = int(data["queue_size"])
        if data.get("last_command_ts"):
            bh.last_command_ts = float(data["last_command_ts"])

        # Önceden nabız kesintisi alarmı açıksa otomatik kapat
        if was_stale or f"{bot_key}:heartbeat_timeout" in self.state.incidents:
            await self.engine.ingest(
                Event(
                    source="heartbeat",
                    bot=bot_key,
                    kind="status",
                    category="heartbeat_timeout",
                    title="Nabız Normale Döndü",
                    message="Bot tekrar nabız göndermeye başladı.",
                    incident_key=f"{bot_key}:heartbeat_timeout",
                    resolves=True,
                )
            )

        # Metrik kurallarını ve istatistiksel anomali dedektörünü çalıştır
        await self.engine.ingest(
            Event(
                source="heartbeat",
                bot=bot_key,
                kind="metric",
                message="heartbeat",
                data={
                    "ping_ms": bh.ping_ms,
                    "ram_mb": bh.ram_mb,
                    "loop_lag_ms": bh.loop_lag_ms,
                },
            )
        )
        anom_ev = self.engine.anomaly.check_metrics(
            bot_key,
            ping_ms=bh.ping_ms,
            ram_mb=bh.ram_mb,
            ts=now,
        )
        if anom_ev is not None:
            await self.engine.ingest(anom_ev)

    async def check_stale_heartbeats(self) -> None:
        """Redis'teki nabızları okur ve YALNIZCA ajanı aktif olan botlar için 90 sn donma kontrolü yapar."""
        redis_hbs = await self.engine.flags.read_redis_heartbeats()
        for bot_key, data in redis_hbs.items():
            ts = float(data.get("ts") or 0)
            if ts > self.state.bot(bot_key).last_heartbeat_ts:
                await self.apply_heartbeat(bot_key, data)

        now = time.time()
        timeout = self.settings.heartbeat_timeout
        for bot_key, bh in self.state.bots.items():
            spec = self.engine.registry.get(bot_key)
            # Ajan kurulu değilse ve daha önce hiç nabız gelmediyse ASLA donma alarmı üretme
            if bh.last_heartbeat_ts <= 0:
                continue
            if spec is not None and not spec.agent_installed and bh.last_heartbeat_ts <= 0:
                continue

            silent_s = now - bh.last_heartbeat_ts
            if silent_s > timeout:
                await self.engine.ingest(
                    Event(
                        source="heartbeat",
                        bot=bot_key,
                        kind="status",
                        category="heartbeat_timeout",
                        severity="critical",
                        title=f"Bot Donmuş Olabilir ({int(silent_s)} sn'dir nabız yok)",
                        message=f"Son nabız {int(silent_s)} saniye önce alındı (eşik: {timeout} sn).",
                        cause="Container çalışıyor görünse bile botun event loop'u kilitlenmiş veya süreç çökmüş olabilir.",
                        suggestion="Railway loglarını incele; kilitlenen modülü duraklat veya servisi yeniden başlat.",
                        fingerprint=make_fingerprint(bot_key, "heartbeat_timeout", "frozen"),
                        incident_key=f"{bot_key}:heartbeat_timeout",
                        sticky=True,
                    )
                )
