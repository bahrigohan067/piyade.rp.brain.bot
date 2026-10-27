"""Web Sitesi, SSL Sertifikası, ER:LC Durumu ve Harici Nabız (UptimeRobot) Toplayıcısı."""
from __future__ import annotations

import asyncio
import datetime
import logging
import socket
import ssl
import time
from typing import TYPE_CHECKING
from urllib.parse import urlparse

import aiohttp

from brain.core.events import Event
from brain.core.fingerprint import make_fingerprint
from brain.core.state import EndpointResult

if TYPE_CHECKING:
    from brain.engine import BrainEngine

log = logging.getLogger("brain.web")


def _check_ssl_days_sync(hostname: str, port: int = 443) -> int | None:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                if not cert or "notAfter" not in cert:
                    return None
                exp_str = str(cert["notAfter"])
                exp_dt = datetime.datetime.strptime(exp_str, "%b %d %H:%M:%S %Y %Z").replace(
                    tzinfo=datetime.timezone.utc
                )
                delta = exp_dt - datetime.datetime.now(tz=datetime.timezone.utc)
                return max(0, delta.days)
    except Exception:
        return None


class WebCollector:
    def __init__(self, engine: "BrainEngine") -> None:
        self.engine = engine
        self.settings = engine.settings
        self.registry = engine.registry
        self.state = engine.state
        self._last_ssl_check: float = 0.0
        self._erlc_disconnect_streak: int = 0

    async def poll_once(self) -> None:
        site_spec = self.registry.site
        if not site_spec or not site_spec.base_url:
            return

        now = time.time()
        timeout = aiohttp.ClientTimeout(total=10, connect=5)
        any_critical_failed = False

        async with aiohttp.ClientSession(timeout=timeout) as session:
            for chk in site_spec.checks:
                url = f"{site_spec.base_url}{chk.path}"
                t0 = time.perf_counter()
                ok = False
                status_code = 0
                err_msg: str | None = None
                try:
                    async with session.get(
                        url,
                        allow_redirects=False,
                        headers={"User-Agent": "PiyadeRP-BrainBot-HealthCheck/1.0"},
                    ) as resp:
                        latency_ms = (time.perf_counter() - t0) * 1000.0
                        status_code = resp.status
                        if chk.expect_not_5xx:
                            ok = status_code < 500
                        else:
                            ok = status_code in chk.expect

                        if chk.json_erlc and status_code == 200:
                            try:
                                body = await resp.json(content_type=None)
                                await self._inspect_erlc_payload(body)
                            except Exception:
                                pass
                except Exception as exc:
                    latency_ms = (time.perf_counter() - t0) * 1000.0
                    err_msg = str(exc)[:180]
                    ok = False

                self.state.site.endpoints[chk.name] = EndpointResult(
                    name=chk.name,
                    path=chk.path,
                    ok=ok,
                    status_code=status_code,
                    latency_ms=latency_ms,
                    checked_at=now,
                    error=err_msg,
                )

                inc_key = f"site:endpoint:{chk.name}"
                if not ok:
                    if chk.critical:
                        any_critical_failed = True
                    await self.engine.ingest(
                        Event(
                            source="web",
                            bot="site",
                            kind="http",
                            category="site_endpoint_down",
                            severity="critical" if chk.critical else "warning",
                            title=f"Site Uç Noktası Hatalı ({chk.path})",
                            message=f"{url} -> HTTP {status_code} ({err_msg or 'beklenmeyen yanıt'})",
                            cause=f"`{chk.path}` uç noktası beklenen yanıtı vermedi (durum kodu: {status_code or 'zaman aşımı'}).",
                            suggestion="Railway'de site servisinin loglarını ve son Next.js build durumunu kontrol et.",
                            fingerprint=make_fingerprint("site", "site_endpoint_down", chk.path),
                            incident_key=inc_key,
                            min_count=2,
                            window=120,
                        )
                    )
                else:
                    await self.engine.ingest(
                        Event(
                            source="web",
                            bot="site",
                            kind="http",
                            category="site_endpoint_down",
                            title=f"Site Uç Noktası Normale Döndü ({chk.path})",
                            message=f"{url} -> HTTP {status_code} ({int(latency_ms)} ms)",
                            incident_key=inc_key,
                            resolves=True,
                        )
                    )

            # Harici nabız (UptimeRobot / Better Stack)
            if self.settings.uptime_push_url:
                try:
                    async with session.get(self.settings.uptime_push_url) as _:
                        pass
                except Exception:
                    pass

        if any_critical_failed:
            self.state.site.consecutive_failures += 1
        else:
            self.state.site.consecutive_failures = 0
        self.state.site.last_check_ts = now

        # Saatlik SSL sertifika kontrolü
        if (now - self._last_ssl_check) >= 3600:
            self._last_ssl_check = now
            parsed = urlparse(site_spec.base_url)
            if parsed.scheme == "https" and parsed.hostname:
                days = await asyncio.to_thread(_check_ssl_days_sync, parsed.hostname)
                self.state.site.ssl_days_left = days
                if days is not None and days <= 7:
                    await self.engine.ingest(
                        Event(
                            source="web",
                            bot="site",
                            kind="ssl",
                            category="ssl_expiring",
                            severity="critical" if days <= 2 else "warning",
                            title=f"SSL Sertifikası Bitiyor ({days} gün kaldı)",
                            message=f"{parsed.hostname} SSL sertifikasının dolmasına {days} gün kaldı.",
                            cause="Alan adı TLS/SSL sertifikası yakında sona erecek.",
                            suggestion="Cloudflare / Railway domain ayarlarından SSL yenilemesini kontrol et.",
                            fingerprint=make_fingerprint("site", "ssl_expiring", parsed.hostname),
                            incident_key="site:ssl_expiring",
                        )
                    )

    async def _inspect_erlc_payload(self, body: dict) -> None:
        if not isinstance(body, dict):
            return
        erlc = body.get("erlc")
        if not isinstance(erlc, dict):
            return
        connected = bool(erlc.get("connected"))
        self.state.erlc.connected = connected
        self.state.erlc.current_players = int(erlc.get("currentPlayers") or 0)
        self.state.erlc.max_players = int(erlc.get("maxPlayers") or 0)
        self.state.erlc.queue_count = int(erlc.get("queueCount") or 0)
        self.state.erlc.last_check_ts = time.time()

        inc_key = "erlc:connection"
        if not connected:
            self._erlc_disconnect_streak += 1
            if self._erlc_disconnect_streak >= 3:
                await self.engine.ingest(
                    Event(
                        source="web",
                        bot="erlc",
                        kind="status",
                        category="erlc_down",
                        severity="warning",
                        title="ER:LC Sunucu Köprüsü Yanıt Vermiyor",
                        message="Site /api/status uç noktasında erlc.connected=false döndü (ardışık 3 kontrol).",
                        cause="ER:LC oyun API'si çökmüş, hız sınırına (429) takılmış veya özel sunucu kapalı olabilir.",
                        suggestion="Botların ER:LC yoklama sıklığını kontrol et; gerekirse radar/araç-log modüllerini geçici duraklat.",
                        fingerprint=make_fingerprint("erlc", "erlc_down", "disconnected"),
                        incident_key=inc_key,
                    )
                )
        else:
            self._erlc_disconnect_streak = 0
            await self.engine.ingest(
                Event(
                    source="web",
                    bot="erlc",
                    kind="status",
                    category="erlc_down",
                    title="ER:LC Bağlantısı Normale Döndü",
                    message="erlc.connected=true",
                    incident_key=inc_key,
                    resolves=True,
                )
            )
