"""Beyin Çekirdek Motoru (Orchestrator).

Algıla -> Teşhis Et -> Korelasyon Kur -> (Onaylı/Güvenli) Müdahale Et -> Bildir
akışının tamamını yönetir.
"""
from __future__ import annotations

import asyncio
import datetime
import logging
import time
from collections import defaultdict, deque
from typing import Any

import discord

from brain.actions.cloudflare import CloudflareShield
from brain.actions.flags import FlagStore
from brain.actions.notify import TZ_TR, Notifier, fmt_ago, fmt_tr_time
from brain.analyzers.ai import AIRootCauseAnalyzer
from brain.analyzers.anomaly import AnomalyDetector
from brain.analyzers.correlator import Correlator
from brain.analyzers.rules import RuleEngine
from brain.collectors.auditor import EcosystemAuditor
from brain.collectors.discord_watch import DiscordWatchCollector
from brain.collectors.github import GitHubInspector
from brain.collectors.heartbeat import BrainHttpServer
from brain.collectors.railway import RailwayCollector
from brain.collectors.web import WebCollector
from brain.config.registry import Registry
from brain.config.settings import Settings
from brain.core.events import SEV_EMOJI, Event, Incident, max_sev
from brain.core.redactor import redact
from brain.core.state import WorldState
from brain.memory.db import BrainDB

log = logging.getLogger("brain.engine")


class BrainEngine:
    def __init__(self, bot: discord.Client, settings: Settings, registry: Registry) -> None:
        self.bot = bot
        self.settings = settings
        self.registry = registry
        self.state = WorldState(
            bot_specs=registry.bots,
            site_base_url=registry.site.base_url if registry.site else "",
        )
        self.db = BrainDB(database_url=settings.database_url, sqlite_path=settings.sqlite_path)
        self.flags = FlagStore(settings, registry, self.db, self.state)
        self.cloudflare = CloudflareShield(settings, self.db)
        self.rules = RuleEngine(registry, self.state)
        self.anomaly = AnomalyDetector()
        self.correlator = Correlator(registry, self.state)
        self.ai = AIRootCauseAnalyzer(settings, self.db)
        self.github = GitHubInspector(settings)
        self.notifier = Notifier(bot, self)
        self.http_server = BrainHttpServer(self)
        self.railway = RailwayCollector(self)
        self.web = WebCollector(self)
        self.discord_watch = DiscordWatchCollector(bot, self)
        self.auditor = EcosystemAuditor(self)

        # Eşik penceresi sayacı: key -> deque[ts]
        self._window_hits: dict[str, deque[float]] = defaultdict(lambda: deque(maxlen=50))
        self._last_daily_report_date: str = ""

    async def start(self) -> None:
        await self.db.connect()
        await self.flags.connect()
        # Kalıcı sessiz / bakım modu zamanlarını yükle
        try:
            q_val = await self.db.get_kv("quiet_until", "0")
            m_val = await self.db.get_kv("maintenance_until", "0")
            self.state.quiet_until = float(q_val or 0)
            self.state.maintenance_until = float(m_val or 0)
        except Exception:
            pass
        await self.http_server.start()

    async def stop(self) -> None:
        await self.http_server.stop()
        await self.flags.close()
        await self.db.close()

    # ── Ana Olay Giriş Kapısı ──
    async def ingest(self, raw_event: Event) -> Incident | None:
        # 1. Çözülme (recovery) olayı mı?
        if raw_event.resolves and raw_event.incident_key:
            existing = self.state.incidents.get(raw_event.incident_key)
            if existing and existing.is_open:
                await self._close_incident(existing, raw_event.message or "Durum normale döndü.")
            return existing

        # 2. Kural motorundan geçir
        ev = self.rules.evaluate(raw_event)
        if ev is None or not ev.category:
            return None

        inc_key = ev.incident_key or f"{ev.bot}:{ev.category}:{ev.fingerprint or 'default'}"

        # 3. Açık bir olay zaten varsa sayacı artır ve güncelle
        existing = self.state.incidents.get(inc_key)
        if existing and existing.is_open:
            existing.count += 1
            existing.last_seen = ev.ts
            existing.severity = max_sev(existing.severity, ev.severity)
            if ev.message:
                existing.samples.append(redact(ev.message)[:400])
            if ev.data.get("location") and not existing.data.get("location"):
                existing.data.update(ev.data)
            await self.db.update_incident(existing)
            if existing.fingerprint:
                await self.db.touch_fingerprint(
                    existing.fingerprint,
                    bot=existing.bot,
                    category=existing.category,
                    title=existing.title,
                    location=existing.data.get("location"),
                    now=ev.ts,
                )
            # Hata sayısı 5'i geçtiyse ve otomatik duraklatma açıksa devre kesiciyi çalıştır
            await self._maybe_circuit_break(existing)
            self.correlator.correlate(existing)
            await self.notifier.send_or_update_incident(existing)
            return existing

        # 4. Eşik kontrolü (min_count / window)
        if ev.min_count > 1:
            hits = self._window_hits[inc_key]
            hits.append(ev.ts)
            cutoff = ev.ts - ev.window
            while hits and hits[0] < cutoff:
                hits.popleft()
            if len(hits) < ev.min_count:
                return None

        # 5. Yeni Olay Kaydı (Incident) oluştur
        pause_mod = self._suggest_pause_module(ev)
        inc = Incident(
            id=0,
            key=inc_key,
            bot=ev.bot,
            category=ev.category,
            title=ev.title or ev.category,
            severity=ev.severity,
            first_seen=ev.ts,
            last_seen=ev.ts,
            module=ev.module,
            fingerprint=ev.fingerprint,
            cause=ev.cause,
            suggestion=ev.suggestion,
            count=max(1, ev.min_count),
            sticky=ev.sticky,
            pause_module=pause_mod,
            data=dict(ev.data),
        )
        if ev.message:
            inc.samples.append(redact(ev.message)[:400])

        # Hafızadan geçmiş parmak izi ve öğrenilmiş çözümü sorgula
        if inc.fingerprint:
            fp_row = await self.db.touch_fingerprint(
                inc.fingerprint,
                bot=inc.bot,
                category=inc.category,
                title=inc.title,
                location=inc.data.get("location"),
                now=ev.ts,
            )
            if fp_row.get("learned_resolution"):
                inc.data["learned_resolution"] = fp_row["learned_resolution"]
                inc.data["previous_occurrences"] = max(1, int(fp_row.get("total_occurrences", 1)) - 1)
            if fp_row.get("ai"):
                inc.ai = fp_row["ai"]

        await self.db.insert_incident(inc)
        self.state.incidents[inc.key] = inc
        self.state.incidents_by_id[inc.id] = inc

        await self._maybe_circuit_break(inc)
        self.correlator.correlate(inc)
        await self.notifier.send_or_update_incident(inc)

        # Arka planda GitHub kaynak kodu + son commit + Gemini AI kök neden analizi çalıştır
        if inc.ai is None and not inc.ai_pending:
            inc.ai_pending = True
            asyncio.create_task(self._enrich_incident_async(inc))

        return inc

    def _suggest_pause_module(self, ev: Event) -> str | None:
        if ev.module:
            return ev.module
        if ev.category == "gemini_error" and ev.bot == "yapay-zeka":
            return "ai_ticket_assistant"
        if ev.category == "erlc_rate_limit":
            defaults = {
                "ana-bot": "live_radar",
                "bot-1": "arac_sistemi",
                "ticket-bot": "yardim_bekleme",
            }
            return defaults.get(ev.bot)
        return None

    async def _maybe_circuit_break(self, inc: Incident) -> None:
        """AUTO_ACTIONS=true ise ve modül beyaz listedeyse 3-durumlu devre kesiciyi çalıştırır."""
        if inc.action_taken or inc.dismissed or not self.settings.auto_actions:
            return
        mod = inc.pause_module or inc.module
        if not mod:
            return
        spec = self.registry.get(inc.bot)
        if not spec or not spec.can_auto_pause(mod):
            return
        if inc.severity == "critical":
            ok, _ = await self.flags.set_flag(
                inc.bot,
                mod,
                "PAUSED",
                actor="auto",
                reason=f"Kritik devre kesici: {inc.title}",
                incident_id=inc.id,
            )
            if ok:
                inc.action_taken = f"⚡ Otomatik devre kesici `{mod}` modülünü duraklattı."
                await self.db.update_incident(inc)
            return

        # 5 hata / 2 dk (CLOSED -> OPEN) veya HALF_OPEN hatası
        cb = self.flags.breakers.get((inc.bot, mod))
        if cb is None and inc.count > 1:
            for _ in range(inc.count - 1):
                await self.flags.record_circuit_error(
                    inc.bot,
                    mod,
                    reason=inc.title,
                    incident_id=inc.id,
                    now=inc.last_seen,
                )
        ok, _ = await self.flags.record_circuit_error(
            inc.bot,
            mod,
            reason=inc.title,
            incident_id=inc.id,
            now=inc.last_seen,
        )
        if ok:
            inc.action_taken = f"⚡ Otomatik devre kesici `{mod}` modülünü duraklattı (5 hata/2 dk)."
            await self.db.update_incident(inc)

    async def _enrich_incident_async(self, inc: Incident) -> None:
        try:
            repo = self.registry.repo_of(inc.bot)
            trace_file = inc.data.get("trace_file")
            trace_line = inc.data.get("trace_line")

            if repo and trace_file and trace_line:
                snippet = await self.github.fetch_snippet(repo, str(trace_file), int(trace_line))
                if snippet:
                    inc.data["code_snippet"] = snippet

            if repo:
                commit_summary = await self.github.fetch_latest_commit(repo)
                if commit_summary:
                    inc.data["recent_commit"] = commit_summary

            bh = self.state.bots.get(inc.bot)
            recent_logs = list(bh.recent_logs)[-60:] if bh else list(inc.samples)
            metrics = {
                "ping_ms": bh.ping_ms if bh else None,
                "ram_mb": bh.ram_mb if bh else None,
                "loop_lag_ms": bh.loop_lag_ms if bh else None,
                "deploy_status": bh.deploy_status if bh else None,
            }

            ai_res = await self.ai.analyze(
                fingerprint=inc.fingerprint,
                bot_name=self.registry.display(inc.bot),
                category=inc.category,
                title=inc.title,
                recent_logs=recent_logs,
                code_snippet=inc.data.get("code_snippet"),
                commit_summary=inc.data.get("recent_commit"),
                metrics=metrics,
            )
            if ai_res:
                inc.ai = ai_res
                if ai_res.get("etkilenen_dosya") and not inc.data.get("location"):
                    inc.data["location"] = ai_res["etkilenen_dosya"]
                await self.db.update_incident(inc)
                await self.notifier.send_or_update_incident(inc, force_edit=True)
        except Exception as exc:
            log.debug("Olay zenginleştirme hatası (#%s): %s", inc.id, exc)
        finally:
            inc.ai_pending = False

    async def _close_incident(self, inc: Incident, resolution: str) -> None:
        inc.status = "resolved"
        inc.resolved_at = time.time()
        inc.resolution = resolution
        await self.db.update_incident(inc)
        await self.notifier.send_or_update_incident(inc, force_edit=True)

    async def resolve_incident_manual(self, incident_id: int, note: str, *, actor: str) -> tuple[bool, str]:
        inc = self.state.incidents_by_id.get(incident_id)
        if inc is None:
            return False, f"Olay #{incident_id} bulunamadı."
        await self._close_incident(inc, note)
        if inc.fingerprint:
            await self.db.record_resolution(inc.fingerprint, note)
        await self.db.log_action(
            actor=actor,
            action="resolve_incident",
            target=inc.key,
            reason=note,
            incident_id=inc.id,
        )
        return True, f"Olay #{inc.id} çözüldü olarak işaretlendi ve çözüm hafızaya kaydedildi."

    async def sweep_stale_incidents(self) -> None:
        """20 dakikadır tekrarlanmayan yapışkan olmayan olayları otomatik kapatır,
        devre kesici zamanlayıcılarını ilerletir ve bekleyen DM düzenlemelerini gönderir.
        """
        now = time.time()
        await self.flags.tick_circuit_breakers(now)
        for inc in list(self.state.open_incidents()):
            if not inc.sticky and (now - inc.last_seen) >= 1200:
                await self._close_incident(inc, "20 dakikadır tekrarlanmadı (otomatik kapandı).")
            elif inc.dm_dirty and (now - inc.last_dm_edit) >= 15:
                await self.notifier.send_or_update_incident(inc, force_edit=True)

        # Sabah 09:00 TSİ günlük sağlık özeti kontrolü
        now_tr = datetime.datetime.now(tz=TZ_TR)
        today_str = now_tr.strftime("%Y-%m-%d")
        if now_tr.hour == self.settings.daily_report_hour and self._last_daily_report_date != today_str:
            self._last_daily_report_date = today_str
            await self.notifier.send_daily_report()

    # ── Rapor ve Pano Oluşturucular (`/durum`, `/bot`, `/rapor`, `/neden`) ──
    def build_status_embed(self) -> discord.Embed:
        open_incs = self.state.open_incidents()
        color = 0xE74C3C if any(i.severity == "critical" for i in open_incs) else (0xE67E22 if open_incs else 0x2ECC71)

        embed = discord.Embed(
            title="🧠 Piyade RP — Canlı Ekosistem Panosu",
            color=color,
            timestamp=datetime.datetime.now(tz=datetime.timezone.utc),
        )

        bot_lines: list[str] = []
        for key, spec in self.registry.bots.items():
            bh = self.state.bot(key)
            emoji, badge = bh.overall_badge(self.settings.heartbeat_timeout)
            extras: list[str] = []
            if bh.ping_ms is not None:
                extras.append(f"`{int(bh.ping_ms)}ms`")
            if bh.ram_mb is not None:
                extras.append(f"`{int(bh.ram_mb)}MB`")
            if bh.paused_modules:
                extras.append(f"⏸️`{','.join(bh.paused_modules)}`")
            extra_str = f" • {' '.join(extras)}" if extras else ""
            bot_lines.append(f"{emoji} **{spec.name}** (`{key}`): {badge}{extra_str}")

        embed.add_field(name="🤖 Botlar", value="\n".join(bot_lines) or "Kayıtlı bot yok", inline=False)

        # Site ve ER:LC durumu
        s_emoji, s_badge = self.state.site.overall_badge()
        erlc = self.state.erlc
        if erlc.connected is True:
            erlc_str = f"🟢 Bağlı (`{erlc.current_players}/{erlc.max_players}` oyuncu, sıra: `{erlc.queue_count}`)"
        elif erlc.connected is False:
            erlc_str = f"🔴 Bağlantı Yok (son 3 dk 429: `{erlc.hits_last_3m()}`)"
        else:
            erlc_str = "⚪ Veri bekleniyor"

        embed.add_field(
            name="🌐 Web Sitesi & ER:LC Köprüsü",
            value=f"{s_emoji} **Site:** {s_badge}\n🚓 **ER:LC API:** {erlc_str}",
            inline=False,
        )

        # Açık olaylar
        if open_incs:
            inc_lines = [
                f"{SEV_EMOJI.get(i.severity, '🟠')} **#{i.id}** `{self.registry.display(i.bot)}` — {redact(i.title)} *({i.count}x, {fmt_ago(i.last_seen)})*"
                for i in open_incs[:8]
            ]
            embed.add_field(name=f"🚨 Açık Olaylar ({len(open_incs)})", value="\n".join(inc_lines), inline=False)
        else:
            embed.add_field(name="✅ Açık Olaylar", value="Şu anda açık bir sorun yok.", inline=False)

        # Beyin altyapı durumu
        modes = []
        modes.append(f"Mod: `{self.settings.action_mode_label}`")
        modes.append(f"Hafıza: `{self.db.backend}`")
        modes.append(f"Redis: `{'aktif' if self.flags.redis_connected else 'DB yedek'}`")
        modes.append(f"Railway: `{'aktif' if self.settings.railway_enabled else 'kapalı'}`")
        modes.append(f"AI: `{self.ai.model if self.settings.ai_enabled else 'kapalı'}`")
        if self.state.in_maintenance:
            modes.append(f"🛠️ **Bakım Modu** ({fmt_tr_time(self.state.maintenance_until)}'e kadar)")
        elif self.state.is_quiet:
            modes.append(f"🔕 **Sessiz Mod** ({fmt_tr_time(self.state.quiet_until)}'e kadar)")

        embed.add_field(name="⚙️ Beyin Altyapısı", value=" • ".join(modes), inline=False)

        if self.state.unmatched_railway_services:
            unmatched = ", ".join(f"`{s}`" for s in sorted(self.state.unmatched_railway_services)[:6])
            embed.add_field(
                name="ℹ️ Eşleşmeyen Railway Servis İsimleri",
                value=f"{unmatched} *(registry.yaml `railway_service` alanına ekleyebilirsin)*",
                inline=False,
            )

        embed.set_footer(text=f"Piyade RP Beyin • Çalışma süresi: {fmt_ago(self.state.started_at)}")
        return embed

    async def build_bot_detail_embed(self, bot_key: str) -> discord.Embed:
        spec = self.registry.get(bot_key)
        bh = self.state.bot(bot_key)
        emoji, badge = bh.overall_badge(self.settings.heartbeat_timeout)

        embed = discord.Embed(
            title=f"{emoji} {spec.name if spec else bot_key} (`{bot_key}`) — Detaylı Sağlık",
            color=0x3498DB,
            timestamp=datetime.datetime.now(tz=datetime.timezone.utc),
        )
        metrics = [
            f"**Durum:** {badge}",
            f"**Railway Deploy:** `{bh.deploy_status}` ({fmt_ago(bh.last_deploy_ts)})",
            f"**Discord Çevrimiçi:** `{bh.discord_online if bh.discord_online is not None else 'Bilinmiyor'}`",
            f"**Son Nabız:** `{fmt_ago(bh.last_heartbeat_ts)}`",
            f"**Gateway Ping:** `{int(bh.ping_ms)} ms`" if bh.ping_ms is not None else "**Gateway Ping:** `—`",
            f"**RAM Kullanımı:** `{bh.ram_mb:.1f} MB`" if bh.ram_mb is not None else "**RAM Kullanımı:** `—`",
            f"**Event Loop Gecikmesi:** `{bh.loop_lag_ms:.1f} ms`" if bh.loop_lag_ms is not None else "**Event Loop Gecikmesi:** `—`",
            f"**Son 1 Saatte Hata:** `{bh.errors_last_hour()}` (24 saatte: `{bh.errors_last_24h()}`)",
        ]
        embed.add_field(name="📊 Metrikler", value="\n".join(metrics), inline=False)

        flags = await self.flags.get_bot_flags(bot_key)
        if flags:
            flag_parts = [
                f"{'⏸️' if st == 'PAUSED' else '🟢'} `{m}`"
                for m, st in flags.items()
            ]
            embed.add_field(name="🧩 Modüller ve Bayraklar", value="  ".join(flag_parts)[:1000], inline=False)

        if bh.failed_cogs:
            fail_lines = [f"❌ `{c}` → `{redact(err)}`" for c, err in bh.failed_cogs.items()]
            embed.add_field(name="⚠️ Yüklenemeyen Cog'lar", value="\n".join(fail_lines)[:1000], inline=False)

        if bh.last_error_text:
            embed.add_field(
                name=f"🚨 Son Hata ({fmt_tr_time(bh.last_error_ts)} TSİ)",
                value=f"```\n{redact(bh.last_error_text)[:900]}\n```",
                inline=False,
            )

        if bh.recent_logs:
            tail = "\n".join(redact(line) for line in list(bh.recent_logs)[-8:])
            embed.add_field(name="📜 Son Log Satırları", value=f"```\n{tail[:950]}\n```", inline=False)

        return embed

    async def build_daily_report_embed(self, hours: int = 24) -> discord.Embed:
        rows = await self.db.recent_incidents(hours=hours, limit=100)
        actions = await self.db.recent_actions(hours=hours, limit=20)

        total_inc = len(rows)
        crit_count = sum(1 for r in rows if r.get("severity") == "critical")
        open_count = sum(1 for r in rows if r.get("status") == "open")

        by_bot: dict[str, int] = defaultdict(int)
        for r in rows:
            by_bot[str(r.get("bot") or "?")] += int(r.get("count") or 1)

        top_bots = ", ".join(
            f"**{self.registry.display(b)}** ({c} olay)"
            for b, c in sorted(by_bot.items(), key=lambda x: x[1], reverse=True)[:4]
        ) or "Sorun kaydı yok"

        embed = discord.Embed(
            title=f"🟢 Piyade RP — Son {hours} Saat Sağlık Raporu",
            description=(
                f"• **Toplam Olay Kaydı:** `{total_inc}` (`{crit_count}` kritik, `{open_count}` hâlâ açık)\n"
                f"• **En Çok Uyarı Üreten:** {top_bots}\n"
                f"• **Alınan Eylem Sayısı:** `{len(actions)}`"
            ),
            color=0x2ECC71 if open_count == 0 else 0xE67E22,
            timestamp=datetime.datetime.now(tz=datetime.timezone.utc),
        )

        if rows:
            lines = []
            for r in rows[:10]:
                st_icon = "🔴" if r.get("status") == "open" else "🟢"
                b_name = self.registry.display(str(r.get("bot") or ""))
                lines.append(
                    f"{st_icon} **#{r['id']}** `{b_name}` — {redact(str(r.get('title') or ''))} "
                    f"*({r.get('count', 1)}x, {fmt_tr_time(float(r.get('last_seen') or 0))})*"
                )
            embed.add_field(name="📋 Son Olaylar", value="\n".join(lines)[:1020], inline=False)

        if actions:
            act_lines = [
                f"• `{fmt_tr_time(float(a['ts']))}` **{a['action']}** → `{a['target']}` *({redact(str(a.get('reason') or ''))[:60]})*"
                for a in actions[:6]
            ]
            embed.add_field(name="🛡️ Denetim Kaydı (Son Eylemler)", value="\n".join(act_lines)[:1020], inline=False)

        embed.set_footer(text="Piyade RP Beyin • Günlük Özet")
        return embed
