"""Discord Sunucu, Sözleşme, Ses Kanalı, Güvenlik Log Kanalı ve Denetim Kaydı (Audit Log) İzleyicisi.

Hiçbir bota müdahale etmeden Discord üzerinden gözlem yapar:
1. Botların Discord çevrimiçi/çevrimdışı durumunu takip eder.
2. Rehber botunun `DESTEK_BEKLEME_SES_ID` (1532829788824404274) ses kanalında bağlı olup olmadığını her dakika denetler.
3. Ticket botunun her gece 00:00 TSİ'de `#only-mod` (1532828404347437287) kanalına attığı kapanış raporunu bekler; 00:05'e kadar gelmezse alarm verir.
4. Yeni bir `ticket-*` kanalı açıldığında Yapay Zeka botunun 60 saniye içinde karşılama mesajı atıp atmadığını (sözleşme testi) kontrol eder.
5. Güvenlik botunun `SECURITY_LOG_CHANNEL_ID` kanalına attığı `🛡️ PİYADER RP GÜVENLİK | ...` embedlerini okur.
6. Sunucudaki kitlesel katılımları (raid) ve kritik denetim kaydı (audit log) olaylarını (beklenmeyen yönetici yetkisi, izinsiz bot/webhook ekleme, kanal/rol silme) izler.
"""
from __future__ import annotations

import asyncio
import datetime
import logging
import time
from collections import deque
from typing import TYPE_CHECKING

import discord

from brain.actions.notify import TZ_TR
from brain.core.events import Event
from brain.core.fingerprint import make_fingerprint
from brain.core.redactor import redact

if TYPE_CHECKING:
    from brain.engine import BrainEngine

log = logging.getLogger("brain.discord_watch")


class DiscordWatchCollector:
    def __init__(self, bot: discord.Client, engine: "BrainEngine") -> None:
        self.bot = bot
        self.engine = engine
        self.settings = engine.settings
        self.registry = engine.registry
        self.state = engine.state
        self._join_timestamps: deque[float] = deque(maxlen=200)
        # channel_id -> first bot message timestamp
        self._ticket_greeted: set[int] = set()

    def _is_trusted_actor(self, user_id: int | None) -> bool:
        if not user_id:
            return False
        if user_id == self.settings.owner_id:
            return True
        if user_id in self.settings.trusted_user_ids:
            return True
        if self.bot.user and user_id == self.bot.user.id:
            return True
        if user_id in self.registry.known_bot_ids():
            return True
        return False

    # ── Dakikalık Durum Denetimi (Ses, Çevrimiçi, Gece Raporu, Snapshot) ──
    async def check_minute_tasks(self) -> None:
        guild = self.bot.get_guild(self.settings.guild_id)
        now = time.time()
        now_tr = datetime.datetime.now(tz=TZ_TR)
        today_str = now_tr.strftime("%Y-%m-%d")

        for bot_key, spec in self.registry.bots.items():
            bh = self.state.bot(bot_key)

            # 1. Discord çevrimiçi durumu ve ses kanalı kontrolü
            if guild is not None and spec.discord_bot_id:
                member = guild.get_member(spec.discord_bot_id)
                if member is not None:
                    online = member.status != discord.Status.offline
                    prev_online = bh.discord_online
                    bh.discord_online = online
                    inc_key = f"{bot_key}:discord_offline"
                    if not online:
                        await self.engine.ingest(
                            Event(
                                source="discord",
                                bot=bot_key,
                                kind="status",
                                category="bot_offline",
                                severity="critical",
                                title="Bot Discord'da Çevrimdışı",
                                message=f"{spec.name} ({spec.discord_bot_id}) sunucuda çevrimdışı görünüyor.",
                                cause="Bot süreci durmuş veya Discord Gateway bağlantısı kopmuş.",
                                suggestion="Railway servis durumunu ve son logları kontrol et.",
                                fingerprint=make_fingerprint(bot_key, "bot_offline", "offline"),
                                incident_key=inc_key,
                                sticky=True,
                            )
                        )
                    elif prev_online is False and online:
                        await self.engine.ingest(
                            Event(
                                source="discord",
                                bot=bot_key,
                                kind="status",
                                category="bot_offline",
                                title="Bot Tekrar Çevrimiçi",
                                message=f"{spec.name} çevrimiçi oldu.",
                                incident_key=inc_key,
                                resolves=True,
                            )
                        )

                    # Ses kanalında bulunma kontrolü (Rehber botu)
                    if spec.voice_presence:
                        target_vc_id = int(spec.voice_presence.get("channel_id") or 0)
                        grace = int(spec.voice_presence.get("grace_checks") or 2)
                        in_vc = bool(member.voice and member.voice.channel and member.voice.channel.id == target_vc_id)
                        bh.in_expected_voice = in_vc
                        vc_inc_key = f"{bot_key}:voice_presence"
                        if not in_vc:
                            bh.voice_miss_count += 1
                            if bh.voice_miss_count >= grace:
                                mesai_mi = 12 <= now_tr.hour or now_tr.hour < 1
                                await self.engine.ingest(
                                    Event(
                                        source="discord",
                                        bot=bot_key,
                                        kind="voice",
                                        category="voice_disconnected",
                                        severity="warning",
                                        title="Rehber Botu Ses Kanalından Düştü",
                                        message=f"{spec.name}, #{target_vc_id} ses kanalında bağlı değil ({'mesai içi' if mesai_mi else 'mesai dışı'}).",
                                        cause="Discord ses sunucusu bağlantısı koptu veya ffmpeg süreci takıldı.",
                                        suggestion="Botun otomatik yeniden bağlanma döngüsünü (`destek_ses_uyari`) kontrol et.",
                                        module="destek_ses_uyari",
                                        fingerprint=make_fingerprint(bot_key, "voice_disconnected", str(target_vc_id)),
                                        incident_key=vc_inc_key,
                                    )
                                )
                        else:
                            if bh.voice_miss_count > 0:
                                bh.voice_miss_count = 0
                                await self.engine.ingest(
                                    Event(
                                        source="discord",
                                        bot=bot_key,
                                        kind="voice",
                                        category="voice_disconnected",
                                        title="Rehber Botu Ses Kanalına Bağlandı",
                                        message="Ses bağlantısı normale döndü.",
                                        incident_key=vc_inc_key,
                                        resolves=True,
                                    )
                                )

            # 2. Zamanlanmış mesaj kontrolü (Ticket botu 00:00 TSİ Gece Raporu)
            for sched in spec.scheduled_messages:
                hh, mm = (int(x) for x in sched.time.split(":"))
                sched_dt = now_tr.replace(hour=hh, minute=mm, second=0, microsecond=0)
                diff_min = (now_tr - sched_dt).total_seconds() / 60.0
                if sched.grace_minutes <= diff_min <= (sched.grace_minutes + 25):
                    if bh.scheduled_last_seen.get(sched.name) != today_str:
                        # Kanalın son mesajlarını da kontrol et (Beyin yeni açılmış olabilir)
                        found = await self._verify_channel_recent_message(sched.channel_id, sched.contains, since_ts=sched_dt.timestamp() - 120)
                        if found:
                            bh.scheduled_last_seen[sched.name] = today_str
                        else:
                            bh.scheduled_last_seen[sched.name] = today_str  # Aynı gece tekrar tekrar tetikleme
                            await self.engine.ingest(
                                Event(
                                    source="discord",
                                    bot=bot_key,
                                    kind="schedule",
                                    category="missed_scheduled_message",
                                    severity="critical",
                                    title=f"Gece Raporu Gelmedi ({sched.time} TSİ)",
                                    message=f"Beklenen '{sched.name}' mesajı #{sched.channel_id} kanalına {sched.time} TSİ'de ulaşmadı.",
                                    cause="Bot ER:LC API limitine takılıp kilitlenmiş veya zamanlayıcı döngüsü (`gunluk_rapor`) durmuş olabilir. Veri sıfırlama kaçırılmış olabilir.",
                                    suggestion="Ticket botu loglarını kontrol et; ER:LC yoklama aralığını ve hata yakalamasını gözden geçir.",
                                    module=sched.module or "yardim_bekleme",
                                    fingerprint=make_fingerprint(bot_key, "missed_scheduled_message", sched.name),
                                    incident_key=f"{bot_key}:sched:{sched.name}:{today_str}",
                                    sticky=True,
                                )
                            )

            # 3. Periyodik log kontrolü (Güvenlik botu 30 dk snapshot)
            for per in spec.expect_periodic:
                last_ts = bh.periodic_last_seen.get(per.name, 0.0)
                if last_ts > 0:
                    limit_s = (per.every_minutes + per.grace_minutes) * 60
                    if (now - last_ts) > limit_s:
                        await self.engine.ingest(
                            Event(
                                source="discord",
                                bot=bot_key,
                                kind="schedule",
                                category="missed_periodic_log",
                                severity="warning",
                                title=f"Periyodik Yedekleme Gecikti ({per.name})",
                                message=f"Son '{per.pattern}' logu {int((now - last_ts) // 60)} dk önce görüldü (beklenen: {per.every_minutes} dk).",
                                cause="Güvenlik botunun snapshot zamanlayıcısı veya SQLite Volume yazımı aksamış olabilir.",
                                suggestion="Railway Volume bağlantısını ve güvenlik botu loglarını kontrol et.",
                                fingerprint=make_fingerprint(bot_key, "missed_periodic_log", per.name),
                                incident_key=f"{bot_key}:periodic:{per.name}",
                            )
                        )

    async def _verify_channel_recent_message(self, channel_id: int, keywords: list[str], since_ts: float) -> bool:
        ch = self.bot.get_channel(channel_id)
        if ch is None:
            try:
                ch = await self.bot.fetch_channel(channel_id)
            except Exception:
                return False
        if not isinstance(ch, discord.abc.Messageable):
            return False
        try:
            async for msg in ch.history(limit=15):
                if msg.created_at.timestamp() < since_ts:
                    break
                text_parts = [msg.content or ""]
                for emb in msg.embeds:
                    text_parts.append(emb.title or "")
                    text_parts.append(emb.description or "")
                combined = " ".join(text_parts).lower()
                if any(k.lower() in combined for k in keywords):
                    return True
        except Exception:
            return False
        return False

    # ── Mesaj Dinleyicisi (#only-mod Gece Raporu + Güvenlik Log Kanalı + Ticket AI Yanıtı) ──
    async def on_message(self, message: discord.Message) -> None:
        if not message.guild or message.guild.id != self.settings.guild_id:
            return

        # 1. Ticket kanallarına gelen ilk bot mesajını kaydet (AI sözleşme testi için)
        if message.author.bot and isinstance(message.channel, discord.TextChannel):
            if message.channel.name.startswith("ticket-"):
                self._ticket_greeted.add(message.channel.id)

        # 2. Zamanlanmış mesaj takibi (#only-mod gece raporu)
        for bot_key, spec in self.registry.bots.items():
            for sched in spec.scheduled_messages:
                if message.channel.id == sched.channel_id and message.author.bot:
                    combined = " ".join(
                        [message.content or ""]
                        + [f"{e.title or ''} {e.description or ''}" for e in message.embeds]
                    ).lower()
                    if any(k.lower() in combined for k in sched.contains):
                        today_str = datetime.datetime.now(tz=TZ_TR).strftime("%Y-%m-%d")
                        self.state.bot(bot_key).scheduled_last_seen[sched.name] = today_str

        # 3. Güvenlik Botu Log Kanalı Ayrıştırıcısı
        if self.settings.security_log_channel_id and message.channel.id == self.settings.security_log_channel_id:
            await self._parse_security_channel_message(message)

    async def _parse_security_channel_message(self, message: discord.Message) -> None:
        for emb in message.embeds:
            title = (emb.title or "").strip()
            if "GÜVENLİK" not in title.upper() and "GUARD" not in (emb.footer.text or "").upper():
                continue
            clean_title = title.split("|", 1)[-1].strip() if "|" in title else title
            desc = redact(emb.description or "")
            color_val = emb.color.value if emb.color else 0

            # Renk kodundan aciliyet çıkar (logger.js: CRITICAL=0xE74C3C, DANGER=0xE67E22)
            if color_val in (0xE74C3C, 0xE67E22) or any(
                w in clean_title.upper() for w in ("BAN", "KARANTİNA", "RAID", "AKIN", "SİLİNDİ", "GERİ YÜKLENDİ")
            ):
                sev = "critical" if color_val == 0xE74C3C else "warning"
            else:
                sev = "info"

            field_summary = "; ".join(f"{f.name}: {f.value}" for f in emb.fields[:4])
            full_msg = f"{clean_title} — {desc} ({field_summary})".strip()
            self.state.bot("guvenlik").record_log(full_msg)

            if sev in ("warning", "critical"):
                await self.engine.ingest(
                    Event(
                        source="security",
                        bot="guvenlik",
                        kind="security_log",
                        category="security_alert",
                        severity=sev,
                        title=f"Güvenlik Botu: {clean_title[:80]}",
                        message=full_msg[:800],
                        cause=desc[:300] or "Güvenlik botu şüpheli bir işlem tespit etti ve müdahale etti.",
                        suggestion="İşlemi yapan kullanıcıyı/botu ve sunucu denetim kaydını kontrol et.",
                        fingerprint=make_fingerprint("guvenlik", "security_alert", clean_title),
                    )
                )

    # ── Yapay Zeka Botu `ticket-*` Sözleşme Testi ──
    async def on_guild_channel_create(self, channel: discord.abc.GuildChannel) -> None:
        if channel.guild.id != self.settings.guild_id or not isinstance(channel, discord.TextChannel):
            return
        ai_spec = self.registry.get("yapay-zeka")
        if not ai_spec or not ai_spec.ticket_contract:
            return
        prefix = str(ai_spec.ticket_contract.get("channel_prefix") or "ticket-")
        timeout_s = int(ai_spec.ticket_contract.get("timeout_seconds") or 60)
        if not channel.name.startswith(prefix):
            return

        # `ai_ticket_assistant` modülü bilinçli olarak duraklatılmışsa uyarı üretme
        if "ai_ticket_assistant" in self.state.bot("yapay-zeka").paused_modules:
            return

        asyncio.create_task(self._verify_ticket_greeting(channel, timeout_s))

    async def _verify_ticket_greeting(self, channel: discord.TextChannel, timeout_s: int) -> None:
        await asyncio.sleep(timeout_s)
        if channel.id in self._ticket_greeted:
            self._ticket_greeted.discard(channel.id)
            return

        # Kanal silinmiş veya kapanmış olabilir
        ch = self.bot.get_channel(channel.id)
        if ch is None:
            return

        try:
            async for msg in channel.history(limit=10):
                if msg.author.bot:
                    return
        except Exception:
            return

        await self.engine.ingest(
            Event(
                source="discord",
                bot="yapay-zeka",
                kind="contract",
                category="ticket_ai_no_greeting",
                severity="warning",
                title=f"Yeni Bilette AI Karşılama Gelmedi (#{channel.name})",
                message=f"#{channel.name} açıldıktan {timeout_s} sn sonra hiçbir bot mesajı görülmedi.",
                cause="Yapay Zeka botu çevrimdışı/donmuş olabilir ya da kanal topic'indeki `acan_id:` sözleşmesi değişmiş olabilir.",
                suggestion="Yapay Zeka botu durumunu ve Ticket botunun kanal oluşturma formatını kontrol et.",
                module="ai_ticket_assistant",
                fingerprint=make_fingerprint("yapay-zeka", "ticket_ai_no_greeting", "contract"),
                incident_key="yapay-zeka:ticket_greeting_contract",
            )
        )

    # ── Raid (Toplu Katılım) Tespiti ──
    async def on_member_join(self, member: discord.Member) -> None:
        if member.guild.id != self.settings.guild_id:
            return
        now = time.time()
        self._join_timestamps.append(now)
        cutoff = now - self.settings.raid_window_seconds
        recent_joins = sum(1 for t in self._join_timestamps if t >= cutoff)
        if recent_joins >= self.settings.raid_join_threshold:
            await self.engine.ingest(
                Event(
                    source="discord",
                    bot="guild",
                    kind="raid",
                    category="raid_detected",
                    severity="critical",
                    title=f"Olası Raid / Toplu Katılım ({recent_joins} üye / {self.settings.raid_window_seconds} sn)",
                    message=f"Son {self.settings.raid_window_seconds} saniyede {recent_joins} yeni hesap sunucuya katıldı (son: {member} / {member.id}).",
                    cause="Koordineli bot/hesap akını (raid) gerçekleşiyor olabilir.",
                    suggestion="Sunucu doğrulama seviyesini yükseltmeyi ve davet bağlantılarını geçici duraklatmayı değerlendir.",
                    fingerprint=make_fingerprint("guild", "raid_detected", "join_burst"),
                    incident_key="guild:raid_detected",
                )
            )

    # ── Discord Denetim Kaydı (Audit Log) Koruması ──
    async def on_audit_log_entry(self, entry: discord.AuditLogEntry) -> None:
        if not entry.guild or entry.guild.id != self.settings.guild_id:
            return
        actor_id = entry.user_id
        actor_str = f"{entry.user} ({actor_id})" if entry.user else f"ID:{actor_id}"

        # 1. Beklenmeyen birine Yönetici (Administrator) yetkisi verilmesi -> Her zaman uyar
        if entry.action == discord.AuditLogAction.role_update:
            before_perms = getattr(entry.before, "permissions", None)
            after_perms = getattr(entry.after, "permissions", None)
            if (
                isinstance(before_perms, discord.Permissions)
                and isinstance(after_perms, discord.Permissions)
                and not before_perms.administrator
                and after_perms.administrator
                and actor_id != self.settings.owner_id
            ):
                target_name = getattr(entry.target, "name", str(entry.target))
                await self.engine.ingest(
                    Event(
                        source="discord",
                        bot="guild",
                        kind="audit",
                        category="admin_grant",
                        severity="critical",
                        title=f"KRİTİK: '{target_name}' Rolüne Yönetici İzni Verildi!",
                        message=f"Yapan: {actor_str} -> Rol: {target_name}",
                        cause="Bir role tam Yönetici (Administrator) yetkisi açıldı.",
                        suggestion="Bu işlem bilgin dışında yapıldıysa rolün yönetici iznini derhal geri al.",
                        fingerprint=make_fingerprint("guild", "admin_grant", str(actor_id)),
                        sticky=True,
                    )
                )
                return

        if self._is_trusted_actor(actor_id):
            return

        # 2. Sunucuya yabancı bot eklenmesi
        if entry.action == discord.AuditLogAction.bot_add:
            await self.engine.ingest(
                Event(
                    source="discord",
                    bot="guild",
                    kind="audit",
                    category="untrusted_bot_add",
                    severity="critical",
                    title="Sunucuya Tanınmayan Bot Eklendi!",
                    message=f"Ekleyen: {actor_str} -> Bot: {entry.target}",
                    cause="Güvenli listede olmayan bir kullanıcı sunucuya yeni bir bot ekledi.",
                    suggestion="Eklenen botu ve ekleyen yöneticinin hesabını hemen kontrol et.",
                    fingerprint=make_fingerprint("guild", "untrusted_bot_add", str(actor_id)),
                    sticky=True,
                )
            )
            return

        # 3. Webhook oluşturulması, kanal silinmesi veya rol silinmesi
        critical_actions = {
            discord.AuditLogAction.webhook_create: ("Şüpheli Webhook Oluşturuldu", "webhook_create"),
            discord.AuditLogAction.channel_delete: ("Kanal Silindi", "channel_delete"),
            discord.AuditLogAction.role_delete: ("Rol Silindi", "role_delete"),
        }
        if entry.action in critical_actions:
            title_tr, cat = critical_actions[entry.action]
            await self.engine.ingest(
                Event(
                    source="discord",
                    bot="guild",
                    kind="audit",
                    category=cat,
                    severity="critical",
                    title=f"Denetim Kaydı Uyarısı: {title_tr}",
                    message=f"Yapan: {actor_str} -> Hedef: {entry.target}",
                    cause=f"Muaf listede olmayan bir hesap ({actor_str}) kritik sunucu değişikliği yaptı.",
                    suggestion="Güvenlik botunun müdahale edip etmediğini ve kullanıcı yetkilerini kontrol et.",
                    fingerprint=make_fingerprint("guild", cat, str(actor_id)),
                )
            )
