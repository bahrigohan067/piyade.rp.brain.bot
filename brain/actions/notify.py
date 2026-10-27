"""DM Bildirim Katmanı ve Onaylı Eylem Butonları.

Özellikler:
- Yalnızca `OWNER_ID`'ye DM gönderir; başka kimseye mesaj atmaz ve başkasının buton tıklamasını kabul etmez.
- Tekilleştirme: Her `Incident` için tek bir DM atılır; sayı arttığında, AI analizi tamamlandığında,
  korelasyon bulunduğunda veya sorun çözüldüğünde yeni mesaj atmak yerine mevcut DM güncellenir.
- Sessiz saatler (`QUIET_HOURS` veya `/sessiz`) sırasında 🟠 Uyarı bildirimleri bekletilir;
  🔴 Kritik bildirimler acil durum istisnasıyla anında iletilir.
- 🟡 Bilgi olayları saatlik özette, genel durum ise her sabah 09:00 TSİ günlük raporda gönderilir.
- Kalıcı dinamik butonlar (`DynamicItem`): Beyin yeniden başlasa bile eski DM'lerdeki butonlar çalışır.
"""
from __future__ import annotations

import asyncio
import logging
import re
import time
from collections import deque
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any

import discord

from brain.core.events import SEV_EMOJI, SEV_LABEL, Incident
from brain.core.redactor import redact

if TYPE_CHECKING:
    from brain.engine import BrainEngine

log = logging.getLogger("brain.notify")

TZ_TR = timezone(timedelta(hours=3))

_COLORS = {
    "critical": 0xE74C3C,  # Kırmızı
    "warning": 0xE67E22,   # Turuncu
    "info": 0xF1C40F,      # Sarı
    "resolved": 0x2ECC71,  # Yeşil
    "report": 0x2ECC71,    # Yeşil
}


def fmt_tr_time(ts: float | None) -> str:
    if not ts:
        return "—"
    dt = datetime.fromtimestamp(ts, tz=TZ_TR)
    return dt.strftime("%H:%M:%S")


def fmt_ago(ts: float | None) -> str:
    if not ts:
        return "hiç"
    diff = max(0, int(time.time() - ts))
    if diff < 60:
        return f"{diff} sn önce"
    if diff < 3600:
        return f"{diff // 60} dk önce"
    if diff < 86400:
        return f"{diff // 3600} sa {(diff % 3600) // 60} dk önce"
    return f"{diff // 86400} gün önce"


class ResolutionModal(discord.ui.Modal, title="Çözüm Notu Kaydet (Öğrenme)"):
    note = discord.ui.TextInput(
        label="Bu sorun nasıl çözüldü?",
        placeholder="Örn: ER:LC yoklama aralığı 5 sn -> 10 sn yapıldı",
        style=discord.TextStyle.paragraph,
        required=False,
        max_length=300,
    )

    def __init__(self, engine: "BrainEngine", incident_id: int) -> None:
        super().__init__()
        self.engine = engine
        self.incident_id = incident_id

    async def on_submit(self, interaction: discord.Interaction) -> None:
        if (
            not self.engine.settings.has_valid_owner
            or interaction.user is None
            or interaction.user.id != self.engine.settings.owner_id
        ):
            await interaction.response.send_message("❌ Yetkisiz işlem.", ephemeral=True)
            return
        note_text = (self.note.value or "").strip() or "Sahip tarafından çözüldü olarak işaretlendi."
        ok, msg = await self.engine.resolve_incident_manual(self.incident_id, note_text, actor=f"owner:{interaction.user.id}")
        await interaction.response.send_message(f"✅ {msg}", ephemeral=True)


class BrainActionButton(
    discord.ui.DynamicItem[discord.ui.Button],
    template=r"brain:act:(?P<op>[a-z_]+):(?P<inc_id>\d+)",
):
    """Kalıcı DM eylem butonu (`brain:act:<işlem>:<olay_id>`)."""

    def __init__(
        self,
        *,
        op: str,
        inc_id: int,
        label: str,
        style: discord.ButtonStyle,
        emoji: str | None = None,
        disabled: bool = False,
    ) -> None:
        super().__init__(
            discord.ui.Button(
                label=label,
                style=style,
                custom_id=f"brain:act:{op}:{inc_id}",
                emoji=emoji,
                disabled=disabled,
            )
        )
        self.op = op
        self.inc_id = inc_id

    @classmethod
    async def from_custom_id(
        cls,
        interaction: discord.Interaction,
        item: discord.ui.Item[Any],
        match: re.Match[str],
    ) -> "BrainActionButton":
        op = match.group("op")
        inc_id = int(match.group("inc_id"))
        btn = item if isinstance(item, discord.ui.Button) else None
        return cls(
            op=op,
            inc_id=inc_id,
            label=btn.label or op if btn else op,
            style=btn.style if btn else discord.ButtonStyle.secondary,
        )

    async def callback(self, interaction: discord.Interaction) -> None:
        engine: "BrainEngine | None" = getattr(interaction.client, "engine", None)
        if engine is None:
            await interaction.response.send_message("⚠️ Beyin motoru henüz hazır değil.", ephemeral=True)
            return
        if (
            not engine.settings.has_valid_owner
            or interaction.user is None
            or interaction.user.id != engine.settings.owner_id
        ):
            await interaction.response.send_message("❌ Bu butonları yalnızca bot sahibi kullanabilir.", ephemeral=True)
            return

        inc = engine.state.incidents_by_id.get(self.inc_id)
        if self.op == "resolve":
            await interaction.response.send_modal(ResolutionModal(engine, self.inc_id))
            return

        if inc is None:
            await interaction.response.send_message("ℹ️ Bu olay kaydı bellekte bulunamadı (eski kayıt olabilir).", ephemeral=True)
            return

        if self.op == "toggle":
            mod = inc.pause_module or inc.module
            if not mod:
                await interaction.response.send_message("⚠️ Bu olayla ilişkili duraklatılabilir bir modül yok.", ephemeral=True)
                return
            cur = await engine.flags.get_state(inc.bot, mod)
            target_state = "ACTIVE" if cur == "PAUSED" else "PAUSED"
            ok, msg = await engine.flags.set_flag(
                inc.bot,
                mod,
                target_state,
                actor=f"owner:{interaction.user.id}",
                reason=f"DM butonu (Olay #{inc.id}: {inc.title})",
                incident_id=inc.id,
            )
            inc.action_taken = f"`{mod}` {'duraklatıldı' if target_state == 'PAUSED' else 'başlatıldı'}"
            await engine.notifier.send_or_update_incident(inc, force_edit=True)
            await interaction.response.send_message(("✅ " if ok else "❌ ") + msg, ephemeral=True)
            return

        if self.op == "detail":
            detail_embed = engine.notifier.build_detail_embed(inc)
            await interaction.response.send_message(embed=detail_embed, ephemeral=True)
            return

        if self.op == "mute":
            inc.muted_until = time.time() + 3600
            await engine.db.log_action(
                actor=f"owner:{interaction.user.id}",
                action="mute_incident",
                target=inc.key,
                reason="1 saat susturuldu",
                incident_id=inc.id,
            )
            await engine.notifier.send_or_update_incident(inc, force_edit=True)
            await interaction.response.send_message(f"🔕 Olay #{inc.id} **1 saat** boyunca sessize alındı.", ephemeral=True)
            return

        if self.op == "ignore":
            inc.dismissed = True
            inc.muted_until = time.time() + 7200
            await engine.db.log_action(
                actor=f"owner:{interaction.user.id}",
                action="dismiss_suggestion",
                target=inc.key,
                reason="Sahip 'Dokunma' seçti",
                incident_id=inc.id,
            )
            await engine.notifier.send_or_update_incident(inc, force_edit=True)
            await interaction.response.send_message("👍 Anlaşıldı, bu olay için modüle dokunulmayacak.", ephemeral=True)


def build_incident_view(inc: Incident, *, is_paused: bool = False, has_agent: bool = False) -> discord.ui.View:
    view = discord.ui.View(timeout=None)
    mod = inc.pause_module or inc.module
    spec_Allows = inc.bot not in ("guvenlik", "site", "guild", "erlc", "brain")
    if mod and spec_Allows and inc.is_open:
        if not has_agent:
            view.add_item(
                BrainActionButton(
                    op="toggle",
                    inc_id=inc.id,
                    label=f"Duraklat ({mod} • Ajan Yok)",
                    style=discord.ButtonStyle.secondary,
                    emoji="⏸️",
                    disabled=True,
                )
            )
        elif is_paused:
            view.add_item(
                BrainActionButton(
                    op="toggle",
                    inc_id=inc.id,
                    label=f"Tekrar Başlat ({mod})",
                    style=discord.ButtonStyle.success,
                    emoji="▶️",
                )
            )
        else:
            view.add_item(
                BrainActionButton(
                    op="toggle",
                    inc_id=inc.id,
                    label=f"Duraklat ({mod})",
                    style=discord.ButtonStyle.danger,
                    emoji="⏸️",
                )
            )
            view.add_item(
                BrainActionButton(
                    op="ignore",
                    inc_id=inc.id,
                    label="Dokunma",
                    style=discord.ButtonStyle.secondary,
                    emoji="✖️",
                )
            )

    view.add_item(
        BrainActionButton(
            op="detail",
            inc_id=inc.id,
            label="Detay Gör",
            style=discord.ButtonStyle.primary,
            emoji="🔍",
        )
    )
    if inc.is_open:
        view.add_item(
            BrainActionButton(
                op="resolve",
                inc_id=inc.id,
                label="Çözüldü",
                style=discord.ButtonStyle.success,
                emoji="✅",
            )
        )
        view.add_item(
            BrainActionButton(
                op="mute",
                inc_id=inc.id,
                label="Sessize Al (1s)",
                style=discord.ButtonStyle.secondary,
                emoji="🔕",
            )
        )
    return view


class Notifier:
    def __init__(self, bot: discord.Client, engine: "BrainEngine") -> None:
        self.bot = bot
        self.engine = engine
        self._dm_timestamps: deque[float] = deque(maxlen=50)
        self._hourly_buffer: list[Incident] = []
        self._owner_user: discord.User | None = None
        self._lock = asyncio.Lock()

    def is_quiet_hour_now(self) -> bool:
        if self.engine.state.is_quiet:
            return True
        raw = self.engine.settings.quiet_hours
        if not raw or "-" not in raw:
            return False
        try:
            start_s, end_s = raw.split("-", 1)
            sh, sm = (int(x) for x in start_s.strip().split(":"))
            eh, em = (int(x) for x in end_s.strip().split(":"))
            now_tr = datetime.now(tz=TZ_TR)
            cur = now_tr.hour * 60 + now_tr.minute
            st = sh * 60 + sm
            en = eh * 60 + em
            if st <= en:
                return st <= cur < en
            return cur >= st or cur < en
        except Exception:
            return False

    async def _get_owner(self) -> discord.User | None:
        if not self.engine.settings.has_valid_owner:
            log.error(
                "OWNER_ID boş veya geçersiz (%r); hiçbir yere bildirim gönderilmiyor.",
                self.engine.settings.owner_id,
            )
            return None
        owner_id = self.engine.settings.owner_id
        if self._owner_user is not None and self._owner_user.id == owner_id:
            return self._owner_user
        user = self.bot.get_user(owner_id)
        if user is None:
            try:
                user = await self.bot.fetch_user(owner_id)
            except Exception as exc:
                log.error("Sahip kullanıcısı (%s) alınamadı: %s", owner_id, exc)
                return None
        if user is None or getattr(user, "id", None) != owner_id or getattr(user, "bot", False) is True:
            log.error("Alınan kullanıcı OWNER_ID (%s) ile eşleşmiyor veya bir bot hesabı; DM iptal edildi.", owner_id)
            return None
        self._owner_user = user
        return user

    async def _send_owner_dm(
        self,
        owner: discord.User,
        *,
        embed: discord.Embed,
        view: discord.ui.View | None = None,
        context_label: str = "Bildirim",
    ) -> discord.Message | None:
        """Yalnızca `OWNER_ID` kullanıcısına DM gönderir.
        DM kapalıysa (Forbidden/HTTPException) hatayı loglar ve ASLA başka bir kanala/kullanıcıya yedek mesaj atmaz.
        """
        if not self.engine.settings.has_valid_owner or getattr(owner, "id", None) != self.engine.settings.owner_id:
            log.error("Güvenlik engeli: OWNER_ID doğrulaması başarısız, DM gönderilmedi.")
            return None
        if isinstance(owner, discord.abc.GuildChannel):
            log.error("Güvenlik engeli: Sunucu kanalına mesaj gönderimi reddedildi.")
            return None
        try:
            if view is not None:
                return await owner.send(embed=embed, view=view)
            return await owner.send(embed=embed)
        except Exception as exc:
            log.error(
                "%s sahibe (%s) DM olarak gönderilemedi (DM kapalı olabilir; başka kanala yedek mesaj ATILMADI): %s",
                context_label,
                owner.id,
                exc,
            )
            return None

    def _allow_new_dm(self) -> bool:
        now = time.time()
        cutoff = now - 60
        while self._dm_timestamps and self._dm_timestamps[0] < cutoff:
            self._dm_timestamps.popleft()
        if len(self._dm_timestamps) >= self.engine.settings.max_dm_per_minute:
            return False
        self._dm_timestamps.append(now)
        return True

    def build_incident_embed(self, inc: Incident) -> discord.Embed:
        reg = self.engine.registry
        bot_title = reg.display(inc.bot)
        bh = self.engine.state.bots.get(inc.bot)

        if not inc.is_open:
            head = f"🟢 [ÇÖZÜLDÜ] {bot_title} — {inc.title}"
            color = _COLORS["resolved"]
        else:
            emoji = SEV_EMOJI.get(inc.severity, "🟠")
            head = f"{emoji} {bot_title} — {inc.title}"
            color = _COLORS.get(inc.severity, _COLORS["warning"])

        lines: list[str] = []
        if inc.cause:
            lines.append(f"📍 **Neden:** {redact(inc.cause)} *(son {max(1, int((inc.last_seen - inc.first_seen) // 60) or 1)} dk'da {inc.count} kez)*")
        else:
            lines.append(f"📍 **Tekrar:** {inc.count} kez")

        loc = inc.data.get("location")
        if loc:
            lines.append(f"🧩 **Dosya:** `{loc}`")
        elif inc.module:
            lines.append(f"🧩 **Modül:** `{inc.module}`")

        # Başlangıç ve son deploy karşılaştırması
        deploy_note = ""
        if bh and bh.last_deploy_ts > 0:
            diff_min = int((inc.first_seen - bh.last_deploy_ts) / 60)
            if 0 <= diff_min <= 15:
                deploy_note = f" ⚠️ **(son deploy'dan {diff_min} dk sonra başladı!)**"
            else:
                deploy_note = f" *(son deploy: {fmt_tr_time(bh.last_deploy_ts)}, ilgisiz)*"
        lines.append(f"🕒 **Başlangıç:** {fmt_tr_time(inc.first_seen)} TSİ{deploy_note}")

        # AI Kök Neden Teşhisi
        if inc.ai:
            conf = int(float(inc.ai.get("guven_orani", 0)) * (100 if float(inc.ai.get("guven_orani", 0)) <= 1 else 1))
            neden_ai = redact(str(inc.ai.get("neden") or ""))
            cozum_ai = redact(str(inc.ai.get("onerilen_cozum") or ""))
            lines.append(f"🤖 **AI Teşhis (güven %{conf}):** {neden_ai}")
            if cozum_ai:
                lines.append(f"💡 **AI Öneri:** {cozum_ai}")
        elif inc.suggestion:
            lines.append(f"💡 **Öneri:** {redact(inc.suggestion)}")

        # Geçmiş öğrenme bilgisi
        learned = inc.data.get("learned_resolution")
        prev_count = inc.data.get("previous_occurrences", 0)
        if learned:
            lines.append(f"🧠 **Hafıza:** Bu hata daha önce {prev_count} kez görüldü → *\"{redact(learned)}\"* ile çözülmüştü.")

        # Korelasyon bilgisi (zincirleme olaylar)
        if inc.shared_note:
            lines.append(f"🔗 **Korelasyon:** {redact(inc.shared_note)}")
        if inc.children:
            child_titles = []
            for cid in inc.children[:4]:
                c_inc = self.engine.state.incidents_by_id.get(cid)
                if c_inc:
                    child_titles.append(f"`{reg.display(c_inc.bot)}: {c_inc.title}`")
            if child_titles:
                lines.append(f"⛓️ **Bağlı Sonuç Olaylar:** {', '.join(child_titles)}")

        if inc.action_taken:
            lines.append(f"🛡️ **Alınan Önlem:** {inc.action_taken}")
        elif (inc.pause_module or inc.module) and inc.bot in self.engine.registry.bots and not self.engine.flags.has_active_agent(inc.bot):
            lines.append("ℹ️ **Mod (Sadece Öner):** Bu botta `brain_agent.py` kurulu olmadığı için uzaktan duraklatma kapalıdır.")

        # Diğer modüllerin/botların durumu
        if bh and bh.paused_modules:
            lines.append(f"⏸️ **Duraklatılan modüller:** `{', '.join(sorted(bh.paused_modules))}`")
        else:
            lines.append("✅ **Diğer modüller:** Normal çalışıyor")

        if not inc.is_open and inc.resolution:
            lines.append(f"🏁 **Çözüm:** {redact(inc.resolution)} ({fmt_tr_time(inc.resolved_at)} TSİ)")

        embed = discord.Embed(
            title=head[:250],
            description="\n".join(lines)[:4000],
            color=color,
            timestamp=datetime.now(tz=timezone.utc),
        )
        fp_txt = f" • İz: #{inc.fingerprint}" if inc.fingerprint else ""
        embed.set_footer(text=f"Piyade RP Beyin • Olay #{inc.id} • {SEV_LABEL.get(inc.severity, 'Uyarı')}{fp_txt}")
        return embed

    def build_detail_embed(self, inc: Incident) -> discord.Embed:
        reg = self.engine.registry
        embed = discord.Embed(
            title=f"🔍 Olay #{inc.id} Detayı — {reg.display(inc.bot)}",
            color=_COLORS.get(inc.severity, 0x3498DB),
            timestamp=datetime.now(tz=timezone.utc),
        )
        if inc.samples:
            sample_block = "\n".join(redact(s) for s in list(inc.samples)[-5:])
            embed.add_field(
                name="📜 Son Log Örnekleri (Temizlenmiş)",
                value=f"```\n{sample_block[:950]}\n```",
                inline=False,
            )
        snippet = inc.data.get("code_snippet")
        if snippet:
            embed.add_field(
                name=f"📄 Kaynak Kod ({inc.data.get('location', 'GitHub')})",
                value=f"```python\n{redact(snippet)[:950]}\n```",
                inline=False,
            )
        commit_info = inc.data.get("recent_commit")
        if commit_info:
            embed.add_field(
                name="🐙 Son GitHub Commit",
                value=redact(str(commit_info))[:500],
                inline=False,
            )
        return embed

    async def send_or_update_incident(self, inc: Incident, *, force_edit: bool = False) -> None:
        # Bakım modunda bildirim gönderme
        if self.engine.state.in_maintenance:
            return
        # Başka bir kök olayın sonucuysa ayrı DM atma; kök DM güncellenecek
        if inc.root_id and not inc.dm_message_id:
            root = self.engine.state.incidents_by_id.get(inc.root_id)
            if root:
                await self.send_or_update_incident(root, force_edit=True)
            return
        # Susturulmuşsa yeni bildirim gönderme (force_edit hariç)
        if inc.muted_until > time.time() and not force_edit:
            return
        # Bilgi seviyesindeki küçük olayları saatlik özete biriktir
        if inc.severity == "info" and not inc.dm_message_id:
            if inc not in self._hourly_buffer:
                self._hourly_buffer.append(inc)
            return
        # Sessiz saatlerde kritik olmayan olayları beklet
        if inc.severity != "critical" and self.is_quiet_hour_now() and not inc.dm_message_id:
            if inc not in self._hourly_buffer:
                self._hourly_buffer.append(inc)
            return

        owner = await self._get_owner()
        if owner is None:
            return

        mod = inc.pause_module or inc.module
        is_paused = False
        if mod:
            is_paused = (await self.engine.flags.get_state(inc.bot, mod)) == "PAUSED"
        has_agent = self.engine.flags.has_active_agent(inc.bot)

        embed = self.build_incident_embed(inc)
        view = build_incident_view(inc, is_paused=is_paused, has_agent=has_agent)

        async with self._lock:
            if inc.dm_message_id:
                now = time.time()
                if not force_edit and (now - inc.last_dm_edit) < 12:
                    inc.dm_dirty = True
                    return
                try:
                    dm = owner.dm_channel or await owner.create_dm()
                    msg = await dm.fetch_message(int(inc.dm_message_id))
                    await msg.edit(embed=embed, view=view)
                    inc.last_dm_edit = now
                    inc.dm_dirty = False
                    return
                except Exception as exc:
                    log.debug("Mevcut DM düzenlenemedi (%s), yeni gönderilecek.", exc)
                    if not inc.is_open:
                        return

            if not self._allow_new_dm():
                log.warning("DM hız sınırı aşıldı, olay #%s saatlik özete eklendi.", inc.id)
                if inc not in self._hourly_buffer:
                    self._hourly_buffer.append(inc)
                return

            sent = await self._send_owner_dm(owner, embed=embed, view=view, context_label=f"Olay #{inc.id} alarmı")
            if sent is not None:
                inc.dm_message_id = sent.id
                inc.last_dm_edit = time.time()
                inc.dm_dirty = False
                await self.engine.db.update_incident(inc)

    async def flush_hourly_digest(self) -> None:
        if not self._hourly_buffer or self.engine.state.in_maintenance or self.is_quiet_hour_now():
            return
        owner = await self._get_owner()
        if owner is None:
            return
        items = self._hourly_buffer[:]
        self._hourly_buffer.clear()

        lines = []
        for inc in items[:15]:
            bot_name = self.engine.registry.display(inc.bot)
            lines.append(f"• **{bot_name}** — {redact(inc.title)} *({inc.count}x, {fmt_tr_time(inc.last_seen)})*")

        embed = discord.Embed(
            title=f"🟡 Saatlik Bilgi Özeti ({len(items)} olay)",
            description="\n".join(lines)[:4000],
            color=_COLORS["info"],
            timestamp=datetime.now(tz=timezone.utc),
        )
        embed.set_footer(text="Piyade RP Beyin • Saatlik Özet")
        await self._send_owner_dm(owner, embed=embed, context_label="Saatlik özet")

    async def send_daily_report(self) -> bool:
        owner = await self._get_owner()
        if owner is None:
            return False
        embed = await self.engine.build_daily_report_embed()
        sent = await self._send_owner_dm(owner, embed=embed, context_label="Günlük rapor")
        return sent is not None
