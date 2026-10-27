"""Beyin Slash Komutları (Yalnızca `OWNER_ID` kullanabilir).

Komutlar:
- `/durum`                          : Tüm botların ve sitenin canlı panosu
- `/bot <isim>`                     : Seçilen botun detaylı sağlık ve log raporu
- `/modul <bot> <modul> <islem>`    : Modülü elle duraklat veya başlat (Redis/DB bayrağı)
- `/rapor [saat]`                   : Son 24 saatlik (veya belirtilen sürelik) sağlık özeti
- `/neden [bot]`                    : Son sorunun kök nedenini ve AI açıklamasını gösterir
- `/sessiz <sure>`                  : Bildirimleri geçici olarak susturur (örn: 30dk, 2sa, kapat)
- `/bakim <sure>`                   : Planlı bakım modunu açar/kapatır (alarm üretilmez)
"""
from __future__ import annotations

import re
import time
from typing import TYPE_CHECKING, Literal

import discord
from discord import app_commands
from discord.ext import commands

from brain.actions.notify import fmt_tr_time
from brain.core.redactor import redact

if TYPE_CHECKING:
    from brain.engine import BrainEngine


def parse_duration_seconds(raw: str) -> int | None:
    """'30dk', '2sa', '90m', '1h', 'kapat', '0' gibi süre dizelerini saniyeye çevirir."""
    s = (raw or "").strip().lower()
    if s in ("0", "kapat", "ac", "aç", "iptal", "off", "bitir"):
        return 0
    m = re.match(r"^(\d+)\s*(sn|s|dk|d|m|sa|saat|h|g|gun|gün)?$", s)
    if not m:
        return None
    val = int(m.group(1))
    unit = m.group(2) or "dk"
    if unit in ("sn", "s"):
        return val
    if unit in ("dk", "d", "m"):
        return val * 60
    if unit in ("sa", "saat", "h"):
        return val * 3600
    if unit in ("g", "gun", "gün"):
        return val * 86400
    return val * 60


class BrainSlashCog(commands.Cog):
    def __init__(self, bot: commands.Bot, engine: "BrainEngine") -> None:
        self.bot = bot
        self.engine = engine

    def _is_owner(self, interaction: discord.Interaction) -> bool:
        return bool(
            self.engine.settings.has_valid_owner
            and interaction.user is not None
            and interaction.user.id == self.engine.settings.owner_id
        )

    async def _deny(self, interaction: discord.Interaction) -> None:
        if interaction.response.is_done():
            await interaction.followup.send(
                "❌ Bu komutu yalnızca **Beyin Bot Sahibi** kullanabilir.",
                ephemeral=True,
            )
        else:
            await interaction.response.send_message(
                "❌ Bu komutu yalnızca **Beyin Bot Sahibi** kullanabilir.",
                ephemeral=True,
            )

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if not self._is_owner(interaction):
            await self._deny(interaction)
            return False
        return True

    # ── Autocomplete yardımcıları ──
    async def _bot_autocomplete(
        self,
        interaction: discord.Interaction,
        current: str,
    ) -> list[app_commands.Choice[str]]:
        if not self._is_owner(interaction):
            return []
        cur = current.lower().strip()
        out: list[app_commands.Choice[str]] = []
        for k, spec in self.engine.registry.bots.items():
            label = f"{spec.name} ({k})"
            if not cur or cur in k.lower() or cur in spec.name.lower():
                out.append(app_commands.Choice(name=label[:100], value=k))
        return out[:25]

    async def _module_autocomplete(
        self,
        interaction: discord.Interaction,
        current: str,
    ) -> list[app_commands.Choice[str]]:
        if not self._is_owner(interaction):
            return []
        bot_key = getattr(interaction.namespace, "bot", None)
        spec = self.engine.registry.get(str(bot_key or ""))
        modules = spec.modules if spec else []
        cur = current.lower().strip()
        return [
            app_commands.Choice(name=m, value=m)
            for m in modules
            if not cur or cur in m.lower()
        ][:25]

    # ── 1. /durum ──
    @app_commands.command(name="durum", description="Tüm botların, sitenin ve ER:LC köprüsünün canlı sağlık panosu.")
    async def cmd_durum(self, interaction: discord.Interaction) -> None:
        if not self._is_owner(interaction):
            return await self._deny(interaction)
        embed = self.engine.build_status_embed()
        await interaction.response.send_message(embed=embed, ephemeral=True)

    # ── 2. /bot <isim> ──
    @app_commands.command(name="bot", description="Seçilen botun RAM, ping, modül bayrakları ve son hata detaylarını gösterir.")
    @app_commands.describe(isim="İncelenecek botun anahtarı (örn: ana-bot, ticket-bot, rehber)")
    @app_commands.autocomplete(isim=_bot_autocomplete)
    async def cmd_bot(self, interaction: discord.Interaction, isim: str) -> None:
        if not self._is_owner(interaction):
            return await self._deny(interaction)
        if isim not in self.engine.registry.bots:
            valid = ", ".join(f"`{k}`" for k in self.engine.registry.bots)
            await interaction.response.send_message(f"⚠️ Bilinmeyen bot: `{isim}`. Geçerli botlar: {valid}", ephemeral=True)
            return
        embed = await self.engine.build_bot_detail_embed(isim)
        await interaction.response.send_message(embed=embed, ephemeral=True)

    # ── 3. /modul <bot> <modul> <islem> ──
    @app_commands.command(name="modul", description="Bir botun modülünü (cog) elle duraklatır veya tekrar başlatır.")
    @app_commands.describe(
        bot="Hedef bot (örn: ana-bot, yapay-zeka)",
        modul="Hedef modül / cog adı (örn: live_radar, ai_ticket_assistant)",
        islem="duraklat veya başlat",
    )
    @app_commands.autocomplete(bot=_bot_autocomplete, modul=_module_autocomplete)
    async def cmd_modul(
        self,
        interaction: discord.Interaction,
        bot: str,
        modul: str,
        islem: Literal["duraklat", "başlat"],
    ) -> None:
        if not self._is_owner(interaction):
            return await self._deny(interaction)
        if bot not in self.engine.registry.bots:
            await interaction.response.send_message(f"⚠️ Bilinmeyen bot: `{bot}`.", ephemeral=True)
            return
        target_state = "PAUSED" if islem == "duraklat" else "ACTIVE"
        ok, msg = await self.engine.flags.set_flag(
            bot,
            modul,
            target_state,
            actor=f"owner:{interaction.user.id}",
            reason="Slash komutu (/modul)",
        )
        await interaction.response.send_message(("✅ " if ok else "❌ ") + msg, ephemeral=True)

    # ── 4. /rapor ──
    @app_commands.command(name="rapor", description="Son 24 saatin (veya belirtilen saatin) olay ve eylem özetini gösterir.")
    @app_commands.describe(saat="Kaç saatlik geçmiş incelensin? (Varsayılan: 24)")
    async def cmd_rapor(self, interaction: discord.Interaction, saat: app_commands.Range[int, 1, 168] = 24) -> None:
        if not self._is_owner(interaction):
            return await self._deny(interaction)
        embed = await self.engine.build_daily_report_embed(hours=saat)
        await interaction.response.send_message(embed=embed, ephemeral=True)

    # ── 5. /neden ──
    @app_commands.command(name="neden", description="Son yaşanan sorunun kök nedenini, kod satırını ve AI teşhisini açıklar.")
    @app_commands.describe(bot="Belirli bir botun son sorununu incele (boş bırakılırsa en son olay)")
    @app_commands.autocomplete(bot=_bot_autocomplete)
    async def cmd_neden(self, interaction: discord.Interaction, bot: str | None = None) -> None:
        if not self._is_owner(interaction):
            return await self._deny(interaction)
        await interaction.response.defer(ephemeral=True, thinking=True)

        # Önce bellekteki en son olaya bak, yoksa veritabanından çek
        candidates = [
            inc
            for inc in self.engine.state.incidents_by_id.values()
            if (not bot or inc.bot == bot)
        ]
        if candidates:
            inc = max(candidates, key=lambda x: x.last_seen)
            if inc.ai is None and self.engine.settings.ai_enabled:
                await self.engine._enrich_incident_async(inc)
            embed = self.engine.notifier.build_incident_embed(inc)
            detail = self.engine.notifier.build_detail_embed(inc)
            await interaction.followup.send(embeds=[embed, detail], ephemeral=True)
            return

        row = await self.engine.db.latest_incident(bot=bot)
        if not row:
            await interaction.followup.send("✅ Kayıtlı herhangi bir sorun bulunamadı.", ephemeral=True)
            return

        embed = discord.Embed(
            title=f"🧠 Son Olay Özeti — #{row['id']} ({self.engine.registry.display(str(row['bot']))})",
            description=(
                f"**Başlık:** {redact(str(row.get('title') or ''))}\n"
                f"**Neden:** {redact(str(row.get('cause') or '—'))}\n"
                f"**Öneri:** {redact(str(row.get('suggestion') or '—'))}\n"
                f"**Son Görülme:** {fmt_tr_time(float(row.get('last_seen') or 0))} TSİ ({row.get('count', 1)}x)"
            ),
            color=0x3498DB,
        )
        if row.get("sample_log"):
            embed.add_field(
                name="📜 Örnek Log",
                value=f"```\n{redact(str(row['sample_log']))[:900]}\n```",
                inline=False,
            )
        await interaction.followup.send(embed=embed, ephemeral=True)

    # ── 6. /sessiz <sure> ──
    @app_commands.command(name="sessiz", description="Kritik olmayan DM bildirimlerini belirtilen süre boyunca susturur.")
    @app_commands.describe(sure="Süre (örn: 30dk, 2sa, 8sa veya 'kapat')")
    async def cmd_sessiz(self, interaction: discord.Interaction, sure: str) -> None:
        if not self._is_owner(interaction):
            return await self._deny(interaction)
        secs = parse_duration_seconds(sure)
        if secs is None:
            await interaction.response.send_message("⚠️ Geçersiz süre. Örnek: `30dk`, `2sa`, `kapat`.", ephemeral=True)
            return
        if secs == 0:
            self.engine.state.quiet_until = 0.0
            await self.engine.db.set_kv("quiet_until", "0")
            await interaction.response.send_message("🔔 Sessiz mod **kapatıldı**. Bildirimler normal akışında.", ephemeral=True)
            return

        until = time.time() + secs
        self.engine.state.quiet_until = until
        await self.engine.db.set_kv("quiet_until", str(until))
        await self.engine.db.log_action(
            actor=f"owner:{interaction.user.id}",
            action="quiet_mode",
            target="brain",
            reason=f"{sure} ({secs} sn)",
        )
        await interaction.response.send_message(
            f"🔕 Sessiz mod **{fmt_tr_time(until)} TSİ** saatine kadar açıldı *(🔴 Kritik alarmlar yine de iletilir)*.",
            ephemeral=True,
        )

    # ── 7. /bakim <sure> ──
    @app_commands.command(name="bakim", description="Planlı bakım modunu açar veya kapatır (bakım süresince alarm üretilmez).")
    @app_commands.describe(sure="Süre (örn: 30dk, 1sa, 2sa veya 'kapat')")
    async def cmd_bakim(self, interaction: discord.Interaction, sure: str) -> None:
        if not self._is_owner(interaction):
            return await self._deny(interaction)
        secs = parse_duration_seconds(sure)
        if secs is None:
            await interaction.response.send_message("⚠️ Geçersiz süre. Örnek: `30dk`, `1sa`, `kapat`.", ephemeral=True)
            return
        if secs == 0:
            self.engine.state.maintenance_until = 0.0
            await self.engine.db.set_kv("maintenance_until", "0")
            await interaction.response.send_message("🛠️ Planlı bakım modu **kapatıldı**. Beyin tekrar nöbette.", ephemeral=True)
            return

        until = time.time() + secs
        self.engine.state.maintenance_until = until
        await self.engine.db.set_kv("maintenance_until", str(until))
        await self.engine.db.log_action(
            actor=f"owner:{interaction.user.id}",
            action="maintenance_mode",
            target="brain",
            reason=f"{sure} ({secs} sn)",
        )
        await interaction.response.send_message(
            f"🛠️ Planlı bakım modu **{fmt_tr_time(until)} TSİ** saatine kadar etkinleştirildi. Bu sürede DM alarmı gönderilmeyecek.",
            ephemeral=True,
        )

    # ── 8. /mod <secim> ──
    @app_commands.command(name="mod", description="Beyin eylem modunu değiştirir: Sadece Öner (varsayılan) veya Otomatik Devre Kesici.")
    @app_commands.describe(secim="sadece_oner (onaylı) veya otomatik (devre kesici açık)")
    async def cmd_mod(
        self,
        interaction: discord.Interaction,
        secim: Literal["sadece_oner", "otomatik"],
    ) -> None:
        if not self._is_owner(interaction):
            return await self._deny(interaction)
        self.engine.settings.auto_actions = secim == "otomatik"
        await self.engine.db.set_kv("auto_actions", "1" if self.engine.settings.auto_actions else "0")
        await self.engine.db.log_action(
            actor=f"owner:{interaction.user.id}",
            action="change_action_mode",
            target="brain",
            reason=self.engine.settings.action_mode_label,
        )
        await interaction.response.send_message(
            f"🛡️ Eylem modu **{self.engine.settings.action_mode_label}** olarak güncellendi.",
            ephemeral=True,
        )

    # ── 9. /denetim ──
    @app_commands.command(name="denetim", description="GitHub gizli anahtar sızıntısı ve Railway Volume denetimini çalıştırır.")
    async def cmd_denetim(self, interaction: discord.Interaction) -> None:
        if not self._is_owner(interaction):
            return await self._deny(interaction)
        await interaction.response.defer(ephemeral=True, thinking=True)
        findings = await self.engine.auditor.run_full_audit()
        if not findings:
            await interaction.followup.send("✅ Denetim tamamlandı: Herhangi bir sızıntı veya Volume sorunu bulunmadı.", ephemeral=True)
            return
        lines = [f"• {redact(f)}" for f in findings[:15]]
        await interaction.followup.send("🔍 **Denetim Bulguları:**\n" + "\n".join(lines), ephemeral=True)

    # ── 10. /kalkan <ip> ──
    @app_commands.command(name="kalkan", description="Cloudflare üzerinden saldırgan bir IP adresini engeller.")
    @app_commands.describe(ip="Engellenecek IPv4/IPv6 adresi", neden="Engelleme nedeni")
    async def cmd_kalkan(self, interaction: discord.Interaction, ip: str, neden: str = "Manuel kalkan") -> None:
        if not self._is_owner(interaction):
            return await self._deny(interaction)
        ok, msg = await self.engine.cloudflare.block_ip(ip, reason=neden, actor=f"owner:{interaction.user.id}")
        await interaction.response.send_message(("✅ " if ok else "❌ ") + msg, ephemeral=True)
