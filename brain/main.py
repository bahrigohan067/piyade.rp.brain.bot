"""Beyin Botu Ana Giriş Noktası (`python -m brain`)."""
from __future__ import annotations

import asyncio
import logging
import sys

import discord
from discord.ext import commands, tasks

from brain.actions.notify import BrainActionButton
from brain.commands.slash import BrainSlashCog
from brain.config.registry import Registry, load_registry
from brain.config.settings import Settings, load_settings
from brain.engine import BrainEngine

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("brain.main")


def build_intents(privileged: bool = True) -> discord.Intents:
    intents = discord.Intents.default()
    intents.guilds = True
    intents.voice_states = True
    intents.messages = True
    intents.moderation = True
    if privileged:
        intents.members = True
        intents.presences = True
        intents.message_content = True
    return intents


class BrainBot(commands.Bot):
    def __init__(self, settings: Settings, registry: Registry, *, privileged_intents: bool = True) -> None:
        # Kural 3: OWNER_ID boşsa veya geçersizse bot açılırken hata fırlatır
        settings.validate_owner_id()
        super().__init__(
            command_prefix="!brain_",
            intents=build_intents(privileged=privileged_intents),
            help_command=None,
        )
        self.settings = settings
        self.registry = registry
        self.engine = BrainEngine(self, settings, registry)
        self.tree.interaction_check = self._tree_owner_check  # type: ignore[method-assign]

    async def _tree_owner_check(self, interaction: discord.Interaction) -> bool:
        if (
            not self.settings.has_valid_owner
            or interaction.user is None
            or interaction.user.id != self.settings.owner_id
        ):
            try:
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
            except Exception:
                pass
            return False
        return True

    async def setup_hook(self) -> None:
        await self.engine.start()
        self.add_dynamic_items(BrainActionButton)
        await self.add_cog(BrainSlashCog(self, self.engine))

        # Slash komutlarını hem sunucuya (anında görünmesi için) hem global (DM'de çalışması için) senkronize et
        try:
            if self.settings.guild_id:
                guild_obj = discord.Object(id=self.settings.guild_id)
                self.tree.copy_global_to(guild=guild_obj)
                synced = await self.tree.sync(guild=guild_obj)
                log.info("[SYNC] %d slash komutu sunucuya (%s) senkronize edildi.", len(synced), self.settings.guild_id)
            await self.tree.sync()
        except Exception as exc:
            log.warning("[SYNC] Slash komut senkronizasyon uyarısı: %s", exc)

        # Arka plan izleme döngülerini başlat
        self.railway_loop.change_interval(seconds=self.settings.railway_poll_seconds)
        self.web_loop.change_interval(seconds=self.settings.web_poll_seconds)
        self.railway_loop.start()
        self.web_loop.start()
        self.heartbeat_check_loop.start()
        self.minute_watch_loop.start()
        self.hourly_digest_loop.start()

    async def close(self) -> None:
        for lp in (
            self.railway_loop,
            self.web_loop,
            self.heartbeat_check_loop,
            self.minute_watch_loop,
            self.hourly_digest_loop,
        ):
            if lp.is_running():
                lp.cancel()
        await self.engine.stop()
        await super().close()

    async def on_ready(self) -> None:
        log.info("=" * 62)
        log.info("🧠 Piyade RP BEYİN Botu Aktif: %s (%s)", self.user, self.user.id if self.user else "?")
        log.info("👑 Sahip ID (OWNER_ID): %s", self.settings.owner_id)
        log.info("🏠 Hedef Sunucu (GUILD_ID): %s", self.settings.guild_id)
        log.info("🛡️ Çalışma Modu: %s", self.settings.action_mode_label)
        log.info("📡 İzlenen Bot Sayısı: %d | Site: %s", len(self.registry.bots), self.registry.site.base_url if self.registry.site else "yok")
        if self.settings.missing:
            log.info("ℹ️ Opsiyonel / Eksik Ayarlar: %s", ", ".join(self.settings.missing))
        log.info("⚠️ Hatırlatma: Güvenlik botunun WHITELIST_BOTS listesine Beyin Bot ID'sini (%s) eklemeyi unutmayın!", self.user.id if self.user else "?")
        log.info("=" * 62)
        if not self.engine.auditor._ran_once:
            asyncio.create_task(self.engine.auditor.run_startup_audit())

    # ── Discord Olay Dinleyicileri ──
    async def on_message(self, message: discord.Message) -> None:
        await self.engine.discord_watch.on_message(message)

    async def on_guild_channel_create(self, channel: discord.abc.GuildChannel) -> None:
        await self.engine.discord_watch.on_guild_channel_create(channel)

    async def on_member_join(self, member: discord.Member) -> None:
        await self.engine.discord_watch.on_member_join(member)

    async def on_audit_log_entry_create(self, entry: discord.AuditLogEntry) -> None:
        await self.engine.discord_watch.on_audit_log_entry(entry)

    # ── Zamanlanmış Toplayıcı Döngüleri ──
    @tasks.loop(seconds=30)
    async def railway_loop(self) -> None:
        try:
            await self.engine.railway.poll_once()
        except Exception as exc:
            log.debug("Railway döngü hatası: %s", exc)

    @tasks.loop(seconds=30)
    async def web_loop(self) -> None:
        try:
            await self.engine.web.poll_once()
        except Exception as exc:
            log.debug("Web döngü hatası: %s", exc)

    @tasks.loop(seconds=20)
    async def heartbeat_check_loop(self) -> None:
        try:
            await self.engine.http_server.check_stale_heartbeats()
        except Exception as exc:
            log.debug("Nabız kontrol döngüsü hatası: %s", exc)

    @tasks.loop(seconds=60)
    async def minute_watch_loop(self) -> None:
        try:
            await self.engine.discord_watch.check_minute_tasks()
            await self.engine.sweep_stale_incidents()
        except Exception as exc:
            log.debug("Dakikalık denetim hatası: %s", exc)

    @tasks.loop(minutes=60)
    async def hourly_digest_loop(self) -> None:
        try:
            await self.engine.notifier.flush_hourly_digest()
        except Exception as exc:
            log.debug("Saatlik özet döngüsü hatası: %s", exc)

    @railway_loop.before_loop
    @web_loop.before_loop
    @heartbeat_check_loop.before_loop
    @minute_watch_loop.before_loop
    @hourly_digest_loop.before_loop
    async def _wait_ready(self) -> None:
        await self.wait_until_ready()


async def _run_Async() -> None:
    settings = load_settings()
    registry = load_registry(settings.registry_path)

    if not settings.token:
        log.critical("❌ HATA: BRAIN_TOKEN tanımlı değil! Lütfen .env veya Railway Variables'a BRAIN_TOKEN ekleyin.")
        sys.exit(1)

    if not settings.has_valid_owner:
        log.critical(
            "❌ HATA: OWNER_ID boş veya geçersiz (%r)! Beyin botu geçerli bir OWNER_ID olmadan başlatılamaz ve hiçbir yere mesaj atmaz.",
            settings.owner_id,
        )
        sys.exit(1)

    try:
        bot = BrainBot(settings, registry, privileged_intents=True)
        await bot.start(settings.token)
    except discord.PrivilegedIntentsRequired:
        log.warning("Privileged Intents kapalı! Standart intent'lerle yeniden başlatılıyor (Presence/MessageContent kısıtlı olacak)...")
        bot = BrainBot(settings, registry, privileged_intents=False)
        await bot.start(settings.token)


def main() -> None:
    try:
        asyncio.run(_run_Async())
    except KeyboardInterrupt:
        log.info("Beyin botu kapatıldı.")


if __name__ == "__main__":
    main()
