"""Piyade RP — Beyin Nabız & Modül Bayrağı Ajanı (`cogs/brain_agent.py`).

Bu tek dosya herhangi bir Python `discord.py` botunun `cogs/` klasörüne bırakıldığında
(`main.py` dosyasına dokunmadan) otomatik yüklenir.

Ekstra paket gerektirmez (yalnızca `discord.py` ve `aiohttp` kullanır).

Ortam Değişkenleri (`os.environ` üzerinden okunur):
- `BRAIN_BOT_NAME`  : Botun `registry.yaml` içindeki adı (örn: `rehber`, `yapay-zeka`, `bot-1`, `ticket-bot`, `ana-bot`)
                      (Geriye dönük uyumluluk için `BRAIN_BOT_KEY` de desteklenir.)
- `BRAIN_URL`       : Beyin servisinin adresi (örn: `http://piyade-brain.railway.internal:8080` veya `https://...up.railway.app`)
- `BRAIN_AGENT_KEY` : Beyin'deki `AGENT_KEYS` içinde bu bot için tanımlanan gizli anahtar (en az 16 karakter)

Güvenlik ve Çökmeyi Önleme İlkeleri (Fail-Open):
1. Yalnızca metrik gönderir: gateway ping (ms), RAM (MB), event loop gecikmesi (ms), açık cog listesi.
   Mesaj içeriği, kullanıcı verisi, stack trace içeriği, token veya ortam değişkeni değeri ASLA gönderilmez.
2. Tüm ağ çağrıları kısa zaman aşımı (`5 sn`) ve `try/except` içindedir.
3. Beyin'e ulaşılamazsa veya bayrak okunamazsa tüm modüller varsayılan olarak `ACTIVE` kabul edilir;
   asla kendiliğinden "duraklatıldı" varsayılmaz ve bot normal çalışmaya devam eder.
4. Kalıcı butonların (`Persistent View`) `custom_id` değerlerine dokunmaz.
"""
from __future__ import annotations

import asyncio
import ctypes
import logging
import os
import sys
import time
from typing import Any

import aiohttp
import discord
from discord.ext import commands, tasks

log = logging.getLogger("brain_agent")


def _get_rss_mb() -> float:
    """Ekstra kütüphane (`psutil`) gerektirmeden sürecin RAM kullanımını (MB) ölçer."""
    if os.path.exists("/proc/self/status"):
        try:
            with open("/proc/self/status", "r", encoding="utf-8") as f:
                for line in f:
                    if line.startswith("VmRSS:"):
                        kb = int(line.split()[1])
                        return round(kb / 1024.0, 2)
        except Exception:
            pass

    if sys.platform == "win32":
        try:
            class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
                _fields_ = [
                    ("cb", ctypes.c_ulong),
                    ("PageFaultCount", ctypes.c_ulong),
                    ("PeakWorkingSetSize", ctypes.c_size_t),
                    ("WorkingSetSize", ctypes.c_size_t),
                    ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                    ("PagefileUsage", ctypes.c_size_t),
                    ("PeakPagefileUsage", ctypes.c_size_t),
                ]

            pmc = PROCESS_MEMORY_COUNTERS()
            pmc.cb = ctypes.sizeof(PROCESS_MEMORY_COUNTERS)
            handle = ctypes.windll.kernel32.GetCurrentProcess()
            if ctypes.windll.psapi.GetProcessMemoryInfo(handle, ctypes.byref(pmc), pmc.cb):
                return round(pmc.WorkingSetSize / (1024.0 * 1024.0), 2)
        except Exception:
            pass
    return 0.0


async def _measure_loop_lag_ms() -> float:
    t0 = time.perf_counter()
    await asyncio.sleep(0.05)
    elapsed = time.perf_counter() - t0
    return round(max(0.0, (elapsed - 0.05) * 1000.0), 2)


def _module_of_cog(cog: Any) -> str:
    if cog is None:
        return ""
    mod = getattr(cog, "__module__", "") or ""
    return mod.split(".")[-1]


class BrainAgent(commands.Cog):
    def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot
        self.bot_name = (
            os.environ.get("BRAIN_BOT_NAME")
            or os.environ.get("BRAIN_BOT_KEY")
            or ""
        ).strip()
        self.brain_url = (os.environ.get("BRAIN_URL") or "").strip().rstrip("/")
        self.agent_key = (os.environ.get("BRAIN_AGENT_KEY") or "").strip()

        # Varsayılan: hiçbir modül duraklatılmış değil (Fail-Open / ACTIVE)
        self.paused_modules: set[str] = set()
        self.last_command_ts: float = 0.0
        self._stopped_loops: dict[str, list[tasks.Loop[Any]]] = {}
        self._orig_tree_check = getattr(bot.tree, "interaction_check", None)

        # Slash komutları için modül bayrağı kontrolünü zincirle (custom_id'lere dokunmaz)
        bot.tree.interaction_check = self._tree_interaction_check  # type: ignore[method-assign]

        if self.brain_url and self.agent_key and self.bot_name:
            self.heartbeat_loop.start()
        else:
            log.info("[BrainAgent] BRAIN_BOT_NAME, BRAIN_URL veya BRAIN_AGENT_KEY tanımlı değil; ajan pasif modda.")

    def cog_unload(self) -> None:
        try:
            if self.heartbeat_loop.is_running():
                self.heartbeat_loop.cancel()
            if self._orig_tree_check is not None:
                self.bot.tree.interaction_check = self._orig_tree_check  # type: ignore[method-assign]
        except Exception as exc:
            log.warning("[BrainAgent] cog_unload hatası: %s", exc)

    async def _tree_interaction_check(self, interaction: discord.Interaction) -> bool:
        try:
            self.last_command_ts = time.time()
            cmd = interaction.command
            if cmd is not None:
                binding = getattr(cmd, "binding", None)
                mod_name = _module_of_cog(binding) or getattr(cmd, "module", "").split(".")[-1]
                if mod_name and mod_name in self.paused_modules:
                    try:
                        if interaction.response.is_done():
                            await interaction.followup.send(
                                "🛠️ Bu özellik geçici olarak bakımda, kısa süre içinde tekrar açılacaktır.",
                                ephemeral=True,
                            )
                        else:
                            await interaction.response.send_message(
                                "🛠️ Bu özellik geçici olarak bakımda, kısa süre içinde tekrar açılacaktır.",
                                ephemeral=True,
                            )
                    except Exception:
                        pass
                    return False

            if self._orig_tree_check is not None:
                return await self._orig_tree_check(interaction)
        except Exception as exc:
            log.warning("[BrainAgent] interaction_check hatası (fail-open): %s", exc)
        return True

    async def bot_check(self, ctx: commands.Context[Any]) -> bool:
        try:
            self.last_command_ts = time.time()
            mod_name = _module_of_cog(ctx.cog)
            if mod_name and mod_name in self.paused_modules:
                try:
                    await ctx.reply("🛠️ Bu özellik geçici olarak bakımda, kısa süre içinde tekrar açılacaktır.")
                except Exception:
                    pass
                return False
        except Exception as exc:
            log.warning("[BrainAgent] bot_check hatası (fail-open): %s", exc)
        return True

    def _apply_flags(self, flags: dict[str, Any]) -> None:
        try:
            # Yalnızca açıkça "PAUSED" olan modüller duraklatılır; diğer her değer ACTIVE sayılır.
            new_paused = {
                str(mod)
                for mod, st in flags.items()
                if isinstance(mod, str) and str(st).upper() == "PAUSED" and mod != "brain_agent"
            }

            # Yeni duraklatılan modüllerin arka plan döngülerini durdur
            for mod in new_paused - self.paused_modules:
                stopped: list[tasks.Loop[Any]] = []
                for cog in self.bot.cogs.values():
                    if _module_of_cog(cog) == mod:
                        for attr in dir(cog):
                            val = getattr(cog, attr, None)
                            if isinstance(val, tasks.Loop) and val.is_running():
                                val.cancel()
                                stopped.append(val)
                if stopped:
                    self._stopped_loops[mod] = stopped
                log.warning("[BrainAgent] Modül duraklatıldı (PAUSED): %s", mod)

            # Tekrar ACTIVE olan modüllerin döngülerini başlat
            for mod in self.paused_modules - new_paused:
                for lp in self._stopped_loops.pop(mod, []):
                    if not lp.is_running():
                        try:
                            lp.start()
                        except Exception:
                            pass
                log.info("[BrainAgent] Modül tekrar başlatıldı (ACTIVE): %s", mod)

            self.paused_modules = new_paused
        except Exception as exc:
            log.warning("[BrainAgent] Bayrak uygulama hatası (fail-open): %s", exc)

    @tasks.loop(seconds=30)
    async def heartbeat_loop(self) -> None:
        try:
            lag_ms = await _measure_loop_lag_ms()
            ram_mb = _get_rss_mb()
            raw_latency = getattr(self.bot, "latency", 0.0) or 0.0
            ping_ms = round(raw_latency * 1000.0, 1) if raw_latency == raw_latency else 0.0
            loaded = sorted({_module_of_cog(c) for c in self.bot.cogs.values() if _module_of_cog(c)})

            # Kural 5: Yalnızca metrikler gönderilir (mesaj, kullanıcı verisi, token veya env gönderilmez)
            payload = {
                "bot": self.bot_name,
                "ts": time.time(),
                "ping_ms": ping_ms,
                "ram_mb": ram_mb,
                "loop_lag_ms": lag_ms,
                "loaded_cogs": loaded,
                "last_command_ts": self.last_command_ts,
                "queue_size": 0,
            }
            timeout = aiohttp.ClientTimeout(total=5)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.post(
                    f"{self.brain_url}/agent/heartbeat",
                    headers={"X-Brain-Key": self.agent_key},
                    json=payload,
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json(content_type=None)
                        if isinstance(data, dict) and isinstance(data.get("flags"), dict):
                            self._apply_flags(data["flags"])
        except Exception as exc:
            log.debug("[BrainAgent] Beyin'e ulaşılamadı (bot normal çalışmaya devam ediyor): %s", exc)

    @heartbeat_loop.before_loop
    async def _wait_ready(self) -> None:
        await self.bot.wait_until_ready()


async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(BrainAgent(bot))
