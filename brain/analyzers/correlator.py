"""Korelasyon Motoru — Olayları zaman çizelgesinde birleştirir.

Tek bir olaya ayrı ayrı bakmak yerine kök nedeni bulup bağlı olayları onun altına bağlar:
1. ER:LC API 429 / kesintisi aktifken başka bir botta (`ana-bot`, `bot-1`, `ticket-bot`, `rehber`)
   veya sitede (`durum_api`) hata oluşursa, bunları ER:LC kök olayına bağlar. Böylece 3 ayrı DM yerine
   tek bir birleşik DM raporu gider.
2. Bir botta hata, son Railway deploy'undan sonraki 10 dakika içinde başladıysa
   "Yeni deploy/commit kaynaklı" olarak işaretler.
3. Aynı anda (3 dakika içinde) 3+ botta ağ/Discord hatası başlarsa "Ortak altyapı / Discord kesintisi"
   notu düşer.
"""
from __future__ import annotations

import time

from brain.config.registry import Registry
from brain.core.events import Incident
from brain.core.state import WorldState

_ERLC_DEPENDENT_CATEGORIES = {
    "erlc_rate_limit",
    "erlc_down",
    "site_erlc_disconnected",
    "nightly_report_error",
    "missed_scheduled_message",
    "network_error",
    "unhandled_exception",
}


class Correlator:
    def __init__(self, registry: Registry, state: WorldState) -> None:
        self.registry = registry
        self.state = state

    def correlate(self, inc: Incident) -> Incident | None:
        """Yeni veya güncellenen olayı mevcut açık olaylarla ilişkilendirir.

        Eğer bu olay başka bir açık olayın sonucuysa, kök olayı (`root`) döndürür.
        """
        now = time.time()

        # 1. Deploy sonrası regresyon kontrolü
        bh = self.state.bots.get(inc.bot)
        if bh and bh.last_deploy_ts > 0 and 0 <= (inc.first_seen - bh.last_deploy_ts) <= 600:
            diff_m = max(1, int((inc.first_seen - bh.last_deploy_ts) // 60))
            inc.shared_note = f"Bu sorun yeni deploy'dan {diff_m} dk sonra başladı (yeni commit incelenmeli)."

        # 2. ER:LC API Kök Neden Korelasyonu
        root_erlc = self._find_erlc_root(inc, now)
        if root_erlc and root_erlc.id != inc.id:
            inc.root_id = root_erlc.id
            if inc.id not in root_erlc.children:
                root_erlc.children.append(inc.id)
            root_erlc.shared_note = (
                "Kök neden: ER:LC API hız sınırı / kesintisi. "
                f"Toplam {len(root_erlc.children)} bağlı modül/servis etkilendi."
            )
            return root_erlc

        # 3. Çoklu bot ağ / Discord kesintisi korelasyonu
        if inc.category in ("network_error", "discord_rate_limit"):
            peers = [
                other
                for other in self.state.open_incidents()
                if other.id != inc.id
                and other.category == inc.category
                and abs(other.last_seen - now) <= 180
            ]
            if len(peers) >= 2:
                bots_affected = sorted({self.registry.display(p.bot) for p in peers} | {self.registry.display(inc.bot)})
                note = f"Ortak dış servis / Discord sorunu ({', '.join(bots_affected)} aynı anda etkilendi)."
                inc.shared_note = note
                for p in peers:
                    p.shared_note = note

        return None

    def _find_erlc_root(self, inc: Incident, now: float) -> Incident | None:
        # Kendisi zaten ilk ER:LC olayıysa kök odur
        open_erlc = [
            o
            for o in self.state.open_incidents()
            if o.category in ("erlc_rate_limit", "erlc_down") and o.root_id is None
        ]
        if not open_erlc:
            return None
        root = min(open_erlc, key=lambda x: x.first_seen)
        if root.id == inc.id:
            return None

        # İncelenen olay ER:LC bağımlı bir botta veya kategoride mi?
        spec = self.registry.get(inc.bot)
        uses_erlc = (spec and "erlc" in spec.dependencies) or inc.bot in ("site", "erlc")
        if uses_erlc and inc.category in _ERLC_DEPENDENT_CATEGORIES and (now - root.last_seen) <= 600:
            return root
        return None
