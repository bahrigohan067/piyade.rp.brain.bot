"""Katman B: İstatistiksel Anomali Tespiti (Hareketli Ortalama + Standart Sapma).

Makine öğrenmesi gerektirmeden her botun "normal" davranışını (RAM, ping, event loop gecikmesi
ve olay/aktivite sıklığı) öğrenir ve büyük sapmalarda (Z-skoru >= 3.0) uyarı üretir.
"""
from __future__ import annotations

import math
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field

from brain.core.events import Event
from brain.core.fingerprint import make_fingerprint


@dataclass
class MetricWindow:
    values: deque[float] = field(default_factory=lambda: deque(maxlen=60))

    def add(self, val: float) -> None:
        self.values.append(val)

    def stats(self) -> tuple[float, float, int]:
        n = len(self.values)
        if n == 0:
            return 0.0, 0.0, 0
        mean = sum(self.values) / n
        if n < 2:
            return mean, 0.0, n
        variance = sum((x - mean) ** 2 for x in self.values) / (n - 1)
        return mean, math.sqrt(variance), n

    def z_score(self, val: float, *, min_samples: int = 12, min_std: float = 5.0) -> float | None:
        mean, std, n = self.stats()
        if n < min_samples:
            return None
        effective_std = max(std, min_std)
        return (val - mean) / effective_std


class AnomalyDetector:
    """Bot metriklerindeki ani sıçramaları (ping, RAM) ve beklenmedik sessizlikleri tespit eder."""

    def __init__(self) -> None:
        # (bot, metric_name) -> MetricWindow
        self._windows: dict[tuple[str, str], MetricWindow] = defaultdict(MetricWindow)
        # bot -> son aktivite zaman damgaları
        self._activity_ts: dict[str, deque[float]] = defaultdict(lambda: deque(maxlen=300))

    def record_activity(self, bot: str, ts: float | None = None) -> None:
        self._activity_ts[bot].append(ts or time.time())

    def check_metrics(self, bot: str, *, ping_ms: float | None = None, ram_mb: float | None = None, ts: float | None = None) -> Event | None:
        now = ts or time.time()

        if ping_ms is not None and ping_ms > 0:
            win = self._windows[(bot, "ping_ms")]
            z = win.z_score(ping_ms, min_samples=12, min_std=20.0)
            mean, std, _ = win.stats()
            win.add(ping_ms)
            if z is not None and z >= 3.5 and ping_ms >= 250:
                return Event(
                    source="anomaly",
                    bot=bot,
                    kind="metric",
                    category="ping_anomaly",
                    severity="warning",
                    title=f"Gateway Ping Anomalisi ({int(ping_ms)} ms)",
                    message=f"Ping normal ortalamanın ({int(mean)}±{int(std)} ms) çok üzerine çıktı: {int(ping_ms)} ms (z={z:.1f}).",
                    cause="Discord Gateway bağlantısında ani gecikme sıçraması tespit edildi.",
                    suggestion="Ağ gecikmesini veya diğer botlardaki eşzamanlı ping artışını kontrol et.",
                    fingerprint=make_fingerprint(bot, "ping_anomaly", "zscore"),
                    incident_key=f"{bot}:ping_anomaly",
                    ts=now,
                )

        if ram_mb is not None and ram_mb > 0:
            win = self._windows[(bot, "ram_mb")]
            z = win.z_score(ram_mb, min_samples=12, min_std=15.0)
            mean, std, _ = win.stats()
            win.add(ram_mb)
            if z is not None and z >= 3.5 and (ram_mb - mean) >= 60:
                return Event(
                    source="anomaly",
                    bot=bot,
                    kind="metric",
                    category="ram_anomaly",
                    severity="warning",
                    title=f"Ani Bellek Sıçraması ({int(ram_mb)} MB)",
                    message=f"RAM kullanımı normal ortalamanın ({int(mean)}±{int(std)} MB) üzerine sıçradı: {int(ram_mb)} MB (z={z:.1f}).",
                    cause="Tek bir komut veya döngü normalden çok daha fazla bellek ayırdı.",
                    suggestion="Son çalışan komutu ve büyük veri yapılarını kontrol et.",
                    fingerprint=make_fingerprint(bot, "ram_anomaly", "zscore"),
                    incident_key=f"{bot}:ram_anomaly",
                    ts=now,
                )

        return None
