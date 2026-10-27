"""Katman A & B: Kural Motoru ve Metrik Anomali Tespiti.

Hızlı, ücretsiz ve deterministik teşhis katmanı.
- Piyade RP botlarının gerçek log kalıplarını (`Hata: <cog>.py →`, `[SYNC HATA]`,
  `[GUNLUK RAPOR GÖNDERME HATA]`, `[GÜVENLİ YAKALAMA]`, vb.) tanır.
- Genel Discord / ağ / ER:LC / Gemini hatalarını sınıflandırır.
- Hata döngüsü (aynı parmak izinin 60 saniyede 10+ kez tekrarlanması) ve
  bellek sızıntısı (RAM'in ardışık nabızlarda sürekli artması) tespiti yapar.
"""
from __future__ import annotations

import re
import time
from collections import defaultdict, deque
from dataclasses import dataclass

from brain.config.registry import Registry
from brain.core.events import Event
from brain.core.fingerprint import extract_location, infer_module, make_fingerprint
from brain.core.state import WorldState


@dataclass
class RuleDef:
    category: str
    pattern: re.Pattern[str]
    severity: str
    title: str
    cause: str
    suggestion: str
    min_count: int = 1
    window: int = 300
    sticky: bool = False


_RULES: list[RuleDef] = [
    # 1. Piyade RP Python botlarında Cog yükleme hataları
    RuleDef(
        category="cog_load_error",
        pattern=re.compile(
            r"(?:❌\s*)?(?:Hata|Modül yüklenemedi|\[HATA\] Cog yüklenemedi):\s*([a-zA-Z0-9_.]+?)(?:\.py)?\s*(?:→|->|—|-)\s*(.+)"
            r"|'cogs\.([a-zA-Z0-9_]+)'\s*yüklenirken hata oluştu:\s*(.+)",
            re.IGNORECASE,
        ),
        severity="critical",
        title="Modül (Cog) Yüklenemedi",
        cause="Bot açılırken bir özellik modülü hata verip devre dışı kaldı; bot çalışıyor görünse de bu özellik ölüdür.",
        suggestion="İlgili cog dosyasındaki import veya sözdizimi hatasını düzeltip yeniden başlat.",
        sticky=True,
    ),
    # 2. Geçersiz veya eksik Discord Token / Intent
    RuleDef(
        category="invalid_token",
        pattern=re.compile(
            r"Improper token has been passed|401 Unauthorized.*token|PrivilegedIntentsRequired|"
            r"TOKEN[A-Z_]* tanımlı değil|Bot Tokeni bulunamadı|Geçersiz Discord Bot Tokeni|"
            r"SERVER_TOKEN ortam değişkeni bulunamadı|BOT_TOKEN tanımlanmamış|MUSIC_TOKEN bulunamadı",
            re.IGNORECASE,
        ),
        severity="critical",
        title="Token veya Intent Hatası (Bot Açılmıyor)",
        cause="Discord bot token'ı geçersiz/eksik ya da Developer Portal'da Privileged Intents kapalı.",
        suggestion="Railway Variables'daki token'ı ve Discord Developer Portal > Bot > Privileged Gateway Intents ayarlarını kontrol et.",
        sticky=True,
    ),
    # 3. Gece 00:00 raporu gönderim hatası (Ticket botu)
    RuleDef(
        category="nightly_report_error",
        pattern=re.compile(r"\[GUNLUK RAPOR GÖNDERME HATA\]", re.IGNORECASE),
        severity="critical",
        title="Gece 00:00 Raporu Gönderilemedi",
        cause="Ticket botu günlük yetkili istatistik raporunu #only-mod kanalına gönderirken hata aldı.",
        suggestion="#only-mod kanal izinlerini ve Ticket botunun ER:LC / Discord erişimini kontrol et.",
        sticky=True,
    ),
    # 4. ER:LC API 429 / Hız sınırı veya bağlantı sorunu
    RuleDef(
        category="erlc_rate_limit",
        pattern=re.compile(r"(?:api\.erlc\.gg|erlc).*?(?:\b429\b|rate\s*limit|too many requests)", re.IGNORECASE),
        severity="warning",
        title="ER:LC API Hız Sınırı (429)",
        cause="ER:LC oyun sunucusu API'sine çok sık istek atıldığı için 429 dönüyor.",
        suggestion="ER:LC yoklama aralığını artır veya yoğun modülü geçici olarak duraklat.",
        min_count=3,
        window=180,
    ),
    # 5. Gemini API Kota / Hata (Yapay Zeka botu)
    RuleDef(
        category="gemini_error",
        pattern=re.compile(
            r"\[GeminiClient\].*(?:HTTP\s*(?:429|5\d\d)|hata|Kota|RESOURCE_EXHAUSTED|zaman aşımı)|"
            r"generativelanguage\.googleapis\.com.*(?:429|RESOURCE_EXHAUSTED)",
            re.IGNORECASE,
        ),
        severity="warning",
        title="Gemini AI API Hatası / Kotası",
        cause="Yapay zeka servisi hız sınırına (429) veya zaman aşımına takılıyor.",
        suggestion="Sorun sürerse `ai_ticket_assistant` modülünü duraklat; kullanıcılar '🛎️ Yetkili Çağır' butonuyla devam edebilir.",
        min_count=3,
        window=300,
    ),
    # 6. Slash komut senkronizasyon hatası
    RuleDef(
        category="sync_error",
        pattern=re.compile(
            r"\[SYNC(?:\s+HATA|\s+UYARI)?\]\s*(?:Senkronizasyon hatası|Komut senkronizasyonu başarısız|Komutlar sunucuya doğrudan aktarılamadı)|"
            r"Global komut senkronizasyon hatası",
            re.IGNORECASE,
        ),
        severity="warning",
        title="Slash Komut Senkronizasyon Hatası",
        cause="Bot açılışta slash komutlarını Discord'a senkronize edemedi (sık yeniden başlatma rate limit'i olabilir).",
        suggestion="Botun çökme döngüsünde olmadığından emin ol; gereksiz yeniden başlatmaları azalt.",
        min_count=1,
        window=600,
    ),
    # 7. Discord Yetki / İzin Hatası (50013 / 50001)
    RuleDef(
        category="missing_permissions",
        pattern=re.compile(r"Missing Permissions|50013|Missing Access|50001", re.IGNORECASE),
        severity="warning",
        title="Discord Rol / Kanal İzin Hatası (50013)",
        cause="Botun işlem yapmaya çalıştığı kanal veya rol üzerinde yetkisi kaldırılmış ya da rol sırası düşmüş.",
        suggestion="Sunucu Ayarları > Roller bölümünden botun rol sırasını ve kanal izinlerini kontrol et.",
        min_count=2,
        window=300,
    ),
    # 8. Discord 429 Rate Limit
    RuleDef(
        category="discord_rate_limit",
        pattern=re.compile(r"We are being rate limited|429 Too Many Requests", re.IGNORECASE),
        severity="warning",
        title="Discord API Rate Limit (429)",
        cause="Bot Discord API'ye kısa sürede çok fazla istek gönderiyor.",
        suggestion="Mesaj/kanal güncelleme sıklığını azalt; toplu işlemleri kuyruklayarak gönder.",
        min_count=4,
        window=120,
    ),
    # 9. Ses / FFmpeg hatası
    RuleDef(
        category="voice_error",
        pattern=re.compile(r"ffmpeg.*(?:error|not found|bulunamadı)|ClientException:\s*Already connected to a voice channel|\[SES\].*hata", re.IGNORECASE),
        severity="warning",
        title="Ses / FFmpeg Oynatma Hatası",
        cause="Ses kanalına bağlanırken veya ses dosyası oynatılırken FFmpeg / bağlantı hatası oluştu.",
        suggestion="Container içinde ffmpeg kurulumunu (`nixpacks.toml`) ve ses dosyalarını kontrol et.",
        min_count=2,
        window=300,
    ),
    # 10. Ağ / Bağlantı kopması
    RuleDef(
        category="network_error",
        pattern=re.compile(
            r"\b(?:ECONNRESET|ETIMEDOUT|ECONNREFUSED|ENOTFOUND|ClientConnectorError|ServerDisconnectedError| asyncio\.TimeoutError)\b",
            re.IGNORECASE,
        ),
        severity="warning",
        title="Ağ / Dış Servis Bağlantı Hatası",
        cause="Dış servise bağlanırken zaman aşımı veya bağlantı sıfırlaması yaşandı.",
        suggestion="Harici API durumunu kontrol et; isteklerde üstel geri çekilme (exponential backoff) kullan.",
        min_count=3,
        window=180,
    ),
    # 11. Yakalanmamış İstisna / Traceback
    RuleDef(
        category="unhandled_exception",
        pattern=re.compile(
            r"Traceback \(most recent call last\):|"
            r"UnhandledPromiseRejection|"
            r"\[GÜVENLİ YAKALAMA - Unhandled Rejection\]|"
            r"\[GÜVENLİ YAKALAMA - Uncaught Exception\]|"
            r"Komut Hatası:|"
            r"\b(?:KeyError|AttributeError|TypeError|ValueError|IndexError|ZeroDivisionError|ReferenceError):\s+.+",
        ),
        severity="warning",
        title="Kod Hatası (Exception / Traceback)",
        cause="Çalışma zamanında yakalanmamış bir kod istisnası meydana geldi.",
        suggestion="Hata satırındaki değişken tiplerini ve `None` kontrollerini incele.",
        min_count=1,
        window=300,
    ),
]


class RuleEngine:
    def __init__(self, registry: Registry, state: WorldState) -> None:
        self.registry = registry
        self.state = state
        # fingerprint -> deque[timestamp] (hata döngüsü / fırtınası tespiti için)
        self._fp_hits: dict[str, deque[float]] = defaultdict(lambda: deque(maxlen=40))
        # bot -> deque[ram_mb] (bellek sızıntısı eğilimi için)
        self._ram_history: dict[str, deque[float]] = defaultdict(lambda: deque(maxlen=8))

    def evaluate(self, ev: Event) -> Event | None:
        """Olayı inceler; alarm gerektiren bir durum varsa zenginleştirilmiş `Event` döndürür."""
        # Zaten sınıflandırılmış durum olayları (web, nabız kopması, audit log vb.) doğrudan geçer
        if ev.category:
            if not ev.fingerprint:
                ev.fingerprint = make_fingerprint(ev.bot, ev.category, ev.title or ev.message)
            return ev

        if ev.kind == "metric":
            return self._evaluate_metric(ev)

        if ev.kind not in ("log", "exception"):
            return None

        text = ev.message or ""
        bh = self.state.bot(ev.bot)
        spec = self.registry.get(ev.bot)
        known_mods = spec.modules if spec else []

        # Periyodik beklenen log satırlarını kaydet (örn. Güvenlik botu 30 dk snapshot)
        if spec:
            for per in spec.expect_periodic:
                if per.pattern.lower() in text.lower():
                    bh.periodic_last_seen[per.name] = ev.ts
            for marker in spec.startup_markers:
                if marker.lower() in text.lower():
                    restarts = bh.record_restart(ev.ts)
                    if restarts >= 3:
                        return Event(
                            source=ev.source,
                            bot=ev.bot,
                            kind="status",
                            category="crash_loop",
                            severity="critical",
                            title="Çökme Döngüsü (Crash Loop)",
                            message=text,
                            cause=f"Bot son 10 dakikada {restarts} kez yeniden başladı.",
                            suggestion="Son deploy/commit değişikliklerini ve başlangıç loglarını kontrol et. Sık açılış Discord komut sync rate limit'ine yol açar.",
                            fingerprint=make_fingerprint(ev.bot, "crash_loop", "restart_loop"),
                            incident_key=f"{ev.bot}:crash_loop",
                            sticky=True,
                            ts=ev.ts,
                        )

        matched: RuleDef | None = None
        match_obj: re.Match[str] | None = None
        for rule in _RULES:
            m = rule.pattern.search(text)
            if m:
                matched = rule
                match_obj = m
                break

        if matched is None:
            return None

        loc = extract_location(text)
        mod = ev.module or (loc.module if loc else None) or infer_module(text, known_mods)

        # Cog yükleme hatasında modül adını regex grubundan çek
        if matched.category == "cog_load_error" and match_obj:
            cog_raw = match_obj.group(1) or match_obj.group(3) or ""
            cog_clean = cog_raw.replace("cogs.", "").replace(".py", "").strip()
            if cog_clean:
                mod = cog_clean
                bh.failed_cogs[cog_clean] = (match_obj.group(2) or match_obj.group(4) or text)[:200]

        if matched.category == "erlc_rate_limit":
            self.state.erlc.record_429(ev.ts)

        fp = make_fingerprint(ev.bot, matched.category, text, loc)
        bh.record_error(text, ev.ts)

        # Hata döngüsü kontrolü (60 saniyede 10+ kez aynı parmak izi)
        hits = self._fp_hits[fp]
        hits.append(ev.ts)
        cutoff_60 = ev.ts - 60
        recent_60 = sum(1 for t in hits if t >= cutoff_60)

        ev.category = matched.category
        ev.module = mod
        ev.fingerprint = fp
        ev.severity = "critical" if recent_60 >= 10 else matched.severity
        ev.title = f"{matched.title} ({mod})" if mod and mod not in matched.title else matched.title
        ev.cause = matched.cause
        ev.suggestion = matched.suggestion
        ev.min_count = matched.min_count
        ev.window = matched.window
        ev.sticky = matched.sticky
        if loc:
            ev.data["location"] = loc.short()
            ev.data["trace_file"] = loc.file
            ev.data["trace_line"] = loc.line
        if recent_60 >= 10:
            ev.title = f"Hata Döngüsü: {ev.title}"
            ev.cause = f"Aynı hata 1 dakikada {recent_60} kez tekrarlandı ({matched.cause})"
            if mod:
                ev.suggestion = f"`{mod}` modülünü duraklatarak log fırtınasını ve rate limit riskini kes."
        return ev

    def _evaluate_metric(self, ev: Event) -> Event | None:
        spec = self.registry.get(ev.bot)
        ram_limit = spec.ram_limit_mb if spec else 450
        lag = float(ev.data.get("loop_lag_ms") or 0.0)
        ram = float(ev.data.get("ram_mb") or 0.0)

        if lag > 500:
            sev = "critical" if lag >= 2000 else "warning"
            return Event(
                source=ev.source,
                bot=ev.bot,
                kind="metric",
                category="event_loop_lag",
                severity=sev,
                title=f"Event Loop Gecikmesi ({int(lag)} ms)",
                message=f"Event loop gecikmesi {int(lag)} ms ölçüldü.",
                cause="Senkron ağır bir işlem (dosya, büyük döngü veya bloklayan ağ çağrısı) botu donduruyor.",
                suggestion="Bloklayan işlemi `asyncio.to_thread` veya asenkron kütüphaneye taşı.",
                fingerprint=make_fingerprint(ev.bot, "event_loop_lag", "lag"),
                incident_key=f"{ev.bot}:event_loop_lag",
                min_count=2,
                window=180,
                ts=ev.ts,
            )

        if ram > 0:
            hist = self._ram_history[ev.bot]
            hist.append(ram)
            # 6 ardışık ölçümde sürekli artış ve toplamda +80 MB artış varsa bellek sızıntısı uyarısı
            if len(hist) >= 6 and all(hist[i] < hist[i + 1] for i in range(len(hist) - 1)) and (hist[-1] - hist[0]) >= 80:
                return Event(
                    source=ev.source,
                    bot=ev.bot,
                    kind="metric",
                    category="memory_leak",
                    severity="warning",
                    title=f"Olası Bellek Sızıntısı ({int(ram)} MB)",
                    message=f"RAM kullanımı sürekli artıyor: {int(hist[0])} MB -> {int(ram)} MB",
                    cause="Temizlenmeyen önbellek, liste veya görev birikimi nedeniyle RAM sürekli yükseliyor.",
                    suggestion="Büyüyen sözlük/listelere üst sınır (`maxlen`) veya periyodik temizlik ekle.",
                    fingerprint=make_fingerprint(ev.bot, "memory_leak", "ram_climb"),
                    incident_key=f"{ev.bot}:memory_leak",
                    ts=ev.ts,
                )
            if ram >= ram_limit:
                return Event(
                    source=ev.source,
                    bot=ev.bot,
                    kind="metric",
                    category="high_ram",
                    severity="critical" if ram >= ram_limit * 1.25 else "warning",
                    title=f"Yüksek Bellek Kullanımı ({int(ram)} MB)",
                    message=f"RAM kullanımı eşiği aştı: {int(ram)} MB (eşik: {ram_limit} MB)",
                    cause="Konteyner bellek sınırına yaklaşıyor; OOM (Out of Memory) ile çökebilir.",
                    suggestion="Yüksek bellek tüketen modülü kontrol et veya yeniden başlatma planla.",
                    fingerprint=make_fingerprint(ev.bot, "high_ram", "ram_high"),
                    incident_key=f"{ev.bot}:high_ram",
                    ts=ev.ts,
                )
        return None
