# 🧠 Piyade RP — Beyin Botu (`piyade.rp.brain.bot`)

Piyade RP ekosistemindeki **7 botu ve web sitesini** diğer repoların koduna müdahale etmeden izleyen, hataları teşhis eden ve sahibe DM üzerinden onaylı müdahale imkanı sunan **Gözlemci + Teşhis Uzmanı + Sigorta Şalteri** servisidir.

---

## 🏗️ Mimari ve Katmanlar

```text
brain/
├─ config/
│  ├─ settings.py        # Ortam değişkenleri (Beyin yalnızca kendi token'larını bilir)
│  ├─ registry.yaml      # Piyade RP bot ve site kayıt defteri
│  └─ registry.py        # Tipli kayıt defteri yükleyicisi
├─ core/
│  ├─ events.py          # Olay (Event) ve Tekilleştirilmiş Sorun (Incident) modelleri
│  ├─ redactor.py        # Gizli bilgi maskeleme (Token/Key/IP/E-posta) ve Prompt-Injection kalkanı
│  ├─ fingerprint.py     # SHA-256 hata parmak izi ve Python/Node stack trace ayrıştırıcı
│  └─ state.py           # Canlı ekosistem durumu (WorldState)
├─ collectors/
│  ├─ railway.py         # Railway GraphQL v2 deployment durumu ve log akışı okuyucu
│  ├─ github.py          # GitHub salt-okuma kaynak kod satırı ve son commit inceleyici
│  ├─ web.py             # Site uç noktaları, SSL süresi, /api/status ER:LC durumu ve UptimeRobot
│  ├─ heartbeat.py       # /health ve /agent/heartbeat HTTP sunucusu + 90 sn donma tespiti
│  └─ discord_watch.py   # Ses kanalı (Rehber), 00:00 Gece Raporu, AI bilet sözleşmesi, Güvenlik logu, Audit Log
├─ analyzers/
│  ├─ rules.py           # Katman A/B: Piyade RP'ye özel kural motoru, hata döngüsü ve bellek sızıntısı tespiti
│  ├─ correlator.py      # Zaman çizelgesi korelasyonu (ER:LC kök nedeni, deploy sonrası regresyon)
│  └─ ai.py              # Katman C: Gemini (google-genai) yapılandırılmış JSON kök neden analizi
├─ actions/
│  ├─ flags.py           # Redis + DB yedekli modül bayrağı (ACTIVE / PAUSED) ve devre kesici
│  └─ notify.py          # Tekilleştirilmiş DM bildirimleri ve kalıcı onay butonları
├─ memory/
│  └─ db.py              # PostgreSQL + SQLite yedekli olay geçmişi, parmak izi öğrenme ve denetim kaydı
├─ commands/
│  └─ slash.py           # Sahibe özel (/durum, /bot, /modul, /rapor, /neden, /sessiz, /bakim)
└─ engine.py             # Tüm akışı birleştiren çekirdek motor
agent/
└─ brain_agent.py        # İsteğe bağlı: Diğer Python botlarının cogs/ klasörüne bırakılabilen nabız/bayrak ajanı
```

---

## 🚀 Kurulum (Railway — Ayrı Servis)

1. **Discord Bot Oluştur:**
   - Discord Developer Portal'dan Beyin için ayrı bir uygulama/bot oluştur ve sunucuya ekle.
   - **ÖNEMLİ (Suicide-Loop Önlemi):** Güvenlik botunun (`piyader.rp.security.bot`) Railway `WHITELIST_BOTS` değişkenine Beyin botunun Discord ID'sini ekle.
2. **Railway Değişkenlerini Tanımla:**
   - `.env.example` içindeki değişkenlerden en az `BRAIN_TOKEN` ve `OWNER_ID` (kendi Discord kullanıcı ID'n) değerlerini gir.
   - Railway loglarını okuması için `RAILWAY_API_TOKEN`, AI teşhisi için `GEMINI_API_KEY` ekle.
   - İsteğe bağlı olarak Railway projesindeki **PostgreSQL** (`DATABASE_URL`) ve **Redis** (`REDIS_URL`) bağlantılarını bağla (bağlanmasa bile yerel SQLite ile çalışır).
3. **Çalıştır:**
   ```bash
   python -m brain
   ```

---

## 🛠️ Slash Komutları (Yalnızca `OWNER_ID`)

| Komut | Açıklama |
|---|---|
| `/durum` | Tüm botların, sitenin ve ER:LC köprüsünün canlı sağlık panosu |
| `/bot <isim>` | Seçilen botun RAM, ping, modül bayrakları, yüklenemeyen cog'ları ve son logları |
| `/modul <bot> <modül> <duraklat\|başlat>` | Bir modülü (cog) elle duraklatır veya tekrar başlatır |
| `/rapor [saat]` | Son 24 saatin (veya belirtilen sürenin) olay ve denetim kaydı özeti |
| `/neden [bot]` | Son yaşanan sorunun kök nedenini, kod satırını ve AI teşhisini açıklar |
| `/sessiz <süre>` | Kritik olmayan DM bildirimlerini susturur (`30dk`, `2sa`, `kapat`) |
| `/bakim <süre>` | Planlı bakım modunu açar/kapatır (alarm üretilmez) |
