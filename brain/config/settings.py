"""Ortam değişkenlerinden Beyin ayarlarını okur.

Beyin yalnızca KENDİ anahtarlarını bilir. Diğer botların token'larına
hiçbir koşulda ihtiyaç duymaz ve okumaz.
Varsayılan çalışma modu: **Sadece Öner (`AUTO_ACTIONS=false`)**.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent  # brain/


def _load_dotenv() -> None:
    """Yerel testler için repo kökündeki .env dosyasını okur (Railway'de gerekmez)."""
    env_file = BASE_DIR.parent / ".env"
    if not env_file.exists():
        return
    for line in env_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip().strip("'\""))


def _int(name: str, default: int = 0) -> int:
    raw = (os.getenv(name) or "").strip()
    try:
        return int(raw) if raw else default
    except ValueError:
        return default


def _bool(name: str, default: bool = False) -> bool:
    raw = (os.getenv(name) or "").strip().lower()
    if not raw:
        return default
    return raw in ("1", "true", "yes", "on", "evet", "acik", "açık")


def _id_list(name: str) -> set[int]:
    out: set[int] = set()
    for part in (os.getenv(name) or "").split(","):
        part = part.strip()
        if part.isdigit():
            out.add(int(part))
    return out


def _agent_keys(raw: str) -> dict[str, str]:
    """AGENT_KEYS="ana-bot:anahtar1,ticket-bot:anahtar2" -> {anahtar: bot}
    Güvenlik için 16 karakterden kısa anahtarlar reddedilir.
    """
    out: dict[str, str] = {}
    for part in raw.split(","):
        part = part.strip()
        if ":" not in part:
            continue
        bot, key = part.split(":", 1)
        bot, key = bot.strip(), key.strip()
        if bot and len(key) >= 16:
            out[key] = bot
    return out


def is_valid_owner_id(val: object) -> bool:
    """OWNER_ID'nin geçerli bir Discord kullanıcı Snowflake ID'si (15-20 haneli pozitif tam sayı) olduğunu doğrular."""
    if isinstance(val, bool) or not isinstance(val, int):
        return False
    return 100_000_000_000_000 <= val <= 9_999_999_999_999_999_999


@dataclass
class Settings:
    # ── Discord ──
    token: str
    owner_id: int
    guild_id: int
    trusted_user_ids: set[int]
    security_log_channel_id: int

    # ── Altyapı ──
    port: int
    database_url: str
    sqlite_path: str
    redis_url: str
    registry_path: str

    # ── Ajan (nabız) kimlik doğrulama ──
    agent_keys: dict[str, str]
    brain_shared_secret: str

    # ── Railway (salt okuma amaçlı) ──
    railway_token: str
    railway_token_type: str
    railway_project_id: str
    railway_environment_id: str
    railway_poll_seconds: int
    railway_log_limit: int

    # ── GitHub (salt okuma) ──
    github_token: str
    github_branch: str

    # ── Yapay zeka ──
    ai_provider: str
    ai_model: str
    gemini_api_key: str
    ai_max_calls_per_hour: int

    # ── Bildirim ──
    quiet_hours: str
    daily_report_hour: int
    max_dm_per_minute: int

    # ── Eylem Modu (Varsayılan: Sadece Öner / AUTO_ACTIONS=false) ──
    auto_actions: bool
    max_auto_actions_per_hour: int

    # ── Cloudflare Kalkanı (İsteğe Bağlı) ──
    cloudflare_api_token: str
    cloudflare_zone_id: str

    # ── Harici nabız ──
    uptime_push_url: str

    # ── Eşikler ──
    heartbeat_timeout: int
    web_poll_seconds: int
    raid_join_threshold: int
    raid_window_seconds: int

    missing: list[str] = field(default_factory=list)

    @property
    def ai_enabled(self) -> bool:
        return self.ai_provider == "gemini" and bool(self.gemini_api_key)

    @property
    def railway_enabled(self) -> bool:
        return bool(self.railway_token)

    @property
    def action_mode_label(self) -> str:
        return "Otomatik Devre Kesici" if self.auto_actions else "Sadece Öner (Salt Okuma)"

    @property
    def has_valid_owner(self) -> bool:
        return is_valid_owner_id(self.owner_id)

    def validate_owner_id(self) -> None:
        if not self.has_valid_owner:
            raise ValueError(
                f"OWNER_ID boş veya geçersiz ({self.owner_id!r})! "
                "Beyin botu geçerli bir Discord kullanıcı ID'si (OWNER_ID) olmadan başlatılamaz."
            )


def load_settings() -> Settings:
    _load_dotenv()

    data_dir = Path(os.getenv("DATA_DIR") or (BASE_DIR.parent / "data"))
    data_dir.mkdir(parents=True, exist_ok=True)

    shared_secret = (os.getenv("BRAIN_SHARED_SECRET") or "").strip()
    if len(shared_secret) < 16:
        shared_secret = ""

    s = Settings(
        token=(os.getenv("BRAIN_TOKEN") or "").strip(),
        owner_id=_int("OWNER_ID"),
        guild_id=_int("GUILD_ID", 1529545898294509589),
        trusted_user_ids=_id_list("TRUSTED_USER_IDS"),
        security_log_channel_id=_int("SECURITY_LOG_CHANNEL_ID"),
        port=_int("PORT", 8080),
        database_url=(os.getenv("DATABASE_URL") or "").strip(),
        sqlite_path=str(data_dir / "brain.db"),
        redis_url=(os.getenv("REDIS_URL") or "").strip(),
        registry_path=os.getenv("REGISTRY_PATH") or str(BASE_DIR / "config" / "registry.yaml"),
        agent_keys=_agent_keys(os.getenv("AGENT_KEYS") or ""),
        brain_shared_secret=shared_secret,
        railway_token=(os.getenv("RAILWAY_API_TOKEN") or "").strip(),
        railway_token_type=(os.getenv("RAILWAY_TOKEN_TYPE") or "project").strip().lower(),
        railway_project_id=(os.getenv("BRAIN_RAILWAY_PROJECT_ID") or os.getenv("RAILWAY_PROJECT_ID") or "").strip(),
        railway_environment_id=(os.getenv("BRAIN_RAILWAY_ENVIRONMENT_ID") or os.getenv("RAILWAY_ENVIRONMENT_ID") or "").strip(),
        railway_poll_seconds=max(15, _int("RAILWAY_POLL_SECONDS", 30)),
        railway_log_limit=min(500, max(50, _int("RAILWAY_LOG_LIMIT", 150))),
        github_token=(os.getenv("GITHUB_TOKEN") or "").strip(),
        github_branch=(os.getenv("GITHUB_BRANCH") or "main").strip(),
        ai_provider=(os.getenv("AI_PROVIDER") or "gemini").strip().lower(),
        ai_model=(os.getenv("AI_MODEL") or "gemini-2.5-flash").strip(),
        gemini_api_key=(os.getenv("GEMINI_API_KEY") or "").strip(),
        ai_max_calls_per_hour=_int("AI_MAX_CALLS_PER_HOUR", 20),
        quiet_hours=(os.getenv("QUIET_HOURS") or "").strip(),
        daily_report_hour=_int("DAILY_REPORT_HOUR", 9),
        max_dm_per_minute=_int("MAX_DM_PER_MINUTE", 8),
        auto_actions=_bool("AUTO_ACTIONS", False),
        max_auto_actions_per_hour=_int("MAX_AUTO_ACTIONS_PER_HOUR", 5),
        cloudflare_api_token=(os.getenv("CLOUDFLARE_API_TOKEN") or "").strip(),
        cloudflare_zone_id=(os.getenv("CLOUDFLARE_ZONE_ID") or "").strip(),
        uptime_push_url=(os.getenv("UPTIME_PUSH_URL") or "").strip(),
        heartbeat_timeout=_int("HEARTBEAT_TIMEOUT", 90),
        web_poll_seconds=max(15, _int("WEB_POLL_SECONDS", 30)),
        raid_join_threshold=_int("RAID_JOIN_THRESHOLD", 8),
        raid_window_seconds=_int("RAID_WINDOW_SECONDS", 30),
    )

    if not s.token:
        s.missing.append("BRAIN_TOKEN")
    if not s.has_valid_owner:
        s.missing.append("OWNER_ID")
    if not s.railway_token:
        s.missing.append("RAILWAY_API_TOKEN (Railway log/durum takibi kapalı)")
    if not s.gemini_api_key and s.ai_provider == "gemini":
        s.missing.append("GEMINI_API_KEY (yapay zeka analizi kapalı)")
    if not s.redis_url:
        s.missing.append("REDIS_URL (bayraklar veritabanında tutuluyor)")
    if not s.database_url:
        s.missing.append("DATABASE_URL (geçici yerel SQLite kullanılıyor)")
    if not s.security_log_channel_id:
        s.missing.append("SECURITY_LOG_CHANNEL_ID (güvenlik log kanalı okunmuyor)")
    if not s.agent_keys and not s.brain_shared_secret:
        s.missing.append("AGENT_KEYS / BRAIN_SHARED_SECRET (nabız uç noktası kapalı)")
    return s
