"""Log ve metin temizleyici (Redaction & Prompt-Injection Kalkanı).

Altın kural: Hiçbir log satırı ham haliyle veritabanına, DM'e veya yapay zekaya gitmez.
- Discord bot token'ları, Bearer anahtarları, API key'leri, bağlantı adresleri,
  e-postalar ve IPv4 adresleri maskelenir.
- Yapay zekaya gönderilecek metinlerde kullanıcı ID'leri de maskelenir ve
  log içine gömülmüş olası komut enjeksiyonu (prompt injection) kalıpları etkisizleştirilir.
"""
from __future__ import annotations

import re

# ── Gizli bilgi desenleri ──
_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # Discord bot / kullanıcı token deseni (3 parçalı base64)
    (re.compile(r"\b[MN][A-Za-z\d]{20,28}\.[A-Za-z\d_-]{6,7}\.[A-Za-z\d_-]{25,45}\b"), "[DISCORD_TOKEN]"),
    # Discord webhook URL
    (re.compile(r"https?://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+"), "[WEBHOOK_URL]"),
    # Bearer / Authorization başlıkları
    (re.compile(r"(?i)\b(Bearer|Bot|Token)\s+[A-Za-z0-9._\-]{16,}"), r"\1 [GIZLI_TOKEN]"),
    # Google / Gemini API anahtarı
    (re.compile(r"\bAIza[0-9A-Za-z_-]{33,39}\b"), "[GEMINI_KEY]"),
    # GitHub token'ları
    (re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b"), "[GITHUB_TOKEN]"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{40,}\b"), "[GITHUB_TOKEN]"),
    # OpenAI / Anthropic / genel sk- anahtarları
    (re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"), "[API_KEY]"),
    # Veritabanı ve Redis bağlantı adresleri
    (re.compile(r"\b(?:postgres(?:ql)?|redis(?:s)?|mongodb(?:\+srv)?|mysql)://[^\s\"'`]+"), "[DB_URL]"),
    # URL içindeki key/token/secret parametreleri
    (re.compile(r"(?i)([?&](?:key|api_key|apikey|token|secret|password|access_token)=)[^&\s\"'`]+"), r"\1[GIZLI]"),
    # ANAHTAR=değer biçimindeki ortam değişkeni sızıntıları
    (
        re.compile(
            r"(?i)\b([A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|API_KEY|PRIVATE_KEY|CLIENT_SECRET|AUTH)[A-Z0-9_]*)\s*[:=]\s*['\"]?[^\s'\",;]{8,}['\"]?"
        ),
        r"\1=[GIZLI]",
    ),
    # E-posta adresleri
    (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "[EPOSTA]"),
    # IPv4 adresleri (127.0.0.1 ve 0.0.0.0 hariç)
    (
        re.compile(r"\b(?!127\.0\.0\.1\b)(?!0\.0\.0\.0\b)(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"),
        "[IP]",
    ),
    # Uzun yüksek entropili dizeler (40+ karakterlik rastgele token benzeri dizeler, dosya yolu olmayanlar)
    (re.compile(r"(?<![/\\A-Za-z0-9])(?=[A-Za-z0-9_-]*\d)(?=[A-Za-z0-9_-]*[A-Z])(?=[A-Za-z0-9_-]*[a-z])[A-Za-z0-9_-]{44,}(?![/\\A-Za-z0-9])"), "[UZUN_ANAHTAR]"),
]

_DISCORD_SNOWFLAKE = re.compile(r"\b\d{17,20}\b")

# Log içine gömülmüş prompt-injection girişimlerini etkisizleştirir
_INJECTION_PATTERNS = re.compile(
    r"(?i)(ignore\s+(?:all\s+)?(?:previous|above)\s+instructions|"
    r"system\s*prompt|you\s+are\s+now|disregard\s+previous|"
    r"önceki\s+talimatları\s+unut|sistem\s+komutu|"
    r"<\s*/?\s*(?:system|instruction|prompt)\s*>)"
)


def redact(text: str | None, *, for_ai: bool = False) -> str:
    """Metindeki tüm gizli bilgileri maskeler.

    `for_ai=True` verildiğinde ek olarak Discord ID'leri maskelenir ve
    prompt-injection kalıpları köşeli paranteze alınarak zararsızlaştırılır.
    """
    if not text:
        return ""
    out = str(text)
    for pat, repl in _PATTERNS:
        out = pat.sub(repl, out)
    if for_ai:
        out = _DISCORD_SNOWFLAKE.sub("[ID]", out)
        out = _INJECTION_PATTERNS.sub("[FILTRELENMIS_METIN]", out)
    return out


def redact_lines(lines: list[str], *, for_ai: bool = False, max_lines: int = 200) -> list[str]:
    sliced = lines[-max_lines:] if len(lines) > max_lines else lines
    return [redact(line, for_ai=for_ai) for line in sliced]
