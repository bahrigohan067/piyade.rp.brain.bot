"""Cloudflare Güvenlik Duvarı (Firewall) Eylem Katmanı (İsteğe Bağlı).

`CLOUDFLARE_API_TOKEN` ve `CLOUDFLARE_ZONE_ID` tanımlandığında:
- Saldırı yapan bir IP adresini Cloudflare Access Rules üzerinden engelleyebilir (`block_ip`)
  veya engeli kaldırabilir (`unblock_ip`).
- Token'ın yalnızca `Zone.Firewall Services: Edit` yetkisine sahip olması yeterlidir.
"""
from __future__ import annotations

import logging
import ipaddress

import aiohttp

from brain.config.settings import Settings
from brain.memory.db import BrainDB

log = logging.getLogger("brain.cloudflare")


class CloudflareShield:
    def __init__(self, settings: Settings, db: BrainDB) -> None:
        self.settings = settings
        self.db = db

    @property
    def enabled(self) -> bool:
        return bool(self.settings.cloudflare_api_token and self.settings.cloudflare_zone_id)

    async def block_ip(self, ip_str: str, *, actor: str, reason: str = "Beyin saldırı koruması") -> tuple[bool, str]:
        try:
            ip_obj = ipaddress.ip_address(ip_str.strip())
            if ip_obj.is_private or ip_obj.is_loopback:
                return False, "Özel (private/loopback) IP adresleri engellenemez."
        except ValueError:
            return False, f"Geçersiz IP adresi: `{ip_str}`"

        if not self.enabled:
            return False, "Cloudflare API ayarları (`CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ZONE_ID`) tanımlı değil."

        url = f"https://api.cloudflare.com/client/v4/zones/{self.settings.cloudflare_zone_id}/firewall/access_rules/rules"
        headers = {
            "Authorization": f"Bearer {self.settings.cloudflare_api_token}",
            "Content-Type": "application/json",
        }
        payload = {
            "mode": "block",
            "configuration": {"target": "ip", "value": str(ip_obj)},
            "notes": f"PiyadeRP-Brain ({actor}): {reason[:120]}",
        }
        timeout = aiohttp.ClientTimeout(total=10)
        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.post(url, headers=headers, json=payload) as resp:
                    data = await resp.json(content_type=None)
                    if resp.status in (200, 201) and isinstance(data, dict) and data.get("success"):
                        await self.db.log_action(
                            actor=actor,
                            action="cloudflare_block_ip",
                            target=str(ip_obj),
                            reason=reason,
                        )
                        return True, f"`{ip_obj}` IP adresi Cloudflare üzerinden engellendi."
                    return False, f"Cloudflare API hatası (HTTP {resp.status})."
        except Exception as exc:
            log.warning("Cloudflare IP engelleme hatası: %s", exc)
            return False, f"Cloudflare bağlantı hatası: {exc}"
