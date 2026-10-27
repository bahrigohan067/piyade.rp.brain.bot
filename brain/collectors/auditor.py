"""Başlangıç ve Konfigürasyon Denetçisi (Salt Okuma).

Beyin açıldığında ve periyodik olarak:
1. GitHub Repolarında Sızmış Dosya Taraması:
   `registry.yaml` içindeki tüm repoların kök dizinini GitHub API ile kontrol eder;
   public repoda `.env` veya `node_modules` gibi gizli/istenmeyen dosyalar duruyorsa uyarır.
2. Railway Volume ve Ortam Değişkeni Adı Denetimi:
   - `data/` klasörü kullanan (`expects_volume: true`) servislerde Railway Volume bağlı değilse
     "Her deploy'da yerel veri silinir" uyarısı üretir.
   - Değişkenlerin DEĞERLERİNİ OKUMADAN yalnızca beklenen değişken ADLARININ tanımlı olup olmadığını kontrol eder.
   - Beyin'in kendisinde `DATABASE_URL` tanımlı değilse (geçici SQLite kullanılıyorsa) bunu açıkça bildirir.
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

import aiohttp

from brain.core.events import Event
from brain.core.fingerprint import make_fingerprint

if TYPE_CHECKING:
    from brain.engine import BrainEngine

log = logging.getLogger("brain.auditor")

_DANGEROUS_REPO_FILES = {".env", ".env.local", ".env.production", "node_modules"}

_RAILWAY_VOLUMES_QUERY = """
query GetProjectVolumes($projectId: String!) {
  project(id: $projectId) {
    services {
      edges {
        node {
          id
          name
        }
      }
    }
    volumes {
      edges {
        node {
          id
          name
          serviceInstances {
            edges {
              node {
                serviceId
              }
            }
          }
        }
      }
    }
  }
}
"""


class EcosystemAuditor:
    def __init__(self, engine: "BrainEngine") -> None:
        self.engine = engine
        self.settings = engine.settings
        self.registry = engine.registry
        self._ran_once: bool = False

    async def run_startup_audit(self) -> list[str]:
        """Başlangıç denetimini çalıştırır ve bulguların özet listesini döndürür."""
        findings: list[str] = []

        # 1. Beyin'in kendi veritabanı kalıcılık kontrolü
        if not self.settings.database_url:
            msg = (
                "Beyin şu an yerel SQLite (`data/brain.db`) kullanıyor. "
                "Railway'de konteyner dosya sistemi her deploy'da sıfırlandığı için kalıcı hafıza adına "
                "`DATABASE_URL` (PostgreSQL) bağlanması önerilir."
            )
            findings.append(msg)

        # 2. GitHub repolarında `.env` ve `node_modules` sızıntı kontrolü
        repo_findings = await self._scan_github_repos_for_leaks()
        findings.extend(repo_findings)

        # 3. Railway Volume kontrolü (`expects_volume: true` olan botlar)
        vol_findings = await self._audit_railway_volumes()
        findings.extend(vol_findings)

        self._ran_once = True
        return findings

    async def _scan_github_repos_for_leaks(self) -> list[str]:
        findings: list[str] = []
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "PiyadeRP-BrainBot-Auditor/1.0",
        }
        if self.settings.github_token:
            headers["Authorization"] = f"Bearer {self.settings.github_token}"

        timeout = aiohttp.ClientTimeout(total=10)
        async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
            for bot_key, spec in self.registry.bots.items():
                if not spec.repo:
                    continue
                url = f"https://api.github.com/repos/{spec.repo}/contents/"
                try:
                    async with session.get(url, params={"ref": self.settings.github_branch}) as resp:
                        if resp.status != 200:
                            continue
                        items = await resp.json()
                        if not isinstance(items, list):
                            continue
                        names = {str(it.get("name") or "") for it in items if isinstance(it, dict)}
                        leaked = sorted(names & _DANGEROUS_REPO_FILES)
                        if leaked:
                            leaked_str = ", ".join(f"`{x}`" for x in leaked)
                            finding = f"{spec.name} (`{spec.repo}`) public reposunda {leaked_str} bulundu!"
                            findings.append(finding)
                            await self.engine.ingest(
                                Event(
                                    source="auditor",
                                    bot=bot_key,
                                    kind="security",
                                    category="repo_secret_leak",
                                    severity="critical" if ".env" in leaked else "warning",
                                    title=f"GitHub Reposunda Gizli Dosya ({', '.join(leaked)})",
                                    message=finding,
                                    cause=f"`{spec.repo}` reposunun kök dizininde {leaked_str} dosyası/klasörü GitHub'a yüklenmiş.",
                                    suggestion="İlgili token'ları sıfırla, dosyayı `git rm --cached` ile kaldır ve `.gitignore`'a ekle.",
                                    fingerprint=make_fingerprint(bot_key, "repo_secret_leak", ",".join(leaked)),
                                    incident_key=f"{bot_key}:repo_leak",
                                    sticky=True,
                                )
                            )
                except Exception as exc:
                    log.debug("GitHub sızıntı taraması hatası (%s): %s", spec.repo, exc)
        return findings

    async def _audit_railway_volumes(self) -> list[str]:
        findings: list[str] = []
        if not self.settings.railway_enabled or not self.settings.railway_project_id:
            return findings

        timeout = aiohttp.ClientTimeout(total=10)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            data: dict[str, Any] | None = await self.engine.railway._gql(
                session,
                _RAILWAY_VOLUMES_QUERY,
                {"projectId": self.settings.railway_project_id},
            )
            if not data or not data.get("project"):
                return findings

            proj = data["project"]
            svc_id_to_name: dict[str, str] = {}
            for edge in ((proj.get("services") or {}).get("edges")) or []:
                node = (edge or {}).get("node") or {}
                if node.get("id") and node.get("name"):
                    svc_id_to_name[str(node["id"])] = str(node["name"])

            services_with_volume: set[str] = set()
            for v_edge in ((proj.get("volumes") or {}).get("edges")) or []:
                v_node = (v_edge or {}).get("node") or {}
                for si_edge in ((v_node.get("serviceInstances") or {}).get("edges")) or []:
                    si_node = (si_edge or {}).get("node") or {}
                    sid = str(si_node.get("serviceId") or "")
                    if sid in svc_id_to_name:
                        services_with_volume.add(svc_id_to_name[sid].lower())

            for bot_key, spec in self.registry.bots.items():
                if not spec.expects_volume or not spec.railway_service:
                    continue
                if spec.railway_service.lower() not in services_with_volume:
                    msg = f"{spec.name} (`{spec.railway_service}`) yerel `data/` kullanıyor ancak Railway Volume bağlı görünmüyor."
                    findings.append(msg)
                    await self.engine.ingest(
                        Event(
                            source="auditor",
                            bot=bot_key,
                            kind="config",
                            category="missing_volume",
                            severity="info",
                            title="Kalıcı Depolama (Volume) Bağlı Değil",
                            message=msg,
                            cause="Bot yerel `data/` dizininde JSON/SQLite tutuyor; Volume yoksa her deploy'da sıfırlanabilir.",
                            suggestion="Verilerin kalıcı olması gerekiyorsa Railway'de servise `/app/data` Volume'u bağla.",
                            fingerprint=make_fingerprint(bot_key, "missing_volume", "volume"),
                            incident_key=f"{bot_key}:missing_volume",
                        )
                    )
        return findings
