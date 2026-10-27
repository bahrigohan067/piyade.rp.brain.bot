"""Railway GraphQL v2 Toplayıcısı (Salt Okuma).

Her `railway_poll_seconds` saniyede bir:
1. Projedeki servislerin son deployment durumlarını (`SUCCESS`, `BUILDING`, `CRASHED`, `FAILED`) çeker.
2. Her servisin son loglarını tarar, çok satırlı Python traceback'lerini birleştirir ve
   daha önce işlenmemiş satırları Beyin olay kuyruğuna (`Event`) aktarır.
3. Hem Project Access Token (`Project-Access-Token`) hem de Account/Workspace Token (`Authorization: Bearer`)
   biçimlerini otomatik destekler. Yalnızca okuma (`query`) sorguları çalıştırır; hiçbir `mutation` içermez.
"""
from __future__ import annotations

import datetime
import logging
import time
from collections import defaultdict, deque
from typing import TYPE_CHECKING, Any

import aiohttp

from brain.core.events import Event
from brain.core.fingerprint import make_fingerprint
from brain.core.redactor import redact

if TYPE_CHECKING:
    from brain.engine import BrainEngine

log = logging.getLogger("brain.railway")

RAILWAY_GQL_URL = "https://backboard.railway.com/graphql/v2"

# Proje Token'ı ile ortam ve proje bilgisini keşfetmek için
_PROJECT_TOKEN_QUERY = """
query ProjectTokenInfo {
  projectToken {
    projectId
    environmentId
  }
}
"""

# Projedeki servisleri ve son deployment durumlarını tek sorguda çeker
_PROJECT_SERVICES_QUERY = """
query GetProjectServices($projectId: String!) {
  project(id: $projectId) {
    id
    name
    services {
      edges {
        node {
          id
          name
          deployments(first: 5) {
            edges {
              node {
                id
                status
                createdAt
              }
            }
          }
        }
      }
    }
  }
}
"""

_DEPLOYMENT_LOGS_QUERY = """
query GetDeploymentLogs($deploymentId: String!, $limit: Int) {
  deploymentLogs(deploymentId: $deploymentId, limit: $limit) {
    timestamp
    message
    severity
  }
}
"""


def _parse_iso(ts_str: str | None) -> float:
    if not ts_str:
        return time.time()
    try:
        s = ts_str.replace("Z", "+00:00")
        return datetime.datetime.fromisoformat(s).timestamp()
    except Exception:
        return time.time()


class RailwayCollector:
    def __init__(self, engine: "BrainEngine") -> None:
        self.engine = engine
        self.settings = engine.settings
        self.registry = engine.registry
        self.state = engine.state
        self._header_mode: str = "project" if self.settings.railway_token_type == "project" else "bearer"
        self._seen_logs: dict[str, deque[str]] = defaultdict(lambda: deque(maxlen=600))
        self._primed_deployments: set[str] = set()
        self._project_id: str = self.settings.railway_project_id

    def _headers(self, mode: str) -> dict[str, str]:
        h = {"Content-Type": "application/json", "User-Agent": "PiyadeRP-BrainBot/1.0"}
        if mode == "project":
            h["Project-Access-Token"] = self.settings.railway_token
        else:
            h["Authorization"] = f"Bearer {self.settings.railway_token}"
        return h

    async def _gql(self, session: aiohttp.ClientSession, query: str, variables: dict[str, Any] | None = None) -> dict[str, Any] | None:
        payload = {"query": query, "variables": variables or {}}
        for attempt_mode in (self._header_mode, "bearer" if self._header_mode == "project" else "project"):
            try:
                async with session.post(RAILWAY_GQL_URL, json=payload, headers=self._headers(attempt_mode)) as resp:
                    if resp.status == 401:
                        continue
                    data = await resp.json(content_type=None)
                    if isinstance(data, dict) and data.get("data"):
                        self._header_mode = attempt_mode
                        return data["data"]
            except Exception as exc:
                log.debug("Railway GraphQL isteği başarısız (%s): %s", attempt_mode, exc)
        return None

    async def poll_once(self) -> None:
        if not self.settings.railway_enabled:
            return

        timeout = aiohttp.ClientTimeout(total=15)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            if not self._project_id:
                tok_data = await self._gql(session, _PROJECT_TOKEN_QUERY)
                if tok_data and tok_data.get("projectToken"):
                    self._project_id = str(tok_data["projectToken"].get("projectId") or "")

            if not self._project_id:
                log.warning("Railway projectId bulunamadı. RAILWAY_PROJECT_ID değişkenini ekleyin.")
                return

            proj_data = await self._gql(session, _PROJECT_SERVICES_QUERY, {"projectId": self._project_id})
            if not proj_data or not proj_data.get("project"):
                return

            services_edges = ((proj_data["project"].get("services") or {}).get("edges")) or []
            for edge in services_edges:
                node = (edge or {}).get("node") or {}
                svc_name = str(node.get("name") or "").strip()
                if not svc_name:
                    continue
                bot_key = self.registry.by_railway_service(svc_name)
                if not bot_key:
                    # Beyin'in kendi servisini eşleşmeyen listesine ekleme
                    if "brain" not in svc_name.lower() and "beyin" not in svc_name.lower():
                        self.state.unmatched_railway_services.add(svc_name)
                    continue

                dep_edges = ((node.get("deployments") or {}).get("edges")) or []
                if not dep_edges:
                    continue

                await self._process_service_deployments(session, bot_key, dep_edges)

    async def _process_service_deployments(
        self,
        session: aiohttp.ClientSession,
        bot_key: str,
        dep_edges: list[dict[str, Any]],
    ) -> None:
        bh = self.state.bot(bot_key)
        latest = (dep_edges[0] or {}).get("node") or {}
        dep_id = str(latest.get("id") or "")
        status = str(latest.get("status") or "UNKNOWN").upper()
        created_ts = _parse_iso(latest.get("createdAt"))

        prev_status = bh.deploy_status
        bh.deploy_status = status
        bh.last_deploy_ts = created_ts
        bh.last_deploy_id = dep_id

        # Son 10 dakikadaki çökme/yeniden dağıtım sayısını kontrol et
        now = time.time()
        recent_crashes = sum(
            1
            for e in dep_edges
            if str((e.get("node") or {}).get("status") or "").upper() in ("CRASHED", "FAILED")
            and (now - _parse_iso((e.get("node") or {}).get("createdAt"))) <= 600
        )

        inc_key = f"{bot_key}:railway_deploy"
        if status in ("CRASHED", "FAILED"):
            title = "Servis Çöktü (Railway CRASHED)" if status == "CRASHED" else "Deploy Başarısız (Railway FAILED)"
            if recent_crashes >= 3:
                title = f"Çökme Döngüsü ({recent_crashes}x CRASHED)"
            await self.engine.ingest(
                Event(
                    source="railway",
                    bot=bot_key,
                    kind="deploy",
                    category="deploy_crashed",
                    severity="critical",
                    title=title,
                    message=f"Railway deployment durumu: {status} (id: {dep_id})",
                    cause="Konteyner beklenmedik şekilde sonlandı veya derleme/başlatma aşamasında hata verdi.",
                    suggestion="Son commit'i ve aşağıdaki başlangıç loglarını kontrol et.",
                    fingerprint=make_fingerprint(bot_key, "deploy_crashed", status),
                    incident_key=inc_key,
                    sticky=True,
                )
            )
        elif prev_status in ("CRASHED", "FAILED") and status == "SUCCESS":
            await self.engine.ingest(
                Event(
                    source="railway",
                    bot=bot_key,
                    kind="deploy",
                    category="deploy_crashed",
                    title="Servis Normale Döndü",
                    message="Deployment durumu SUCCESS oldu.",
                    incident_key=inc_key,
                    resolves=True,
                )
            )

        if not dep_id:
            return

        # Aktif deployment loglarını çek
        log_data = await self._gql(
            session,
            _DEPLOYMENT_LOGS_QUERY,
            {"deploymentId": dep_id, "limit": self.settings.railway_log_limit},
        )
        raw_logs = (log_data or {}).get("deploymentLogs") or []
        if not isinstance(raw_logs, list) or not raw_logs:
            return

        seen = self._seen_logs[dep_id]
        is_first_poll = dep_id not in self._primed_deployments
        self._primed_deployments.add(dep_id)

        new_entries: list[tuple[float, str]] = []
        for entry in raw_logs:
            if not isinstance(entry, dict):
                continue
            msg = str(entry.get("message") or "").rstrip()
            ts_str = str(entry.get("timestamp") or "")
            if not msg:
                continue
            sig = f"{ts_str}|{msg}"
            if sig in seen:
                continue
            seen.append(sig)
            clean_line = redact(msg)
            bh.record_log(clean_line)
            new_entries.append((_parse_iso(ts_str), clean_line))

        # İlk açılışta geçmiş logları tampona al ama yalnızca gerçek kritik yükleme hatalarını işle
        for ts_val, line in self._coalesce_tracebacks(new_entries):
            if is_first_poll and "Hata:" not in line and "yüklenemedi" not in line and "tanımlı değil" not in line:
                continue
            await self.engine.ingest(
                Event(
                    source="railway",
                    bot=bot_key,
                    kind="log",
                    message=line,
                    ts=ts_val,
                )
            )

    @staticmethod
    def _coalesce_tracebacks(entries: list[tuple[float, str]]) -> list[tuple[float, str]]:
        """Çok satırlı Python Traceback bloklarını tek bir olay metninde birleştirir."""
        out: list[tuple[float, str]] = []
        buf: list[str] = []
        buf_ts: float = 0.0

        for ts_val, line in entries:
            if "Traceback (most recent call last):" in line:
                if buf:
                    out.append((buf_ts, "\n".join(buf)))
                buf = [line]
                buf_ts = ts_val
                continue

            if buf:
                buf.append(line)
                stripped = line.strip()
                # Traceback'in son satırı (örn. KeyError: 'x') geldiğinde bloğu kapat
                if (
                    not line.startswith((" ", "\t"))
                    and not stripped.startswith("File ")
                    and ":" in stripped
                    and len(buf) >= 2
                ) or len(buf) >= 25:
                    out.append((buf_ts, "\n".join(buf)))
                    buf = []
                continue

            out.append((ts_val, line))

        if buf:
            out.append((buf_ts, "\n".join(buf)))
        return out
