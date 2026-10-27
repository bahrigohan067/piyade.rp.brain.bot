"""Hafıza ve Öğrenme Veritabanı (PostgreSQL + SQLite otomatik yedekli).

Railway'de `DATABASE_URL` tanımlandığında `asyncpg` ile PostgreSQL kullanır;
tanımlı değilse (veya bağlantı kurulamazsa) yerel SQLite dosyasına düşer.

Saklananlar:
- `incidents`      : Olay geçmişi ve durumları
- `fingerprints`   : Hata parmak izleri, AI önbelleği ve öğrenilmiş çözüm notları
- `audit_actions`  : Beyin'in yaptığı her eylemin denetim kaydı (kim, ne, ne zaman, neden)
- `module_flags`   : Redis olmadığında kullanılan modül bayrağı tablosu
- `kv_state`       : Sessiz mod / bakım modu gibi kalıcı ayarlar
"""
from __future__ import annotations

import asyncio
import json
import logging
import sqlite3
import time
from pathlib import Path
from typing import Any

from brain.core.events import Incident

log = logging.getLogger("brain.db")

_SCHEMA_SQL = [
    """
    CREATE TABLE IF NOT EXISTS incidents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        inc_key TEXT NOT NULL,
        bot TEXT NOT NULL,
        module TEXT,
        category TEXT NOT NULL,
        fingerprint TEXT,
        severity TEXT NOT NULL,
        title TEXT NOT NULL,
        cause TEXT,
        suggestion TEXT,
        sample_log TEXT,
        first_seen REAL NOT NULL,
        last_seen REAL NOT NULL,
        count INTEGER NOT NULL DEFAULT 1,
        status TEXT NOT NULL DEFAULT 'open',
        root_id INTEGER,
        dm_message_id TEXT,
        ai_json TEXT,
        resolution TEXT
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS fingerprints (
        fingerprint TEXT PRIMARY KEY,
        bot TEXT NOT NULL,
        category TEXT NOT NULL,
        location TEXT,
        title TEXT,
        total_occurrences INTEGER NOT NULL DEFAULT 1,
        first_seen REAL NOT NULL,
        last_seen REAL NOT NULL,
        ai_json TEXT,
        learned_resolution TEXT,
        resolved_count INTEGER NOT NULL DEFAULT 0
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS audit_actions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts REAL NOT NULL,
        actor TEXT NOT NULL,
        action TEXT NOT NULL,
        target TEXT NOT NULL,
        reason TEXT,
        incident_id INTEGER
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS module_flags (
        bot TEXT NOT NULL,
        module TEXT NOT NULL,
        state TEXT NOT NULL DEFAULT 'ACTIVE',
        reason TEXT,
        updated_by TEXT,
        updated_at REAL NOT NULL,
        PRIMARY KEY (bot, module)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS kv_state (
        k TEXT PRIMARY KEY,
        v TEXT NOT NULL
    )
    """,
]


def _pg_ddl(stmt: str) -> str:
    return stmt.replace("INTEGER PRIMARY KEY AUTOINCREMENT", "BIGSERIAL PRIMARY KEY").replace("REAL", "DOUBLE PRECISION")


class BrainDB:
    def __init__(self, database_url: str = "", sqlite_path: str = "data/brain.db") -> None:
        self.database_url = database_url.strip()
        self.sqlite_path = sqlite_path
        self._pool: Any = None
        self._sqlite: sqlite3.Connection | None = None
        self._lock = asyncio.Lock()
        self.backend = "sqlite"

    async def connect(self) -> None:
        if self.database_url.startswith(("postgres://", "postgresql://")):
            try:
                import asyncpg  # type: ignore

                self._pool = await asyncpg.create_pool(self.database_url, min_size=1, max_size=5, command_timeout=15)
                async with self._pool.acquire() as conn:
                    for stmt in _SCHEMA_SQL:
                        await conn.execute(_pg_ddl(stmt))
                self.backend = "postgres"
                log.info("Hafıza veritabanı bağlandı: PostgreSQL")
                return
            except Exception as exc:
                log.warning("PostgreSQL bağlantısı kurulamadı (%s), yerel SQLite kullanılacak.", exc)
                self._pool = None

        Path(self.sqlite_path).parent.mkdir(parents=True, exist_ok=True)
        self._sqlite = sqlite3.connect(self.sqlite_path, check_same_thread=False)
        self._sqlite.row_factory = sqlite3.Row
        for stmt in _SCHEMA_SQL:
            self._sqlite.execute(stmt)
        self._sqlite.commit()
        self.backend = "sqlite"
        log.info("Hafıza veritabanı bağlandı: SQLite (%s)", self.sqlite_path)

    async def close(self) -> None:
        if self._pool is not None:
            await self._pool.close()
            self._pool = None
        if self._sqlite is not None:
            self._sqlite.close()
            self._sqlite = None

    # ── Yardımcı sorgu çalıştırıcılar ──
    async def _exec(self, sql_sqlite: str, params: tuple[Any, ...] = ()) -> int:
        if self._pool is not None:
            sql_pg = self._to_pg_placeholders(sql_sqlite)
            async with self._pool.acquire() as conn:
                await conn.execute(sql_pg, *params)
            return 0
        async with self._lock:
            assert self._sqlite is not None
            cur = self._sqlite.execute(sql_sqlite, params)
            self._sqlite.commit()
            return int(cur.lastrowid or 0)

    async def _fetchall(self, sql_sqlite: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
        if self._pool is not None:
            sql_pg = self._to_pg_placeholders(sql_sqlite)
            async with self._pool.acquire() as conn:
                rows = await conn.fetch(sql_pg, *params)
                return [dict(r) for r in rows]
        async with self._lock:
            assert self._sqlite is not None
            cur = self._sqlite.execute(sql_sqlite, params)
            return [dict(r) for r in cur.fetchall()]

    async def _fetchone(self, sql_sqlite: str, params: tuple[Any, ...] = ()) -> dict[str, Any] | None:
        rows = await self._fetchall(sql_sqlite, params)
        return rows[0] if rows else None

    @staticmethod
    def _to_pg_placeholders(sql: str) -> str:
        out: list[str] = []
        idx = 0
        for ch in sql:
            if ch == "?":
                idx += 1
                out.append(f"${idx}")
            else:
                out.append(ch)
        return "".join(out)

    # ── Olay Kayıtları (Incidents) ──
    async def insert_incident(self, inc: Incident) -> int:
        sample = inc.samples[-1] if inc.samples else ""
        ai_str = json.dumps(inc.ai, ensure_ascii=False) if inc.ai else None
        params = (
            inc.key,
            inc.bot,
            inc.module,
            inc.category,
            inc.fingerprint,
            inc.severity,
            inc.title,
            inc.cause,
            inc.suggestion,
            sample,
            inc.first_seen,
            inc.last_seen,
            inc.count,
            inc.status,
            inc.root_id,
            str(inc.dm_message_id) if inc.dm_message_id else None,
            ai_str,
            inc.resolution,
        )
        if self._pool is not None:
            sql = (
                "INSERT INTO incidents (inc_key, bot, module, category, fingerprint, severity, title, cause, "
                "suggestion, sample_log, first_seen, last_seen, count, status, root_id, dm_message_id, ai_json, resolution) "
                "VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18) RETURNING id"
            )
            async with self._pool.acquire() as conn:
                row = await conn.fetchrow(sql, *params)
                inc.id = int(row["id"])
                return inc.id

        row_id = await self._exec(
            "INSERT INTO incidents (inc_key, bot, module, category, fingerprint, severity, title, cause, "
            "suggestion, sample_log, first_seen, last_seen, count, status, root_id, dm_message_id, ai_json, resolution) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            params,
        )
        inc.id = row_id
        return row_id

    async def update_incident(self, inc: Incident) -> None:
        if not inc.id:
            return
        sample = inc.samples[-1] if inc.samples else ""
        ai_str = json.dumps(inc.ai, ensure_ascii=False) if inc.ai else None
        await self._exec(
            "UPDATE incidents SET severity=?, title=?, cause=?, suggestion=?, sample_log=?, "
            "last_seen=?, count=?, status=?, root_id=?, dm_message_id=?, ai_json=?, resolution=? "
            "WHERE id=?",
            (
                inc.severity,
                inc.title,
                inc.cause,
                inc.suggestion,
                sample,
                inc.last_seen,
                inc.count,
                inc.status,
                inc.root_id,
                str(inc.dm_message_id) if inc.dm_message_id else None,
                ai_str,
                inc.resolution,
                inc.id,
            ),
        )

    async def recent_incidents(self, hours: int = 24, limit: int = 50) -> list[dict[str, Any]]:
        cutoff = time.time() - (hours * 3600)
        return await self._fetchall(
            "SELECT * FROM incidents WHERE last_seen >= ? ORDER BY last_seen DESC LIMIT ?",
            (cutoff, limit),
        )

    async def latest_incident(self, bot: str | None = None) -> dict[str, Any] | None:
        if bot:
            return await self._fetchone(
                "SELECT * FROM incidents WHERE bot = ? ORDER BY last_seen DESC LIMIT 1",
                (bot,),
            )
        return await self._fetchone("SELECT * FROM incidents ORDER BY last_seen DESC LIMIT 1")

    # ── Parmak İzi & Öğrenme (Fingerprints) ──
    async def get_fingerprint(self, fp: str) -> dict[str, Any] | None:
        row = await self._fetchone("SELECT * FROM fingerprints WHERE fingerprint = ?", (fp,))
        if row and row.get("ai_json"):
            try:
                row["ai"] = json.loads(row["ai_json"])
            except Exception:
                row["ai"] = None
        return row

    async def touch_fingerprint(
        self,
        fp: str,
        *,
        bot: str,
        category: str,
        title: str,
        location: str | None = None,
        now: float | None = None,
    ) -> dict[str, Any]:
        ts = now or time.time()
        existing = await self.get_fingerprint(fp)
        if existing:
            total = int(existing["total_occurrences"]) + 1
            await self._exec(
                "UPDATE fingerprints SET total_occurrences=?, last_seen=?, title=?, location=COALESCE(?, location) "
                "WHERE fingerprint=?",
                (total, ts, title, location, fp),
            )
            existing["total_occurrences"] = total
            existing["last_seen"] = ts
            return existing

        await self._exec(
            "INSERT INTO fingerprints (fingerprint, bot, category, location, title, total_occurrences, first_seen, last_seen) "
            "VALUES (?,?,?,?,?,1,?,?)",
            (fp, bot, category, location, title, ts, ts),
        )
        return {
            "fingerprint": fp,
            "bot": bot,
            "category": category,
            "location": location,
            "title": title,
            "total_occurrences": 1,
            "first_seen": ts,
            "last_seen": ts,
            "ai": None,
            "learned_resolution": None,
            "resolved_count": 0,
        }

    async def save_fingerprint_ai(self, fp: str, ai_data: dict[str, Any]) -> None:
        await self._exec(
            "UPDATE fingerprints SET ai_json=? WHERE fingerprint=?",
            (json.dumps(ai_data, ensure_ascii=False), fp),
        )

    async def record_resolution(self, fp: str | None, resolution_note: str) -> None:
        if not fp:
            return
        await self._exec(
            "UPDATE fingerprints SET learned_resolution=?, resolved_count = resolved_count + 1 WHERE fingerprint=?",
            (resolution_note, fp),
        )

    # ── Denetim Kaydı (Audit Log) ──
    async def log_action(
        self,
        *,
        actor: str,
        action: str,
        target: str,
        reason: str = "",
        incident_id: int | None = None,
    ) -> None:
        await self._exec(
            "INSERT INTO audit_actions (ts, actor, action, target, reason, incident_id) VALUES (?,?,?,?,?,?)",
            (time.time(), actor, action, target, reason[:500], incident_id),
        )

    async def recent_actions(self, hours: int = 24, limit: int = 30) -> list[dict[str, Any]]:
        cutoff = time.time() - (hours * 3600)
        return await self._fetchall(
            "SELECT * FROM audit_actions WHERE ts >= ? ORDER BY ts DESC LIMIT ?",
            (cutoff, limit),
        )

    # ── Modül Bayrakları Yedeği (Redis olmadığında veya yedek olarak) ──
    async def set_flag_db(self, bot: str, module: str, state: str, reason: str = "", updated_by: str = "brain") -> None:
        now = time.time()
        existing = await self._fetchone(
            "SELECT state FROM module_flags WHERE bot=? AND module=?",
            (bot, module),
        )
        if existing:
            await self._exec(
                "UPDATE module_flags SET state=?, reason=?, updated_by=?, updated_at=? WHERE bot=? AND module=?",
                (state, reason, updated_by, now, bot, module),
            )
        else:
            await self._exec(
                "INSERT INTO module_flags (bot, module, state, reason, updated_by, updated_at) VALUES (?,?,?,?,?,?)",
                (bot, module, state, reason, updated_by, now),
            )

    async def get_flags_db(self, bot: str | None = None) -> dict[str, dict[str, str]]:
        if bot:
            rows = await self._fetchall("SELECT * FROM module_flags WHERE bot=?", (bot,))
        else:
            rows = await self._fetchall("SELECT * FROM module_flags")
        out: dict[str, dict[str, str]] = {}
        for r in rows:
            out.setdefault(r["bot"], {})[r["module"]] = r["state"]
        return out

    # ── Kalıcı Anahtar-Değer Durumu ──
    async def set_kv(self, key: str, value: str) -> None:
        existing = await self._fetchone("SELECT v FROM kv_state WHERE k=?", (key,))
        if existing:
            await self._exec("UPDATE kv_state SET v=? WHERE k=?", (value, key))
        else:
            await self._exec("INSERT INTO kv_state (k, v) VALUES (?,?)", (key, value))

    async def get_kv(self, key: str, default: str = "") -> str:
        row = await self._fetchone("SELECT v FROM kv_state WHERE k=?", (key,))
        return str(row["v"]) if row else default
