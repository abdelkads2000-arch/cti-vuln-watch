"""Long-running worker: one APScheduler job per source + processing, digest, heartbeat."""

from __future__ import annotations

import logging
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path

from apscheduler.executors.pool import ThreadPoolExecutor
from apscheduler.schedulers.blocking import BlockingScheduler
from sqlalchemy import select

from cti.db.models import Source
from cti.db.session import session_scope
from cti.pipeline.collect import run_source
from cti.pipeline.notify import routing, send_digest
from cti.pipeline.process import process_pending
from cti.registry import sync_sources
from cti.settings import Settings

log = logging.getLogger(__name__)
HEARTBEAT = Path("/tmp/cti_worker_heartbeat")
_process_lock = threading.Lock()


def _run_source_job(name: str, settings: Settings) -> None:
    with session_scope() as s:
        src = s.scalar(select(Source).where(Source.name == name))
        if src is None or src.status == "disabled":
            return
        run_source(s, src, settings)


def _process_job(settings: Settings) -> None:
    if not _process_lock.acquire(blocking=False):
        return
    try:
        with session_scope() as s:
            process_pending(s, settings)
    finally:
        _process_lock.release()


def _digest_job(settings: Settings) -> None:
    with session_scope() as s:
        send_digest(s, settings)


def _heartbeat() -> None:
    HEARTBEAT.write_text(datetime.now(UTC).isoformat())


def _sync_jobs(sched: BlockingScheduler, settings: Settings) -> None:
    with session_scope() as s:
        sources = sync_sources(s, settings)
        wanted = {f"src:{src.name}": src for src in sources if src.status in ("active", "observation")}
    for job in sched.get_jobs():
        if job.id.startswith("src:") and job.id not in wanted:
            job.remove()
    for i, (job_id, src) in enumerate(sorted(wanted.items())):
        existing = sched.get_job(job_id)
        if existing and getattr(existing.trigger, "interval", None) == timedelta(seconds=src.interval_s):
            continue
        # Stagger first runs to avoid hammering everything at startup.
        sched.add_job(
            _run_source_job, "interval", seconds=src.interval_s, args=[src.name, settings], id=job_id,
            replace_existing=True, max_instances=1, coalesce=True,
            next_run_time=datetime.now(UTC) + timedelta(seconds=5 + 10 * i),
        )
    log.info("planification synchronisée", extra={"jobs": sorted(wanted)})


def run_worker(settings: Settings) -> None:
    sched = BlockingScheduler(executors={"default": ThreadPoolExecutor(3)}, timezone=settings.tz)
    _sync_jobs(sched, settings)
    sched.add_job(_process_job, "interval", seconds=120, args=[settings], id="process", max_instances=1, coalesce=True)
    sched.add_job(_sync_jobs, "interval", seconds=300, args=[sched, settings], id="config-sync", max_instances=1)
    rt = routing(settings)
    default = rt.team(rt.default_team)
    sched.add_job(_digest_job, "cron", hour=default.start.hour, minute=default.start.minute, timezone=default.timezone,
                  args=[settings], id="digest")
    sched.add_job(_heartbeat, "interval", seconds=30, id="heartbeat", next_run_time=datetime.now(UTC))
    log.info("worker démarré")
    sched.start()
