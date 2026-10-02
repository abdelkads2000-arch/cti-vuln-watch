"""Follow-the-sun routing: who receives an alert, in which language, at a given time."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, time
from pathlib import Path
from zoneinfo import ZoneInfo

import yaml

DAYS = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]


@dataclass(frozen=True)
class Team:
    id: str
    name: str
    timezone: str
    start: time
    end: time
    days: tuple[str, ...]
    lang: str
    webhook_env: str | None

    def on_shift(self, at: datetime) -> bool:
        local = at.astimezone(ZoneInfo(self.timezone))
        if DAYS[local.weekday()] not in self.days:
            return False
        t = local.time()
        if self.start <= self.end:
            return self.start <= t < self.end
        return t >= self.start or t < self.end  # shift crossing midnight


@dataclass
class Routing:
    teams: list[Team]
    default_team: str

    @classmethod
    def load(cls, path: Path) -> Routing:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        teams = []
        for t in data["teams"]:
            teams.append(
                Team(
                    id=t["id"],
                    name=t["name"],
                    timezone=t["timezone"],
                    start=time.fromisoformat(t["hours"]["start"]),
                    end=time.fromisoformat(t["hours"]["end"]),
                    days=tuple(t.get("days", DAYS)),
                    lang=t.get("lang", "fr"),
                    webhook_env=t.get("teams_webhook_env"),
                )
            )
        return cls(teams, data.get("default_team", teams[0].id))

    def team(self, team_id: str) -> Team:
        return next(t for t in self.teams if t.id == team_id)

    def recipients(self, priority: str, at: datetime) -> list[Team]:
        on = [t for t in self.teams if t.on_shift(at)]
        if priority == "P1":
            return on or list(self.teams)  # nobody on shift: everybody gets a P1
        if priority == "P2":
            return on or [self.team(self.default_team)]
        return []  # P3 goes to the daily digest
