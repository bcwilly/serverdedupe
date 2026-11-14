"""Schedule maths for saved jobs (daily / chosen weekdays / one-off), in the container's TZ."""
import os
from datetime import datetime, timedelta, timezone

try:
    from zoneinfo import ZoneInfo
    TZ = ZoneInfo(os.environ.get("TZ") or "UTC")
except Exception:  # noqa: BLE001  (tzdata missing or bad name)
    TZ = timezone.utc

TZ_NAME = os.environ.get("TZ") or "UTC"
GRACE = 3 * 3600          # a job that could not start within 3 h of its time is skipped, not run in daytime


def _hhmm(v, what):
    try:
        h, m = str(v).split(":")
        h, m = int(h), int(m)
        if not (0 <= h < 24 and 0 <= m < 60):
            raise ValueError
        return f"{h:02d}:{m:02d}"
    except ValueError:
        raise ValueError(f"{what} must look like 02:30") from None


def clean(s):
    """Validate a schedule dict from the browser and return a normalised copy."""
    t = s.get("type")
    if t not in ("daily", "weekly", "once"):
        raise ValueError("Choose how often the job runs")
    out = {"type": t}
    if t == "once":
        try:
            datetime.fromisoformat(s.get("at", ""))
        except ValueError:
            raise ValueError("Pick a date and time for the one-off run") from None
        out["at"] = s["at"][:16]
    else:
        out["time"] = _hhmm(s.get("time"), "Start time")
    if t == "weekly":
        days = sorted({int(d) for d in s.get("days", []) if 0 <= int(d) <= 6})
        if not days:
            raise ValueError("Pick at least one day of the week")
        out["days"] = days
    if s.get("stop_at"):
        out["stop_at"] = _hhmm(s["stop_at"], "Stop time")
    return out


def next_run_time(s, after_ts):
    """Epoch seconds of the next run strictly after after_ts, or None (a finished one-off)."""
    after = datetime.fromtimestamp(after_ts, TZ)
    if s["type"] == "once":
        at = datetime.fromisoformat(s["at"]).replace(tzinfo=TZ)
        return at.timestamp() if at.timestamp() > after_ts else None
    h, m = map(int, s["time"].split(":"))
    days = s.get("days") if s["type"] == "weekly" else range(7)
    for d in range(0, 9):
        cand = (after + timedelta(days=d)).replace(hour=h, minute=m, second=0, microsecond=0)
        if cand > after and cand.weekday() in days:
            return cand.timestamp()
    return None


def deadline_for(s, start_ts):
    """Epoch seconds when a run that begins at start_ts must stop, or None."""
    if not s.get("stop_at"):
        return None
    h, m = map(int, s["stop_at"].split(":"))
    start = datetime.fromtimestamp(start_ts, TZ)
    stop = start.replace(hour=h, minute=m, second=0, microsecond=0)
    if stop <= start:
        stop += timedelta(days=1)
    return stop.timestamp()
