"""Connection schedule: connect the VPN at set times (and optionally disconnect again).

An entry: {"id", "name", "enabled", "days": [0..6] (Mon=0), "start": "HH:MM", "end": "HH:MM" or "",
           "profile": "" | "last" | "fastest" | <profile id or name>}

A window that ends before (or at) its start time runs past midnight and belongs to the day it started on.  An entry
without an end time only connects at its start time.  The scheduler acts on edges (a window opening or closing), so
a manual disconnect inside a window is respected until the next edge.
"""

import re
import threading
import time
import uuid

DAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
WEEK = 7 * 1440
TICK = 15
_HHMM = re.compile(r"^([01]?\d|2[0-3]):([0-5]\d)$")


def minutes(text):
    m = _HHMM.match(str(text or "").strip())
    if not m:
        raise ValueError("time must look like 09:30 (24-hour), got %r" % (text,))
    return int(m.group(1)) * 60 + int(m.group(2))


def clean(entry):
    """Validate and normalise one entry (raises ValueError)."""
    days = sorted({int(d) for d in entry.get("days", [])})
    if not days or days[0] < 0 or days[-1] > 6:
        raise ValueError("pick at least one day")
    start = minutes(entry.get("start"))
    end = str(entry.get("end") or "").strip()
    if end:
        minutes(end)
    return {"id": str(entry.get("id") or uuid.uuid4().hex[:8]), "name": str(entry.get("name") or "").strip(),
            "enabled": bool(entry.get("enabled", True)), "days": days,
            "start": "%02d:%02d" % divmod(start, 60), "end": "%02d:%02d" % divmod(minutes(end), 60) if end else "",
            "profile": str(entry.get("profile") or "")}


def duration(entry):
    """Window length in minutes (1 for an entry without an end time: it only fires once at its start)."""
    if not entry.get("end"):
        return 1
    d = (minutes(entry["end"]) - minutes(entry["start"])) % 1440
    return d or 1440


def week_minute(t):
    return t.tm_wday * 1440 + t.tm_hour * 60 + t.tm_min


def is_active(entry, t=None):
    """Is `t` (a time.struct_time, default now) inside this entry's window?"""
    if not entry.get("enabled", True):
        return False
    now = week_minute(t or time.localtime())
    dur = duration(entry)
    start = minutes(entry["start"])
    return any((now - (d * 1440 + start)) % WEEK < dur for d in entry.get("days", []))


def next_start(entry, t=None):
    """Minutes from now until the window next opens, or None."""
    if not entry.get("enabled", True) or not entry.get("days"):
        return None
    now = week_minute(t or time.localtime())
    start = minutes(entry["start"])
    waits = [(d * 1440 + start - now) % WEEK for d in entry["days"]]
    waits = [w for w in waits if w > 0] or [WEEK]
    return min(waits)


def describe_days(days):
    days = sorted(days)
    if days == list(range(7)):
        return "Every day"
    if days == [0, 1, 2, 3, 4]:
        return "Weekdays"
    if days == [5, 6]:
        return "Weekends"
    return ", ".join(DAYS[d] for d in days)


def describe(entry):
    span = "%s → %s" % (entry["start"], entry["end"]) if entry.get("end") else "at %s" % entry["start"]
    return "%s · %s" % (describe_days(entry.get("days", [])), span)


class Scheduler:
    """Edge-triggered driver.  `manager` needs connect(), disconnect(), status(), settings and log."""

    def __init__(self, manager):
        self.m = manager
        self.prev = {}            # entry id -> was active
        self.owned = None         # entry id whose window started the current connection
        self._stop = threading.Event()
        self._thread = None

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, args=(self._stop,), daemon=True, name="scheduler")
        self._thread.start()

    def stop(self):
        self._stop.set()

    def _loop(self, stop):
        while not stop.is_set():
            try:
                self.tick()
            except Exception as e:  # noqa: BLE001
                self.m.log.add("warn", "Scheduler: %s" % e)
            stop.wait(TICK)

    def tick(self, t=None):
        s = self.m.settings
        if not s.get("schedule.enabled"):
            self.prev = {}
            return
        entries = s.get("schedule.entries")
        t = t or time.localtime()
        state = self.m.status()["state"]
        if self.owned and state == "disconnected":
            self.owned = None                         # the user (or an error) ended it: stop managing it
        now = {e["id"]: is_active(e, t) for e in entries if "id" in e}
        opened = [e for e in entries if now.get(e.get("id")) and not self.prev.get(e.get("id"))]
        closed = [e for e in entries if self.prev.get(e.get("id")) and not now.get(e.get("id"))]
        self.prev = now
        for e in opened:
            self._open(e, state)
        if self.owned and any(e["id"] == self.owned for e in closed):
            others = [e for e in entries if now.get(e.get("id")) and e.get("end")]
            if others:
                self.owned = others[0]["id"]          # an overlapping window keeps the VPN up
            else:
                e = next(x for x in closed if x["id"] == self.owned)
                self.m.log.add("info", "Schedule '%s' ended - disconnecting" % (e.get("name") or e["start"]))
                self.owned = None
                self.m.disconnect()

    def _open(self, e, state):
        label = e.get("name") or "%s %s" % (describe_days(e["days"]), e["start"])
        if state in ("connected", "connecting", "reconnecting"):
            self.m.log.add("info", "Schedule '%s': already connected" % label)
            return
        prof = e.get("profile") or ""
        try:
            r = self.m.connect(None if prof in ("", "last") else prof, fastest=(prof == "fastest"),
                               last=(prof in ("", "last")), persistent=True)
        except Exception as ex:  # noqa: BLE001
            self.m.log.add("error", "Schedule '%s' could not connect: %s" % (label, ex))
            return
        self.m.log.add("info", "Schedule '%s': connecting to %s" % (label, r["profile"]))
        if e.get("end"):
            self.owned = e["id"]
