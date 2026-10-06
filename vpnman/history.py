"""Connection history: one record per tunnel that was up (server, when, how long, traffic, why it ended)."""

import json
import os
import threading
import time

from . import paths


class History:
    def __init__(self, path=None, limit=200):
        self.path = path or os.path.join(paths.config_dir(), "history.json")
        self.limit = limit
        self._lock = threading.Lock()

    def _read(self):
        try:
            with open(self.path) as fh:
                data = json.load(fh)
            return data if isinstance(data, list) else []
        except (OSError, ValueError):
            return []

    def add(self, profile, protocol, start, end=None, rx=0, tx=0, reason=""):
        end = end or time.time()
        entry = {"profile": profile, "protocol": protocol, "start": int(start), "end": int(end),
                 "duration": max(int(end - start), 0), "rx": int(rx), "tx": int(tx), "reason": reason}
        with self._lock:
            items = (self._read() + [entry])[-self.limit:]
            os.makedirs(os.path.dirname(self.path), mode=0o700, exist_ok=True)
            tmp = self.path + ".tmp"
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as fh:
                json.dump(items, fh)
            os.replace(tmp, self.path)
        return entry

    def list(self, limit=50):
        """Newest first."""
        with self._lock:
            return list(reversed(self._read()))[:max(int(limit), 0)]

    def clear(self):
        with self._lock:
            try:
                os.unlink(self.path)
            except OSError:
                pass
