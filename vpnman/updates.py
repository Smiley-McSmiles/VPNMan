"""Look for a newer VPNMan release on GitHub.  Runs as the user (no root, no daemon), only when asked or opted in."""

import json
import re
import urllib.request

from . import __version__

API = "https://api.github.com/repos/Smiley-McSmiles/VPNMan/releases/latest"
PAGE = "https://github.com/Smiley-McSmiles/VPNMan/releases"


def parse(v):
    """'v1.2.3' -> (1, 2, 3); anything unparsable -> None."""
    m = re.match(r"^v?(\d+)\.(\d+)(?:\.(\d+))?", str(v).strip())
    return tuple(int(x or 0) for x in m.groups()) if m else None


def is_newer(latest, current=__version__):
    a, b = parse(latest), parse(current)
    return bool(a and b and a > b)


def check(timeout=8, opener=None):
    """Return {"current", "latest", "newer", "url", "notes"}; raises OSError/ValueError when GitHub cannot be reached."""
    req = urllib.request.Request(API, headers={"Accept": "application/vnd.github+json",
                                               "User-Agent": "vpnman/%s" % __version__})
    with (opener or urllib.request.urlopen)(req, timeout=timeout) as r:
        data = json.loads(r.read(1 << 20).decode("utf-8", "replace"))
    tag = str(data.get("tag_name") or "")
    if not parse(tag):
        raise ValueError("unexpected answer from GitHub")
    return {"current": __version__, "latest": tag.lstrip("v"), "newer": is_newer(tag),
            "url": data.get("html_url") if str(data.get("html_url", "")).startswith("https://github.com/") else PAGE,
            "notes": str(data.get("body") or "")[:2000]}
