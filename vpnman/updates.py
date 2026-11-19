"""Look for a newer VPNMan release on GitHub.  Runs as the user (no root, no daemon), only when asked or opted in."""

import json
import re
import urllib.request

from . import __version__

API = "https://api.github.com/repos/Smiley-McSmiles/VPNMan/releases/latest"
PAGE = "https://github.com/Smiley-McSmiles/VPNMan/releases"


_PRE_ORDER = {"dev": 0, "alpha": 1, "beta": 2, "pre": 3, "rc": 4}


def parse(v):
    """'v1.2.3' -> (1, 2, 3, 0, 5, 0); anything unparsable -> None."""
    m = re.match(r"^v?(\d+)\.(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:[_~-]?(dev|alpha|beta|pre|rc)(\d*))?$",
                 str(v).strip(), re.I)
    if not m:
        return None
    *nums, pre, pre_num = m.groups()
    if pre:
        rank = (_PRE_ORDER[pre.lower()], int(pre_num or 0))
    else:
        rank = (len(_PRE_ORDER), 0)
    return tuple(int(x or 0) for x in nums) + rank       # alpha < beta < rc < final


def is_newer(latest, current=__version__):
    a, b = parse(latest), parse(current)
    return bool(a and b and a > b)


def check(timeout=8, opener=None):
    """Return {"current", "latest", "newer", "url", "notes"}; raises OSError/ValueError when GitHub cannot be reached."""
    req = urllib.request.Request(API, headers={"Accept": "application/vnd.github+json",
                                               "User-Agent": "vpnman/%s" % __version__})
    with (opener or urllib.request.urlopen)(req, timeout=timeout) as r:
        data = json.loads(r.read(1 << 20).decode("utf-8", "replace"))
    if not isinstance(data, dict):
        raise ValueError("unexpected answer from GitHub")
    tag = str(data.get("tag_name") or "")
    if not parse(tag):
        raise ValueError("unexpected answer from GitHub")
    return {"current": __version__, "latest": tag.lstrip("v"), "newer": is_newer(tag),
            "url": data.get("html_url") if str(data.get("html_url", "")).startswith("https://github.com/") else PAGE,
            "notes": str(data.get("body") or "")[:2000]}
