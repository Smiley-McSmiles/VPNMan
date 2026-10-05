"""Installed-application discovery (freedesktop .desktop entries) for the split-tunnel whitelist."""

import os
import re
import shlex

INTERPRETERS = {"sh", "bash", "dash", "zsh", "env", "python", "python3", "perl", "ruby", "java", "node", "wine",
                "wine64", "flatpak", "snap", "gamemoderun", "mangohud", "gamescope", "bwrap"}
_FIELD_CODE = re.compile(r"%[a-zA-Z%]")


def data_dirs(extra=()):
    dirs = list(extra)
    home = os.environ.get("XDG_DATA_HOME") or os.path.join(os.path.expanduser("~"), ".local", "share")
    dirs.append(home)
    dirs += (os.environ.get("XDG_DATA_DIRS") or "/usr/local/share:/usr/share").split(":")
    dirs += ["/usr/share", "/usr/local/share", "/var/lib/flatpak/exports/share",
             os.path.join(home, "flatpak", "exports", "share"), "/var/lib/snapd/desktop"]
    seen, out = set(), []
    for d in dirs:
        d = os.path.join(d, "applications") if d and not d.rstrip("/").endswith("applications") else d
        if d and d not in seen and os.path.isdir(d):
            seen.add(d)
            out.append(d)
    return out


def parse_desktop(path):
    """Return the [Desktop Entry] keys of a launcher (first value wins, localized names ignored)."""
    entry, inside = {}, False
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if line.startswith("["):
                    if inside:
                        break
                    inside = line == "[Desktop Entry]"
                elif inside and "=" in line and not line.startswith("#"):
                    k, _, v = line.partition("=")
                    entry.setdefault(k.strip(), v.strip())
    except OSError:
        return {}
    return entry


def exec_names(exec_line, desktop_id="", wm_class=""):
    """Process names a launcher can show up as: the executable, a Flatpak/Snap id, the WM class."""
    try:
        argv = shlex.split(_FIELD_CODE.sub("", exec_line or ""))
    except ValueError:
        argv = (exec_line or "").split()
    names = []
    i = 0
    while i < len(argv):
        a = argv[i]
        base = os.path.basename(a)
        if "=" in a and not a.startswith("/"):             # VAR=value
            i += 1
            continue
        if base in ("env", "sh", "bash", "gamemoderun", "mangohud", "nohup") or a.startswith("-"):
            i += 1
            continue
        if base == "flatpak":
            rest = [x for x in argv[i + 1:] if not x.startswith("-") and x != "run"]
            if rest:
                names.append(rest[0])
            break
        if base == "snap" and argv[i + 1:i + 2] == ["run"]:
            names.append(argv[i + 2] if len(argv) > i + 2 else "")
            break
        names.append(base)
        break
    stem = desktop_id[:-8] if desktop_id.endswith(".desktop") else desktop_id
    if stem:
        names.append(stem)
        if stem.count(".") >= 2:                            # org.mozilla.firefox -> firefox
            names.append(stem.rsplit(".", 1)[1])
    if wm_class:
        names.append(wm_class)
    out = []
    for n in names:
        n = n.strip()
        if n and n not in out:
            out.append(n)
    return out


def discover(extra_dirs=()):
    """Installed GUI/launchable applications: [{id, name, match, icon, comment}] sorted by name."""
    found = {}
    for d in data_dirs(extra_dirs):
        for base, _dirs, files in os.walk(d):
            for fn in files:
                if not fn.endswith(".desktop"):
                    continue
                rel = os.path.relpath(os.path.join(base, fn), d).replace(os.sep, "-")
                if rel in found:
                    continue
                e = parse_desktop(os.path.join(base, fn))
                if e.get("Type", "Application") != "Application" or not e.get("Name") or not e.get("Exec"):
                    continue
                if e.get("NoDisplay", "").lower() == "true" or e.get("Hidden", "").lower() == "true":
                    continue
                match = exec_names(e["Exec"], rel, e.get("StartupWMClass", ""))
                if not match:
                    continue
                found[rel] = {"id": rel, "name": e["Name"], "match": match, "icon": e.get("Icon", ""),
                              "comment": e.get("Comment", "")}
    return sorted(found.values(), key=lambda a: a["name"].lower())


def custom_entry(text):
    """Whitelist entry for a bare executable/process name typed by the user."""
    name = os.path.basename(text.strip())
    if not name or "\x00" in name or "/" in name:
        raise ValueError("enter a program name such as 'firefox'")
    return {"id": "custom:" + name, "name": name, "match": [name], "icon": ""}
