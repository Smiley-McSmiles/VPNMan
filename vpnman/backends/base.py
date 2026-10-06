"""Backend interface.  A backend knows how to turn a profile into commands for
one VPN protocol and how to recognise progress in the tool's output."""

import os
import re

from .. import platform as plat


class CredentialsRequired(ValueError):
    """The profile needs a username/password (the GUI asks for them instead of showing an error)."""


class Context:
    """Per-connection scratch state shared between manager and backend."""

    def __init__(self, profile, profile_dir, workdir, ifname, settings):
        self.profile = profile
        self.profile_dir = profile_dir
        self.workdir = workdir
        self.ifname = ifname      # name we ask the tool to give the tunnel (when it supports it)
        self.iface = None         # name actually observed
        self.dns = []             # DNS servers learned from the tunnel
        self.settings = settings
        self.state = {}           # backend private state

    def write(self, name, text, mode=0o600):
        path = os.path.join(self.workdir, name)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
        with os.fdopen(fd, "w") as fh:
            fh.write(text)
        return path


class Backend:
    id = ""
    label = ""
    description = ""
    binaries = ()             # every one of these must be installed
    extensions = ()           # file extensions recognised on import
    mode = "process"          # "process": long-running child; "oneshot": up/down commands
    ready_re = None           # regex that marks the tunnel as established
    iface_fallback = False    # treat "a new interface appeared" as connected
    named_iface = False       # tool accepts a caller-chosen interface name (Linux only)
    needs_credentials = False
    fields = ()               # extra profile fields the GUI/CLI should ask for
    lock_note = ""            # caveat shown when the kill switch is combined with this protocol

    # ---- availability
    def missing(self):
        return [b for b in self.binaries if not plat.which(b)]

    def available(self):
        return not self.missing()

    def binary(self, name=None):
        return plat.which(name or self.binaries[0]) or (name or self.binaries[0])

    # ---- import
    @classmethod
    def sniff(cls, filename, text):
        """Return a confidence 0..100 that this file belongs to the protocol."""
        return 0

    def parse(self, filename, text):
        """Extract profile fields from a config file."""
        return {}

    def iface_prefix(self, profile, profile_dir):
        """Interface name prefix (an index is appended): tun0, tun1, ..."""
        return "tun"

    # ---- profile helpers
    def endpoints(self, profile):
        """List of (host, port, proto) the tunnel itself must reach."""
        eps = [tuple(e) for e in profile.get("options", {}).get("remotes", [])]
        if not eps and profile.get("server"):
            host = profile["server"]
            host = re.sub(r"^[a-z]+://", "", host).split("/")[0]
            if host.count(":") == 1:
                host = host.split(":")[0]
            eps = [(host, profile.get("port") or 0, profile.get("transport") or "")]
        return eps

    def validate(self, profile):
        """Return a list of human readable problems (empty when OK)."""
        problems = []
        miss = self.missing()
        if miss:
            problems.append("missing program(s): " + ", ".join(miss))
        return problems

    # ---- lifecycle
    def prepare(self, ctx):
        """Write runtime files into ctx.workdir."""

    def connect_cmd(self, ctx):
        raise NotImplementedError

    def stdin_data(self, ctx):
        return None

    def connect_cmds(self, ctx):          # oneshot mode
        return [self.connect_cmd(ctx)]

    def disconnect_cmds(self, ctx):       # oneshot mode / extra cleanup for process mode
        return []

    def parse_line(self, line, ctx):
        """Inspect an output line; may update ctx.iface / ctx.dns."""

    def cwd(self, ctx):
        return ctx.profile_dir
