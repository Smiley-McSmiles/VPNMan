"""Filesystem locations.  Every location can be overridden through the
environment, which is what the test-suite and unprivileged dev runs use."""

import os
import sys

_BSD = sys.platform.startswith(("openbsd", "freebsd", "netbsd", "darwin", "dragonfly"))


def config_dir():
    return os.environ.get("VPNMAN_CONFIG_DIR", "/etc/vpnman")


def run_dir():
    return os.environ.get("VPNMAN_RUN_DIR", "/var/run/vpnman" if _BSD else "/run/vpnman")


def socket_path():
    return os.environ.get("VPNMAN_SOCKET", os.path.join(run_dir(), "vpnman.sock"))


def log_file():
    return os.environ.get("VPNMAN_LOG_FILE", "/var/log/vpnman.log")


def profiles_dir():
    return os.path.join(config_dir(), "profiles")


def settings_file():
    return os.path.join(config_dir(), "settings.json")


def state_file():
    return os.path.join(config_dir(), "state.json")


def pidfile():
    return os.path.join(run_dir(), "vpnmand.pid")
