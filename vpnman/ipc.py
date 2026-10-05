"""Line-delimited JSON-RPC over a Unix socket (daemon <-> CLI/GUI)."""

import json
import os
import socket

from . import paths


class DaemonUnavailable(Exception):
    pass


class RpcError(Exception):
    pass


class Client:
    def __init__(self, path=None, timeout=120):
        self.path = path or paths.socket_path()
        self.timeout = timeout
        self._n = 0

    def call(self, method, **params):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        try:
            s.connect(self.path)
        except FileNotFoundError:
            raise DaemonUnavailable("the vpnman daemon is not running (socket %s not found)" % self.path)
        except PermissionError:
            raise DaemonUnavailable("permission denied on %s - join the 'vpnman' group (then log in again) or use sudo"
                                    % self.path)
        except (ConnectionRefusedError, OSError) as e:
            raise DaemonUnavailable("cannot reach the vpnman daemon: %s" % e)
        try:
            self._n += 1
            s.sendall((json.dumps({"id": self._n, "method": method, "params": params}) + "\n").encode())
            buf = b""
            while not buf.endswith(b"\n"):
                chunk = s.recv(65536)
                if not chunk:
                    break
                buf += chunk
        except (socket.timeout, OSError) as e:
            raise DaemonUnavailable("daemon did not answer: %s" % e)
        finally:
            s.close()
        try:
            resp = json.loads(buf.decode())
        except ValueError:
            raise DaemonUnavailable("garbled reply from daemon")
        if not resp.get("ok"):
            raise RpcError(resp.get("error", "unknown error"))
        return resp.get("result")

    def alive(self):
        try:
            self.call("ping")
            return True
        except DaemonUnavailable:
            return False


def peer_uid(conn):
    try:
        import struct
        creds = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        return struct.unpack("3i", creds)[1]
    except (AttributeError, OSError):
        return None


def secure_socket(path):
    """Restrict the socket to root and the vpnman (or wheel) group."""
    import grp
    for g in ("vpnman", "wheel", "sudo"):
        try:
            gid = grp.getgrnam(g).gr_gid
        except KeyError:
            continue
        try:
            os.chown(path, 0, gid)
            os.chmod(path, 0o660)
            return g
        except PermissionError:
            break
    os.chmod(path, 0o600)
    return None
