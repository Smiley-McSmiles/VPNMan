"""The DNS of the programs that skip the VPN, with a resolver on the computer itself (systemd-resolved's stub, dnsmasq...).

Run as root:   unshare -n python3 tests/dnsfwd_check.py
(tests/test_vpnman.py runs it when root, unshare, nsenter and nft are available.)

A stub resolver listens on 127.0.0.53 (what /etc/resolv.conf names on Fedora) and answers 10.1.1.1 - "through the VPN".
The chosen resolver, 203.0.113.53, sits behind a veth pair in another namespace and answers 10.2.2.2.  A program of the
bypass (here: a socket carrying the bypass mark, standing in for the cgroup match, which needs cgroup v2) asks the stub:
* without the forwarder it gets the stub's answer (the bug: its DNS went the VPN's way),
* with the forwarder rule the same query - UDP and TCP - is answered by the chosen resolver,
* a program that is not part of the bypass still gets the stub's answer.
"""
import os
import socket
import struct
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from vpnman import split  # noqa: E402
from vpnman.dnsfwd import DnsForwarder  # noqa: E402

SERVER = r"""
import socket, struct, sys, threading
ip, answer = sys.argv[1], sys.argv[2]
def reply(q):
    end = q[12:].index(b"\0") + 17
    return q[:2] + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" + q[12:end] + \
        b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" + socket.inet_aton(answer)
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.bind((ip, 53))
t = socket.socket(); t.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); t.bind((ip, 53)); t.listen(8)
def udp():
    while True:
        q, peer = u.recvfrom(512)
        u.sendto(reply(q), peer)
def tcp_conn(c):
    try:
        n = struct.unpack("!H", c.recv(2))[0]
        r = reply(c.recv(n))
        c.sendall(struct.pack("!H", len(r)) + r)
    except OSError:
        pass
    c.close()
def tcp():
    while True:
        c, _ = t.accept()
        threading.Thread(target=tcp_conn, args=(c,), daemon=True).start()
threading.Thread(target=udp, daemon=True).start()
tcp()
"""


def sh(*cmd):
    subprocess.run(cmd, check=True, capture_output=True)


def query_connected(server, name, mark=0):
    """The way glibc asks: a connect()ed UDP socket."""
    q = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + b"".join(
        bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0\x00\x01\x00\x01"
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if mark:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, mark)
    s.settimeout(4)
    try:
        s.connect((server, 53))
        s.send(q)
        return socket.inet_ntoa(s.recv(512)[-4:])
    except OSError:
        return None
    finally:
        s.close()


def query(server, name, tcp=False, mark=0):
    q = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + b"".join(
        bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0\x00\x01\x00\x01"
    kind = socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM
    s = socket.socket(socket.AF_INET, kind)
    if mark:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, mark)
    s.settimeout(4)
    try:
        if tcp:
            s.connect((server, 53))
            s.sendall(struct.pack("!H", len(q)) + q)
            n = struct.unpack("!H", s.recv(2))[0]
            data = s.recv(n)
        else:
            s.sendto(q, (server, 53))
            data = s.recvfrom(512)[0]
        return socket.inet_ntoa(data[-4:])
    except OSError:
        return None
    finally:
        s.close()


def local_server(ip, answer):
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.bind((ip, 53))
    t = socket.socket()
    t.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    t.bind((ip, 53))
    t.listen(8)

    def reply(q):
        end = q[12:].index(b"\0") + 17
        return q[:2] + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" + q[12:end] + \
            b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" + socket.inet_aton(answer)

    def udp():
        while True:
            q, peer = u.recvfrom(512)
            u.sendto(reply(q), peer)

    def conn(c):
        try:
            n = struct.unpack("!H", c.recv(2))[0]
            r = reply(c.recv(n))
            c.sendall(struct.pack("!H", len(r)) + r)
        except OSError:
            pass
        c.close()

    def tcp():
        while True:
            c, _ = t.accept()
            threading.Thread(target=conn, args=(c,), daemon=True).start()
    threading.Thread(target=udp, daemon=True).start()
    threading.Thread(target=tcp, daemon=True).start()


def main():
    sh("ip", "link", "set", "lo", "up")
    sh("ip", "addr", "add", "127.0.0.53/8", "dev", "lo")
    local_server("127.0.0.53", "10.1.1.1")                       # the stub: "the VPN's DNS"
    far = subprocess.Popen(["unshare", "-n", "sleep", "300"])
    server = None
    try:
        time.sleep(0.5)
        sh("ip", "link", "add", "v0", "type", "veth", "peer", "name", "v1")
        sh("ip", "link", "set", "v1", "netns", str(far.pid))
        sh("ip", "addr", "add", "10.98.0.1/24", "dev", "v0")
        sh("ip", "link", "set", "v0", "up")
        ns = ["nsenter", "-t", str(far.pid), "-n"]
        sh(*ns, "ip", "addr", "add", "10.98.0.2/24", "dev", "v1")
        sh(*ns, "ip", "addr", "add", "203.0.113.53/32", "dev", "lo")
        sh(*ns, "ip", "link", "set", "v1", "up")
        sh(*ns, "ip", "link", "set", "lo", "up")
        sh("ip", "route", "add", "203.0.113.53/32", "via", "10.98.0.2")
        server = subprocess.Popen(ns + [sys.executable, "-c", SERVER, "203.0.113.53", "10.2.2.2"],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1.0)
        assert query("203.0.113.53", "far.test") == "10.2.2.2", "the chosen resolver answers"

        mark = split.MARK
        # the real ruleset, with the cgroup match swapped for the mark (this machine may have no cgroup v2)
        def rules(port):
            text = split.ruleset(["203.0.113.53"], mode="exclude", fwd_port=port)
            return text.replace('socket cgroupv2 level 1 "%s"' % split.CGROUP, "meta mark 0x%x" % mark)

        subprocess.run(["nft", "-f", "-"], input=rules(0), text=True, check=True)
        assert query("127.0.0.53", "a.test", mark=mark) == "10.1.1.1", "before: the bypassed program gets the stub's answer"
        fwd = DnsForwarder("203.0.113.53", mark)
        port = fwd.start()
        subprocess.run(["nft", "-f", "-"], input=rules(port), text=True, check=True)
        assert query("127.0.0.53", "b.test", mark=mark) == "10.2.2.2", "UDP to the stub goes to the chosen resolver"
        assert query("127.0.0.53", "c.test", tcp=True, mark=mark) == "10.2.2.2", "and so does TCP"
        assert query_connected("127.0.0.53", "glibc.test", mark=mark) == "10.2.2.2", "a connect()ed socket (glibc) as well"
        assert query("127.0.0.53", "d.test") == "10.1.1.1", "a program that is not part of the bypass keeps the stub"
        assert query("203.0.113.53", "e.test", mark=mark) == "10.2.2.2", "a direct query to the chosen resolver is untouched"
        fwd.stop()
        print("DNSFWD-OK")
    finally:
        if server:
            server.terminate()
        far.terminate()


if __name__ == "__main__":
    try:
        main()
    except AssertionError as e:
        print("FAILED:", e)
        sys.exit(1)
