"""End-to-end check of the network proxy with a real xray and real nftables, inside a private network namespace.

Run as root:   unshare -n python3 tests/netns_check.py /path/to/xray
(tests/test_vpnman.py runs it when root, unshare, nft and xray are available.)

The namespace's loopback device gets the addresses of a "website" (10.99.0.2 and 10.99.0.5), an HTTP CONNECT proxy that logs what it
carries (10.99.0.3:8080) and a DNS server that only speaks TCP (10.99.0.6:53).  Then:
* a plain connection to the website must arrive through the proxy (system-wide redirect -> xray -> HTTP proxy),
* a DNS query sent over UDP to any address must be answered - over TCP through the HTTP proxy,
* an ignored address must be reached directly.
(That other UDP and IPv6 are blocked is checked on the ruleset text: on loopback the guard lets everything pass.)
"""
import os
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import json

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from vpnman import xray  # noqa: E402

LOG = []


def sh(*cmd):
    subprocess.run(cmd, check=True)


def website(ip):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((ip, 80))
    s.listen(16)

    def serve():
        while True:
            c, _ = s.accept()
            c.recv(4096)
            c.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: 4\r\n\r\nsite")
            c.close()
    threading.Thread(target=serve, daemon=True).start()


def pipe(a, b):
    try:
        while True:
            d = a.recv(65536)
            if not d:
                break
            b.sendall(d)
    except OSError:
        pass
    finally:
        for x in (a, b):
            try:
                x.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def http_proxy(ip, port):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((ip, port))
    s.listen(16)

    def handle(c):
        head = b""
        while b"\r\n\r\n" not in head:
            d = c.recv(4096)
            if not d:
                return
            head += d
        line = head.split(b"\r\n", 1)[0].decode()
        LOG.append(line)
        method, target, _ = line.split(" ", 2)
        if method != "CONNECT":
            c.sendall(b"HTTP/1.1 405 Only CONNECT\r\n\r\n")
            c.close()
            return
        host, port = target.rsplit(":", 1)
        # the proxy stands in for a remote machine: its own connections must not be redirected (as Xray's are not)
        u = socket.socket()
        u.setsockopt(socket.SOL_SOCKET, getattr(socket, "SO_MARK", 36), xray.MARK)
        u.settimeout(5)
        u.connect((host, int(port)))
        c.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
        threading.Thread(target=pipe, args=(c, u), daemon=True).start()
        pipe(u, c)

    def serve():
        while True:
            c, _ = s.accept()
            threading.Thread(target=handle, args=(c,), daemon=True).start()
    threading.Thread(target=serve, daemon=True).start()


def tcp_dns(ip, answer):
    """Answers every A query with ``answer`` - over TCP only."""
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((ip, 53))
    s.listen(16)

    def serve():
        while True:
            c, _ = s.accept()
            try:
                n = struct.unpack("!H", c.recv(2))[0]
                q = c.recv(n)
                qid, qd = q[:2], q[12:]
                end = qd.index(b"\0") + 5
                resp = (qid + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" + qd[:end] +
                        b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" + socket.inet_aton(answer))
                c.sendall(struct.pack("!H", len(resp)) + resp)
            except (OSError, ValueError, struct.error):
                pass
            c.close()
    threading.Thread(target=serve, daemon=True).start()


def udp_query(server, name):
    q = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + b"".join(
        bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0\x00\x01\x00\x01"
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(8)
    s.sendto(q, (server, 53))
    data, _ = s.recvfrom(512)
    return socket.inet_ntoa(data[-4:])


def fetch(ip):
    c = socket.create_connection((ip, 80), timeout=8)
    c.sendall(b"GET / HTTP/1.0\r\n\r\n")
    data = b""
    while True:
        d = c.recv(4096)
        if not d:
            break
        data += d
    return data.split(b"\r\n\r\n", 1)[-1]


def main(xray_bin):
    sh("ip", "link", "set", "lo", "up")
    for a in ("10.99.0.2/32", "10.99.0.3/32", "10.99.0.5/32", "10.99.0.6/32"):
        sh("ip", "addr", "add", a, "dev", "lo")
    sh("ip", "route", "add", "default", "dev", "lo")          # "the internet" (192.0.2.53 below) is local, too
    website("10.99.0.2")
    website("10.99.0.5")
    http_proxy("10.99.0.3", 8080)
    tcp_dns("10.99.0.6", "10.99.0.2")
    redirect, dns = xray.free_port(), None
    dns = xray.free_port({redirect})
    conf = xray.netproxy_config({"http": ("10.99.0.3", 8080, "", "")}, redirect=redirect, dns=dns, mark=xray.MARK,
                                dns_server="10.99.0.6", direct_nets=["10.99.0.5/32"])
    d = tempfile.mkdtemp()
    path = os.path.join(d, "x.json")
    with open(path, "w") as fh:
        json.dump(conf, fh)
    proc = subprocess.Popen([xray_bin, "run", "-c", path], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    ok = False
    try:
        time.sleep(1.5)
        rules = xray.redirect_ruleset(redirect, dns, exclude=["10.99.0.5/32"], allow_lan=False)
        subprocess.run(["nft", "-f", "-"], input=rules.encode(), check=True)
        assert fetch("10.99.0.2") == b"site", "the website answers through the redirect"
        assert any(l.startswith("CONNECT 10.99.0.2:80") for l in LOG), ("the proxy carried it", LOG)
        n = len(LOG)
        assert udp_query("192.0.2.53", "example.test") == "10.99.0.2", "DNS over UDP is answered (via TCP)"
        assert any(l.startswith("CONNECT 10.99.0.6:53") for l in LOG[n:]), ("DNS went through the proxy", LOG)
        n = len(LOG)
        assert fetch("10.99.0.5") == b"site" and len(LOG) == n, ("an ignored address goes direct", LOG)
        ok = True
        print("NETNS-OK")
    finally:
        proc.terminate()
        out = proc.communicate(timeout=5)[0].decode(errors="replace")
        if not ok:
            print(out[-3000:])


if __name__ == "__main__":
    try:
        main(sys.argv[1])
    except AssertionError as e:
        print("FAILED:", e)
        sys.exit(1)
