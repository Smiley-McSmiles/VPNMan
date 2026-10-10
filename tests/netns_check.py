"""End-to-end check of the network proxy with a real xray and real nftables, inside a private network namespace.

Run as root:   unshare -n python3 tests/netns_check.py /path/to/xray
(tests/test_vpnman.py runs it when root, unshare, nft and xray are available.)

The namespace's loopback device gets the addresses of a "website" (10.99.0.2 and 10.99.0.5), an HTTP CONNECT proxy that logs what it
carries (10.99.0.3:8080) and a DNS server that only speaks TCP (10.99.0.6:53).  Then:
* a plain connection to the website must arrive through the proxy (system-wide redirect -> xray -> HTTP proxy),
* a DNS query sent over UDP to any address must be answered - over TCP through the HTTP proxy,
* an ignored address must be reached directly,
* a device behind a hotspot (a client namespace behind ``ap0``, 10.42.0.0/24) gets the same: its TCP reaches the
  "site" (a namespace behind a veth, 10.98.0.2) through the proxy, its DNS is answered, and an ignored network goes direct,
* a connection the device opened directly before the proxy came on does not carry on around it: the hotspot's
  tracked connections are flushed (hotspot.flush) and it is reset,
* with xray dead and the kill switch's block rules in place, nothing but ignored hosts gets out - for the computer
  and for the hotspot's device.
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
from vpnman import hotspot, xray  # noqa: E402

LOG = []


def sh(*cmd):
    subprocess.run(cmd, check=True)


def nsx(pid, *cmd):
    return subprocess.run(["nsenter", "-t", str(pid), "-n"] + list(cmd), check=True, capture_output=True, text=True)


CLIENT = """
import socket, struct, sys
mode, ip = sys.argv[1], sys.argv[2]
try:
    if mode == "connect":
        socket.create_connection((ip, int(sys.argv[3])), timeout=3).close()
        print("OPEN")
    elif mode == "http":
        c = socket.create_connection((ip, 80), timeout=4)
        c.sendall(b"GET / HTTP/1.0\\r\\n\\r\\n")
        d = b""
        while True:
            x = c.recv(4096)
            if not x: break
            d += x
        print(d.split(b"\\r\\n\\r\\n", 1)[-1].decode())
    else:
        q = b"\\x12\\x34\\x01\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x07hotspot\\x04test\\x00\\x00\\x01\\x00\\x01"
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(5)
        s.sendto(q, (ip, 53))
        print(socket.inet_ntoa(s.recvfrom(512)[0][-4:]))
except OSError as e:
    print("FAIL", e)
"""


HOLD = """
import socket, sys
c = socket.create_connection(("10.98.0.2", 81), timeout=4)
c.sendall(b"a"); c.recv(1)
print("ready", flush=True)
sys.stdin.readline()
c.settimeout(4)
try:
    c.sendall(b"b"); c.recv(1); print("echo", flush=True)
except (ConnectionResetError, BrokenPipeError):
    print("reset", flush=True)
except OSError:
    print("timeout", flush=True)
"""

ECHO = """
import socket, threading
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("0.0.0.0", 81)); s.listen(8)
def serve(c):
    try:
        while True:
            d = c.recv(100)
            if not d: break
            c.sendall(d)
    except OSError: pass
while True:
    c, _ = s.accept()
    threading.Thread(target=serve, args=(c,), daemon=True).start()
"""


def from_client(pid, mode, ip, *extra):
    out = nsx(pid, sys.executable, "-c", CLIENT, mode, ip, *map(str, extra)).stdout.strip()
    return None if out.startswith("FAIL") else out


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
                                dns_server="10.99.0.6", direct_nets=["10.99.0.5/32", "10.98.0.3/32"])
    d = tempfile.mkdtemp()
    os.environ["VPNMAN_RUN_DIR"] = d
    path = os.path.join(d, "x.json")
    with open(path, "w") as fh:
        json.dump(conf, fh)
    # a real second network (on loopback the guards let everything pass): the "site", behind a veth pair, and the
    # device behind the hotspot, behind another one
    site = subprocess.Popen(["unshare", "-n", "sleep", "300"])
    client = subprocess.Popen(["unshare", "-n", "sleep", "300"])
    procs = []
    proc = None
    ok = False
    try:
        time.sleep(0.5)
        for peer, near, far, near_ip, far_ip in ((site, "v0", "v1", "10.98.0.1/24", "10.98.0.2/24"),
                                                 (client, "ap0", "eth0", "10.42.0.1/24", "10.42.0.2/24")):
            sh("ip", "link", "add", near, "type", "veth", "peer", "name", far)
            sh("ip", "link", "set", far, "netns", str(peer.pid))
            sh("ip", "addr", "add", near_ip, "dev", near)
            sh("ip", "link", "set", near, "up")
            nsx(peer.pid, "ip", "addr", "add", far_ip, "dev", far)
            nsx(peer.pid, "ip", "link", "set", far, "up")
            nsx(peer.pid, "ip", "link", "set", "lo", "up")
        nsx(site.pid, "ip", "addr", "add", "10.98.0.3/24", "dev", "v1")
        nsx(site.pid, "ip", "route", "add", "10.42.0.0/24", "via", "10.98.0.1")       # the site answers the hotspot's devices
        # what NetworkManager's shared mode does (and what makes the kernel track the connections)
        subprocess.run(["nft", "-f", "-"], text=True, check=True, input=(
            "table ip nm_shared_ap0 {\n  chain post {\n    type nat hook postrouting priority 100;\n"
            "    ip saddr 10.42.0.0/24 ip daddr != 10.42.0.0/24 masquerade\n  }\n}\n"))
        nsx(client.pid, "ip", "route", "add", "default", "via", "10.42.0.1")
        sh("sysctl", "-qw", "net.ipv4.ip_forward=1")
        sh("sysctl", "-qw", "net.ipv4.conf.all.rp_filter=0")
        procs.append(subprocess.Popen(["nsenter", "-t", str(site.pid), "-n", sys.executable, "-c",
                                       "import http.server\n"
                                       "class H(http.server.BaseHTTPRequestHandler):\n"
                                       " def do_GET(s):\n"
                                       "  s.send_response(200); s.send_header('Content-Length','4'); s.end_headers(); s.wfile.write(b'far!')\n"
                                       " def log_message(s,*a): pass\n"
                                       "http.server.HTTPServer(('0.0.0.0',80),H).serve_forever()"],
                                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        procs.append(subprocess.Popen(["nsenter", "-t", str(site.pid), "-n", sys.executable, "-c", ECHO],
                                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        time.sleep(1.0)

        def reach(ip="10.98.0.2"):
            try:
                socket.create_connection((ip, 80), timeout=2).close()
                return True
            except OSError:
                return False

        def client_reach(ip="10.98.0.2"):
            return from_client(client.pid, "http", ip) == "far!"

        # the hotspot is up (and its device is connected) before any proxy: everything is direct
        assert client_reach(), "the device behind the hotspot reaches the site directly"
        held = subprocess.Popen(["nsenter", "-t", str(client.pid), "-n", sys.executable, "-c", HOLD],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        assert held.stdout.readline().strip() == "ready"
        proc = subprocess.Popen([xray_bin, "run", "-c", path], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        time.sleep(1.5)
        hs = ["ap0"]
        hotspot.route_localnet(hs)
        rules = xray.redirect_ruleset(redirect, dns, exclude=["10.99.0.5/32", "10.98.0.3/32"], allow_lan=False, hotspots=hs)
        subprocess.run(["nft", "-f", "-"], input=rules.encode(), check=True)
        assert hotspot.flush(["10.42.0.0/24"]) >= 1, "the hotspot's tracked connections are flushed"
        held.stdin.write("go\n")
        held.stdin.flush()
        assert held.stdout.readline().strip() == "reset", "a direct connection of the device does not carry on around the proxy"
        held.wait(10)
        assert fetch("10.99.0.2") == b"site", "the website answers through the redirect"
        assert any(l.startswith("CONNECT 10.99.0.2:80") for l in LOG), ("the proxy carried it", LOG)
        n = len(LOG)
        assert udp_query("192.0.2.53", "example.test") == "10.99.0.2", "DNS over UDP is answered (via TCP)"
        assert any(l.startswith("CONNECT 10.99.0.6:53") for l in LOG[n:]), ("DNS went through the proxy", LOG)
        n = len(LOG)
        assert fetch("10.99.0.5") == b"site" and len(LOG) == n, ("an ignored address goes direct", LOG)

        # the device behind the hotspot: the same, through the forward path
        n = len(LOG)
        assert client_reach(), "the hotspot's device reaches the site through the proxy"
        assert any(l.startswith("CONNECT 10.98.0.2:80") for l in LOG[n:]), ("the proxy carried the hotspot's TCP", LOG[n:])
        n = len(LOG)
        assert from_client(client.pid, "dns", "192.0.2.53") == "10.99.0.2", "the hotspot's DNS is answered (via TCP)"
        assert any(l.startswith("CONNECT 10.99.0.6:53") for l in LOG[n:]), ("the hotspot's DNS went through the proxy", LOG)
        n = len(LOG)
        assert client_reach("10.98.0.3") and len(LOG) == n, ("an ignored address goes direct for the hotspot too", LOG[n:])
        # route_localnet must not open the computer's own loopback to the hotspot's devices: the device sends to
        # 127.0.0.1 over the hotspot (its own loopback address and local route are removed for this)
        nsx(client.pid, "ip", "route", "del", "local", "127.0.0.0/8", "dev", "lo", "table", "local")
        nsx(client.pid, "ip", "addr", "del", "127.0.0.1/8", "dev", "lo")
        nsx(client.pid, "ip", "route", "add", "127.0.0.1/32", "via", "10.42.0.1", "dev", "eth0")
        nsx(client.pid, "sh", "-c", "echo 1 > /proc/sys/net/ipv4/conf/eth0/route_localnet")   # an attacker's stack takes it
        out = from_client(client.pid, "connect", "127.0.0.1", redirect)          # the proxy's own listener
        assert out is None, ("the hotspot's devices cannot reach the computer's loopback", out)
        nsx(client.pid, "ip", "route", "del", "127.0.0.1/32")

        # a hotspot that comes later is picked up by rebuilding the rules (hotspots_changed): without it, no redirect
        subprocess.run(["nft", "-f", "-"], input=xray.redirect_ruleset(redirect, dns, exclude=["10.99.0.5/32"],
                                                                      allow_lan=False).encode(), check=True)
        n = len(LOG)
        assert client_reach() and not any(l.startswith("CONNECT 10.98.0.2:80") for l in LOG[n:]), "not redirected without it"

        # the kill switch: xray dies, the block rules replace the redirect in one step - nothing gets out
        proc.terminate()
        proc.wait(5)
        hotspot.route_localnet([])
        xray.remove_ruleset()
        assert reach() and client_reach(), "the second network works before the block rules"
        subprocess.run(["nft", "-f", "-"], input=xray.blocked_ruleset(allow_lan=False).encode(), check=True)
        assert not reach(), "the kill switch must stop traffic while the proxy is down"
        assert not client_reach(), "the kill switch must stop the hotspot's devices as well"
        subprocess.run(["nft", "-f", "-"], input=xray.blocked_ruleset(exclude=["10.98.0.0/24"], allow_lan=False).encode(),
                       check=True)
        assert reach(), "ignored hosts still go direct"
        assert client_reach(), "ignored hosts still go direct for the hotspot's devices"
        ok = True
        print("NETNS-OK")
    finally:
        for p in procs + [site, client]:
            p.terminate()
        if proc:
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
