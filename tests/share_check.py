"""End-to-end check of "share the tunnel" with real nftables and real forwarding, in private network namespaces.

Run as root:   unshare -n python3 tests/share_check.py
(tests/test_vpnman.py runs it when root, unshare, nsenter and nft are available.)

Three network namespaces around this one (the "laptop"): a hotspot client behind ``ap0`` (10.42.0.0/24), the VPN
server behind the tunnel interface ``tun0`` (MTU 1400, a veth standing in for a tunnel) and the plain uplink behind
``wlan0``.  The laptop forwards for the client, with the share rules of vpnman/share.py and the kill switch of netlock:
* the client reaches a site through the tunnel, and the site sees the tunnel's address (masquerade) and a TCP segment
  size that fits the tunnel (clamp: 1360, not the 1460 of an Ethernet client),
* a connection the device opened over the uplink before the VPN came up (its NAT address is the uplink's) cannot
  continue through the tunnel: after the hotspot's tracked connections are flushed it is reset at once,
* with the default route on the uplink (the tunnel "dropped"), the kill switch stops the client reaching the uplink,
  while the client still reaches the tunnel.
"""
import os
import socket
import subprocess
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from vpnman import hotspot, netlock, share  # noqa: E402


def sh(*cmd, check=True):
    return subprocess.run(cmd, check=check, capture_output=True, text=True)


def ns_start():
    p = subprocess.Popen(["unshare", "-n", "sleep", "300"])
    time.sleep(0.4)
    return p


def nsx(p, *cmd, check=True):
    return sh("nsenter", "-t", str(p.pid), "-n", *cmd, check=check)


SERVER = r"""
import http.server, socket
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        mss = self.connection.getsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG)
        body = ("%s %d" % (self.client_address[0], mss)).encode()
        self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a): pass
http.server.HTTPServer(("0.0.0.0", 80), H).serve_forever()
"""
CLIENT = r"""
import socket, sys
try:
    s = socket.create_connection((sys.argv[1], 80), timeout=3)
    s.sendall(b"GET / HTTP/1.0\r\n\r\n")
    d = b""
    while True:
        c = s.recv(4096)
        if not c: break
        d += c
    print(d.split(b"\r\n\r\n", 1)[-1].decode())
except OSError as e:
    print("FAIL", e)
"""


ECHO = r"""
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
HOLD = r"""
import socket, sys
c = socket.create_connection(("203.0.113.1", 81), timeout=4)
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


def held_connection(client, flush):
    """Open a connection from the device, let ``flush`` run, and report what the open connection does."""
    p = subprocess.Popen(["nsenter", "-t", str(client.pid), "-n", sys.executable, "-c", HOLD], stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, text=True)
    assert p.stdout.readline().strip() == "ready"
    flush()
    p.stdin.write("go\n")
    p.stdin.flush()
    out = p.stdout.readline().strip()
    p.wait(10)
    return out


def fetch(client, ip):
    out = nsx(client, "python3", "-c", CLIENT, ip).stdout.strip()
    return None if out.startswith("FAIL") else out.split()


def main():
    sh("ip", "link", "set", "lo", "up")
    client, vpn, up = ns_start(), ns_start(), ns_start()
    procs = []
    try:
        for peer, dev, laptop_dev, laptop_ip, peer_ip, mtu in (
                (client, "eth0", "ap0", "10.42.0.1/24", "10.42.0.2/24", 1500),
                (vpn, "tunp", "tun0", "10.8.0.2/24", "10.8.0.1/24", 1400),
                (up, "upl", "wlan0", "192.168.50.2/24", "192.168.50.1/24", 1500)):
            sh("ip", "link", "add", laptop_dev, "type", "veth", "peer", "name", dev)
            sh("ip", "link", "set", dev, "netns", str(peer.pid))
            sh("ip", "link", "set", laptop_dev, "mtu", str(mtu))
            sh("ip", "addr", "add", laptop_ip, "dev", laptop_dev)
            sh("ip", "link", "set", laptop_dev, "up")
            nsx(peer, "ip", "link", "set", dev, "mtu", "1500")      # only the laptop's end is small (a tunnel's MTU)
            nsx(peer, "ip", "addr", "add", peer_ip, "dev", dev)
            nsx(peer, "ip", "link", "set", dev, "up")
            nsx(peer, "ip", "link", "set", "lo", "up")
        nsx(client, "ip", "route", "add", "default", "via", "10.42.0.1")
        nsx(vpn, "ip", "addr", "add", "198.51.100.1/32", "dev", "lo")
        nsx(vpn, "ip", "route", "add", "10.42.0.0/24", "via", "10.8.0.2")     # a VPN server that routes back
        nsx(up, "ip", "addr", "add", "203.0.113.1/32", "dev", "lo")
        nsx(vpn, "ip", "addr", "add", "203.0.113.1/32", "dev", "lo")          # the same "internet" address on both paths
        # what NetworkManager's shared mode does: NAT the hotspot's network out of whatever interface the route picks
        subprocess.run(["nft", "-f", "-"], text=True, check=True, input=(
            "table ip nm_shared_ap0 {\n  chain post {\n    type nat hook postrouting priority 100;\n"
            "    ip saddr 10.42.0.0/24 ip daddr != 10.42.0.0/24 masquerade\n  }\n}\n"))
        # like the laptop this was reported on: forwarding is off globally and only on for the hotspot and the uplink (what
        # NetworkManager's shared mode does).  The tunnel is created later, so its own setting stays off - and the answers coming back through it
        # are dropped - unless VPNMan turns it on (share.apply)
        sh("sysctl", "-qw", "net.ipv4.ip_forward=0")
        sh("sysctl", "-qw", "net.ipv4.conf.ap0.forwarding=1")
        sh("sysctl", "-qw", "net.ipv4.conf.wlan0.forwarding=1")        # ... and on the uplink it picked
        sh("sysctl", "-qw", "net.ipv4.conf.all.rp_filter=0")
        for peer in (vpn, up):
            procs.append(subprocess.Popen(["nsenter", "-t", str(peer.pid), "-n", "python3", "-c", SERVER],
                                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        time.sleep(1.0)

        for peer in (vpn, up):
            procs.append(subprocess.Popen(["nsenter", "-t", str(peer.pid), "-n", "python3", "-c", ECHO],
                                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        time.sleep(0.5)
        # the hotspot's device is connected and the VPN is off: it uses the uplink
        sh("ip", "route", "add", "default", "via", "192.168.50.1", "dev", "wlan0")
        nsx(up, "ip", "route", "add", "10.42.0.0/24", "via", "192.168.50.2")       # (the uplink's NAT is the other table)

        def vpn_comes_up(do_flush):
            def go():
                sh("ip", "route", "replace", "default", "via", "10.8.0.1", "dev", "tun0")
                err = share.apply(["tun0"])
                assert err == "", err
                if do_flush:
                    hotspot.flush(["10.42.0.0/24"])
            return go

        assert held_connection(client, vpn_comes_up(True)) == "reset", "an open connection is reset after the flush"
        got = fetch(client, "198.51.100.1")
        assert got, "the client reaches the site through the tunnel"
        assert got[0] == "10.8.0.2", ("the site sees the tunnel's address, not the hotspot's", got)
        assert int(got[1]) <= 1360, ("the segment size is clamped to the tunnel's MTU", got)

        # the kill switch with the tunnel route gone (the default route now on the uplink)
        sh("ip", "route", "replace", "default", "via", "192.168.50.1", "dev", "wlan0")
        spec = netlock.Spec(endpoints=["192.0.2.99"], ifaces=["tun0"], allow_lan=False, share=True)
        subprocess.run(["nft", "-f", "-"], input=netlock.nft_ruleset(spec), text=True, check=True)
        assert fetch(client, "203.0.113.1") is None, "the kill switch stops forwarded traffic leaving by the uplink"
        sh("ip", "route", "replace", "default", "via", "10.8.0.1", "dev", "tun0")
        assert fetch(client, "198.51.100.1"), "forwarded traffic still goes through the tunnel under the kill switch"
        share.remove()
        assert not share.active()
        print("SHARE-OK")
    finally:
        for p in procs + [client, vpn, up]:
            p.terminate()


if __name__ == "__main__":
    try:
        main()
    except AssertionError as e:
        print("FAILED:", e)
        sys.exit(1)
