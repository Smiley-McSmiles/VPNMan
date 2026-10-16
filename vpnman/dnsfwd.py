"""A small DNS forwarder for the programs that skip the VPN.

Programs that read /etc/resolv.conf and find a resolver on the computer itself (systemd-resolved's stub 127.0.0.53,
dnsmasq, unbound...) talk to it over loopback, which the app bypass leaves alone - and that resolver asks the VPN's DNS
inside the tunnel.  When the user picks a DNS server for the bypassed programs, their queries to loopback are redirected
here instead (nftables DNAT to 127.0.0.1:port, see split.ruleset) and forwarded to the chosen server over the normal
connection: the upstream sockets carry the bypass mark, so the routing rule sends them around the tunnel.

UDP and TCP, one short thread per query; answers are passed through untouched.
"""

import socket
import struct
import threading

TIMEOUT = 5.0


class DnsForwarder:
    def __init__(self, upstream, mark, port=0):
        self.upstream, self.mark = upstream, int(mark)
        self.port = port
        self._stop = threading.Event()
        self._socks = []
        self._threads = []

    # ---- lifecycle
    def start(self):
        for _ in range(20):                        # UDP and TCP on the same free port
            udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                udp.bind(("127.0.0.1", self.port))
                tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                tcp.bind(("127.0.0.1", udp.getsockname()[1]))
                tcp.listen(32)
                break
            except OSError:
                udp.close()
                tcp.close()
                if self.port:
                    raise
        else:
            raise OSError("no free port for the DNS forwarder")
        self.port = udp.getsockname()[1]
        udp.settimeout(0.5)
        tcp.settimeout(0.5)
        self._socks = [udp, tcp]
        for target, args in ((self._udp_loop, (udp,)), (self._tcp_loop, (tcp,))):
            t = threading.Thread(target=target, args=args, daemon=True, name="dns-forwarder")
            t.start()
            self._threads.append(t)
        return self.port

    def stop(self):
        self._stop.set()
        for s in self._socks:
            try:
                s.close()
            except OSError:
                pass
        for t in self._threads:
            t.join(1)
        self._socks, self._threads = [], []

    # ---- upstream
    def _upstream_socket(self, kind):
        s = socket.socket(socket.AF_INET, kind)
        try:
            s.setsockopt(socket.SOL_SOCKET, getattr(socket, "SO_MARK", 36), self.mark)
        except OSError:
            pass                                   # not root (tests): unmarked, still works on a plain route
        s.settimeout(TIMEOUT)
        return s

    # ---- UDP
    def _udp_loop(self, sock):
        while not self._stop.is_set():
            try:
                data, peer = sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(target=self._udp_query, args=(sock, data, peer), daemon=True).start()

    def _udp_query(self, sock, data, peer):
        up = self._upstream_socket(socket.SOCK_DGRAM)
        try:
            up.sendto(data, (self.upstream, 53))
            while True:
                reply, _ = up.recvfrom(65535)
                if reply[:2] == data[:2]:          # the answer to this query (ids match)
                    break
            sock.sendto(reply, peer)
        except OSError:
            pass
        finally:
            up.close()

    # ---- TCP
    def _tcp_loop(self, sock):
        while not self._stop.is_set():
            try:
                conn, _ = sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(target=self._tcp_session, args=(conn,), daemon=True).start()

    @staticmethod
    def _read(conn, n):
        buf = b""
        while len(buf) < n:
            chunk = conn.recv(n - len(buf))
            if not chunk:
                raise OSError("closed")
            buf += chunk
        return buf

    def _tcp_session(self, conn):
        conn.settimeout(TIMEOUT)
        up = None
        try:
            while True:
                size = struct.unpack("!H", self._read(conn, 2))[0]
                query = self._read(conn, size)
                if up is None:
                    up = self._upstream_socket(socket.SOCK_STREAM)
                    up.connect((self.upstream, 53))
                up.sendall(struct.pack("!H", len(query)) + query)
                rsize = struct.unpack("!H", self._read(up, 2))[0]
                conn.sendall(struct.pack("!H", rsize) + self._read(up, rsize))
        except OSError:
            pass
        finally:
            conn.close()
            if up:
                up.close()
