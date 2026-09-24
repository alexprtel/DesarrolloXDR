"""Sensor de red: conexiones nuevas, puertos a la escucha, métricas de tráfico
e interfaces en modo promiscuo."""
from __future__ import annotations

import os
import socket
import time

import psutil

from xdr.collectors.base import Collector
from xdr.events import Event
from xdr.utils import IS_LINUX, is_private_ip

PROTO = {(socket.AF_INET, socket.SOCK_STREAM): "tcp", (socket.AF_INET6, socket.SOCK_STREAM): "tcp6",
         (socket.AF_INET, socket.SOCK_DGRAM): "udp", (socket.AF_INET6, socket.SOCK_DGRAM): "udp6"}


class NetworkCollector(Collector):
    name = "network"
    default_interval = 3.0

    def setup(self) -> None:
        self.known: set[tuple] = set()
        self.listening: set[tuple] = set()
        self.first = True
        self.names: dict[int, tuple[str, str]] = {}
        self.last_io = psutil.net_io_counters()
        self.last_io_ts = time.time()
        self.promisc: set[str] = set()

    def _proc(self, pid: int | None) -> tuple[str, str]:
        if not pid:
            return "", ""
        if pid in self.names:
            return self.names[pid]
        try:
            p = psutil.Process(pid)
            val = (p.name(), p.exe())
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            val = ("", "")
        self.names[pid] = val
        return val

    def collect(self) -> list[Event]:
        events: list[Event] = []
        try:
            conns = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, OSError):
            conns = []
        if len(self.names) > 5000:
            self.names.clear()
        listen_now: set[tuple] = set()
        conns_now: set[tuple] = set()
        listen_ports: set[int] = set()
        for c in conns:
            proto = PROTO.get((c.family, c.type), "other")
            if not c.laddr:
                continue
            is_listen = c.status == psutil.CONN_LISTEN or (proto.startswith("udp") and not c.raddr)
            if is_listen:
                listen_ports.add(c.laddr.port)
                listen_now.add((proto, c.laddr.ip, c.laddr.port, c.pid))
        for c in conns:
            proto = PROTO.get((c.family, c.type), "other")
            if not c.laddr or not c.raddr:
                continue
            if c.status not in (psutil.CONN_ESTABLISHED, psutil.CONN_SYN_SENT, psutil.CONN_NONE,
                                psutil.CONN_SYN_RECV):
                continue
            conns_now.add((proto, c.laddr.ip, c.laddr.port, c.raddr.ip, c.raddr.port, c.pid,
                           c.laddr.port in listen_ports, c.status))

        for key in listen_now - self.listening:
            proto, ip, port, pid = key
            name, exe = self._proc(pid)
            events.append(self.event("network", "listen", proto=proto, local_ip=ip, local_port=port,
                                     pid=pid, process=name, exe=exe,
                                     exposed=ip not in ("127.0.0.1", "::1", "localhost"),
                                     initial=self.first))
        for key in self.listening - listen_now:
            proto, ip, port, pid = key
            events.append(self.event("network", "listen_closed", proto=proto, local_ip=ip,
                                     local_port=port, pid=pid))
        for key in conns_now - self.known:
            proto, lip, lport, rip, rport, pid, inbound, status = key
            name, exe = self._proc(pid)
            events.append(self.event(
                "network", "connection", proto=proto, local_ip=lip, local_port=lport,
                remote_ip=rip, remote_port=rport, pid=pid, process=name, exe=exe,
                direction="inbound" if inbound else "outbound", status=status,
                remote_private=is_private_ip(rip), initial=self.first))
        self.listening = listen_now
        self.known = conns_now

        # Métricas de tráfico (no se almacenan; alimentan la detección de exfiltración)
        io = psutil.net_io_counters()
        now = time.time()
        dt = max(0.001, now - self.last_io_ts)
        events.append(self.event("metric", "net_io",
                                 bytes_sent=io.bytes_sent - self.last_io.bytes_sent,
                                 bytes_recv=io.bytes_recv - self.last_io.bytes_recv, seconds=dt))
        self.last_io, self.last_io_ts = io, now

        if IS_LINUX:
            events.extend(self._promiscuous())
        self.first = False
        return events

    def _promiscuous(self) -> list[Event]:
        events = []
        now: set[str] = set()
        base = "/sys/class/net"
        try:
            ifaces = os.listdir(base)
        except OSError:
            return events
        for iface in ifaces:
            try:
                with open(f"{base}/{iface}/flags") as fh:
                    flags = int(fh.read().strip(), 16)
            except (OSError, ValueError):
                continue
            if flags & 0x100:
                now.add(iface)
        for iface in now - self.promisc:
            events.append(self.event("network", "promiscuous", interface=iface))
        self.promisc = now
        return events
