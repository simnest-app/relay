#!/usr/bin/env python3
"""Asks a relay whether it is there, from wherever this is run: one STUN binding request over UDP, and a TCP connect.

    tools/probe.py <host> [port]

Run it from a machine OUTSIDE the relay's own network to see whether the firewall and the router let calls reach it.
It needs no key and learns nothing but that the relay answers. Exit code 0 when both UDP and TCP answer.
"""
import os, socket, struct, sys, time

host = sys.argv[1] if len(sys.argv) > 1 else sys.exit(__doc__)
port = int(sys.argv[2]) if len(sys.argv) > 2 else 3478
ok = True

try:
    family, _, _, _, addr = socket.getaddrinfo(host, port, type=socket.SOCK_DGRAM)[0]
    s = socket.socket(family, socket.SOCK_DGRAM)
    s.settimeout(3)
    txid = os.urandom(12)
    started = time.time()
    s.sendto(struct.pack(">HHI", 0x0001, 0, 0x2112A442) + txid, addr)
    data, _ = s.recvfrom(2048)
    good = len(data) >= 20 and struct.unpack(">H", data[:2])[0] == 0x0101 and data[8:20] == txid
    print(f"UDP {port}: " + (f"answers in {1000 * (time.time() - started):.0f} ms" if good else "answered, but not as a relay"))
    ok &= good
except Exception as e:
    print(f"UDP {port}: no answer ({e})")
    ok = False

try:
    started = time.time()
    socket.create_connection((host, port), timeout=3).close()
    print(f"TCP {port}: connects in {1000 * (time.time() - started):.0f} ms")
except Exception as e:
    print(f"TCP {port}: cannot connect ({e})")
    ok = False

sys.exit(0 if ok else 1)
