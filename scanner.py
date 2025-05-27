import socket, struct, random, time, select, argparse, os

def checksum(data: bytes) -> int:
    if len(data) & 1:
        data += b'\x00'
    s = sum(struct.unpack("!%dH" % (len(data)//2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF

def build_ip_header(src_ip: str, dst_ip: str, ident: int) -> bytes:
    version_ihl = (4 << 4) | 5
    total_len   = 20 + 20
    ttl         = 64
    proto       = socket.IPPROTO_TCP
    ip_hdr = struct.pack("!BBHHHBBH4s4s",
        version_ihl, 0, total_len, ident, 0,
        ttl, proto, 0,
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip)
    )
    chksum_val = checksum(ip_hdr)
    return struct.pack("!BBHHHBBH4s4s",
        version_ihl, 0, total_len, ident, 0,
        ttl, proto, chksum_val,
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip)
    )

def build_tcp_header(src_ip: str, dst_ip: str,
                     src_port: int, dst_port: int,
                     seq: int) -> bytes:
    offset = (5 << 4)
    flags  = 0x02
    win    = socket.htons(5840)
    tcp_wo = struct.pack("!HHLLBBHHH",
        src_port, dst_port, seq, 0,
        offset, flags, win, 0, 0
    )
    pseudo = struct.pack("!4s4sBBH",
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
        0, socket.IPPROTO_TCP,
        len(tcp_wo)
    )
    csum = checksum(pseudo + tcp_wo)
    return struct.pack("!HHLLBBHHH",
        src_port, dst_port, seq, 0,
        offset, flags, win, csum, 0
    )

# ————————————————————————————————
# 4) OS fingerprint
def guess_os(ttl: int, window: int) -> str:
    if ttl >= 128:
        base = "Windows-like"
    elif ttl >= 64:
        base = "Linux/Unix-like"
    else:
        base = "Network-device/Other"
    details = {
        8192:  "Windows XP/2003",
        65535: "Windows Vista/7/8/10/11",
        29200: "Linux 2.4.x",
        5840:  "Linux 2.6.x"
    }.get(window)
    return f"{base}" + (f" – {details}" if details else "")

# ————————————————————————————————
# 5) Single port scan
def scan_port(raw_send, raw_recv, src_ip, dst_ip, port: int, timeout: float):
    src_port = random.randint(1024, 65535)
    ident    = random.randint(0, 0xFFFF)
    seq      = random.randint(0, 0xFFFFFFFF)

    pkt = build_ip_header(src_ip, dst_ip, ident) + \
          build_tcp_header(src_ip, dst_ip, src_port, port, seq)
    raw_send.sendto(pkt, (dst_ip, 0))

    end_time = time.time() + timeout
    while time.time() < end_time:
        ready, _, _ = select.select([raw_recv], [], [], timeout)
        if not ready:
            break
        data, addr = raw_recv.recvfrom(65535)
        if addr[0] != dst_ip:
            continue
        iph = struct.unpack("!BBHHHBBH4s4s", data[:20])
        ttl = iph[5]
        tcph = struct.unpack("!HHLLBBHHH", data[20:40])
        sport, dport, _, _, _, flags, window, _, _ = tcph
        if sport == port and dport == src_port:
            return {"flags": flags, "ttl": ttl, "window": window}
    return None

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Raw-socket SYN scanner + OS fingerprint")
    parser.add_argument("target", help="IP or hostname to scan")
    parser.add_argument("--ports", default="1-1024",
                        help="Ports (e.g. 22,80,443 or 1-1024)")
    parser.add_argument("--timeout", type=float, default=1.0,
                        help="Timeout per port in seconds")
    args = parser.parse_args()

    if os.geteuid() != 0:
        print("Please run as root: sudo", __file__)
        exit(1)

    dst_ip = socket.gethostbyname(args.target)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect((dst_ip, 80))
    src_ip = s.getsockname()[0]
    s.close()

    raw_send = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    raw_recv = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    raw_recv.bind((src_ip, 0))

    if '-' in args.ports:
        start, end = map(int, args.ports.split('-', 1))
        ports = list(range(start, end+1))
    else:
        ports = [int(p) for p in args.ports.split(',')]

    print(f"Scanning {args.target} ({dst_ip}), ports={args.ports}")
    os_printed = False

    for p in ports:
        res = scan_port(raw_send, raw_recv, src_ip, dst_ip, p, args.timeout)
        if not res:
            continue
        if (res['flags'] & 0x12) == 0x12:
            if not os_printed:
                os_info = guess_os(res['ttl'], res['window'])
                print(f"OS fingerprint: {os_info}\n")
                os_printed = True
            try:
                svc = socket.getservbyport(p, 'tcp')
            except OSError:
                svc = 'unknown'
            print(f"{p:5d} ({svc:10s}) Open")

    print("\nScan complete.")
