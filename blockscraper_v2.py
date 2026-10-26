#!/usr/bin/env python3
"""
BlockScraper - IP block WHOIS collector, simple local web interface.

Author: Jari van der Werf

Run:   python3 ip_whois_tool.py
Open:  http://localhost:8765

Enter IPv4 / IPv6 blocks (CIDR like 192.0.2.0/28, or a range like 192.0.2.1-192.0.2.20),
one per line. Steps:
  1. Every address gets a reverse-DNS (PTR) check, in parallel. No PTR = "not in use" = skipped.
  2. In-use addresses are looked up in the RIPE NCC WHOIS (one lookup per registered block).
  3. The domain of each PTR hostname is looked up, one lookup per unique domain:
     .nl  -> SIDN (whois.domain-registry.nl)
     .com and other TLDs -> the registry's whois (found via IANA), plus the
     registrar's own whois when the registry refers to one.
  4. Optional, both off by default: tick "InternetDB" on the page to look up every
     in-use address in InternetDB (internetdb.shodan.io), Shodan's free, keyless
     lookup of its own existing data (open ports, hostnames, CPEs, known CVEs) - no
     account needed. Enter a paid Shodan API key (Freelancer plan or higher) to add
     the fuller /shodan/host record (banners, organisation, ISP, TLS certs) too.
     Both are passive - nothing is ever scanned or probed - and go to a separate
     file (shodan_report.txt).
  5. Optional discovery (runs right after step 1, so new addresses get steps 2-4 too):
     - "Certificate transparency": every domain found in reverse DNS is looked up on
       crt.sh; the hostnames from those certificates are resolved (A/AAAA) through
       public resolvers.
     - DNSDumpster (API key): the A/MX/NS records it has on file per domain.
     Any resulting address that lies INSIDE the blocks you entered is added to the
     in-use list, even without a PTR record. Addresses outside your blocks are ignored.
     Still passive: crt.sh and DNSDumpster are third-party databases, and forward DNS
     goes through public resolvers - no host in your blocks is ever contacted.
  6. Optional, off by default: tick "nmap -sL" to cross-check reverse DNS with nmap's
     list scan over the enumerated addresses. -sL sends no packets to the targets - it
     only resolves and lists - so it stays passive. Needs nmap installed; written to a
     separate file (nmap_report.txt).
  7. Optional ACTIVE step, off by default: tick the liveness probe to open a direct
     HTTP(S) connection to each discovered hostname and record which ones serve a site.
     This is the ONE option that contacts the targets: the requests reach them and show
     up in their logs with this machine's IP. Only use it on hosts you are authorised to
     test. Results go to their own file (live_hosts.txt) and are never mixed into the
     other reports.
Everything else ends up in one text file (ip_whois_report.txt), plus a combined_report.txt
that merges every passive source per address.
Uses only the Python standard library (nmap, if enabled, is called as an external command).
"""
import ipaddress
import json
import bisect
import os
import random
import re
import shutil
import socket
import struct
import subprocess
import tempfile
import textwrap
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from datetime import datetime

PORT = 8765
RIPE_HOST = "whois.ripe.net"
SIDN_HOST = "whois.domain-registry.nl"
PTR_WORKERS = 128     # parallel reverse-DNS lookups
SIDN_WORKERS = 3      # keep low: SIDN rate-limits
DELAY = 0.3           # seconds between WHOIS queries per worker
NMAP_BIN = "nmap"
NMAP_BASE_TIMEOUT = 30        # seconds, fixed overhead
NMAP_PER_ADDR_TIMEOUT = 0.05  # seconds, added per address requested
NMAP_MAX_TIMEOUT = 1800

state = {"running": False, "log": [], "done": 0, "total": 0, "used": 0,
         "phase": "Idle", "result": "", "shodan_result": "", "dnsdumpster_result": "",
         "combined_result": "", "probe_result": "", "nmap_result": "", "hostmap_result": ""}
lock = threading.Lock()


def log(msg):
    with lock:
        state["log"].append(msg)
        state["log"] = state["log"][-200:]


def set_state(**kw):
    with lock:
        state.update(kw)


def parse_blocks(text, max_addrs):
    """Returns (ips, walk_nets, errors).
    ips       - addresses of small blocks, checked one by one
    walk_nets - blocks too big to enumerate; explored through the reverse-DNS tree instead"""
    ips, walk, errors = [], [], []
    for raw in text.replace(",", "\n").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            if "-" in line:
                a, b = [x.strip() for x in line.split("-", 1)]
                start, end = ipaddress.ip_address(a), ipaddress.ip_address(b)
                if start.version != end.version or int(end) < int(start):
                    raise ValueError("invalid range")
                count = int(end) - int(start) + 1
                if count > max_addrs:
                    walk.extend(ipaddress.summarize_address_range(start, end))
                    continue
                cls = ipaddress.IPv4Address if start.version == 4 else ipaddress.IPv6Address
                ips.extend(cls(int(start) + i) for i in range(count))
            else:
                net = ipaddress.ip_network(line, strict=False)
                if net.num_addresses > max_addrs:
                    walk.append(net)
                else:
                    ips.extend(net)
        except ValueError as e:
            errors.append(f"{line}: {e}")
    return list(dict.fromkeys(ips)), list(dict.fromkeys(walk)), errors


def ptr(ip):
    try:
        return socket.gethostbyaddr(str(ip))[0]
    except (socket.herror, socket.gaierror, socket.timeout, OSError):
        return None


# ------------------------------------------------ reverse-DNS tree walk (for huge blocks)
# A /48 has 1.2e24 addresses, so they can't be tried one by one. Instead we walk the
# reverse-DNS tree (ip6.arpa / in-addr.arpa) one nibble (IPv6) or octet (IPv4) at a time.
# Per RFC 8020, NXDOMAIN for a name means nothing exists below it, so empty branches are
# cut off immediately and only branches that contain PTR records are followed.
DNS_SERVERS = ["1.1.1.1", "9.9.9.9", "8.8.8.8"]
DNS_WORKERS = 48
try:   # on Linux/macOS also use the system's own IPv4 resolvers as a last resort
    with open("/etc/resolv.conf") as _f:
        for _l in _f:
            _p = _l.split()
            if len(_p) == 2 and _p[0] == "nameserver" and _p[1].count(".") == 3 \
                    and _p[1] not in DNS_SERVERS:
                DNS_SERVERS.append(_p[1])
except OSError:
    pass


def _read_name(buf, off):
    labels, end, jumped = [], 0, False
    for _ in range(128):
        ln = buf[off]
        if ln == 0:
            off += 1
            break
        if ln & 0xC0 == 0xC0:
            if not jumped:
                end, jumped = off + 2, True
            off = ((ln & 0x3F) << 8) | buf[off + 1]
            continue
        labels.append(buf[off + 1:off + 1 + ln].decode("ascii", "replace"))
        off += 1 + ln
    return ".".join(labels), (end if jumped else off)


def dns_probe(name):
    """PTR query. Returns (rcode, [ptr hostnames]) or None if every attempt failed."""
    return dns_query(name, 12)


def dns_query(name, qtype):
    """Query a public resolver. qtype 12 = PTR, 1 = A, 28 = AAAA.
    Returns (rcode, [answers]) or None if every attempt failed. Answers are hostnames
    for PTR and address strings for A/AAAA (CNAME chains are followed by the resolver)."""
    try:
        labels = [l.encode("idna") for l in name.rstrip(".").split(".")]
    except (UnicodeError, ValueError):
        return None
    if not labels or any(not 0 < len(l) < 64 for l in labels):
        return None
    qname = b"".join(bytes([len(l)]) + l for l in labels) + b"\x00"
    start = random.randrange(len(DNS_SERVERS))
    for attempt in range(min(4, len(DNS_SERVERS))):
        server = DNS_SERVERS[(start + attempt) % len(DNS_SERVERS)]
        qid = random.randrange(65536)
        pkt = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0) + qname + struct.pack(">HH", qtype, 1)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(3)
        try:
            s.sendto(pkt, (server, 53))
            data, _ = s.recvfrom(4096)
        except OSError:
            continue
        finally:
            s.close()
        try:
            rid, flags, qd, an, _, _ = struct.unpack(">HHHHHH", data[:12])
            if rid != qid:
                continue
            rcode = flags & 0xF
            if rcode not in (0, 3):          # SERVFAIL / REFUSED etc: try another server
                continue
            off, answers = 12, []
            for _ in range(qd):
                _, off = _read_name(data, off)
                off += 4
            for _ in range(an):
                _, off = _read_name(data, off)
                rtype, _, _, rdlen = struct.unpack(">HHIH", data[off:off + 10])
                off += 10
                if rtype == qtype == 12:
                    answers.append(_read_name(data, off)[0])
                elif rtype == qtype == 1 and rdlen == 4:
                    answers.append(socket.inet_ntop(socket.AF_INET, data[off:off + 4]))
                elif rtype == qtype == 28 and rdlen == 16:
                    answers.append(socket.inet_ntop(socket.AF_INET6, data[off:off + 16]))
                off += rdlen
            return rcode, answers
        except (IndexError, struct.error, ValueError):
            continue
    return None


def rev_name(net):
    if net.version == 6:
        nibbles = net.network_address.exploded.replace(":", "")[: net.prefixlen // 4]
        return ".".join(reversed(nibbles)) + ".ip6.arpa"
    octets = str(net.network_address).split(".")[: net.prefixlen // 8]
    return ".".join(reversed(octets)) + ".in-addr.arpa"


def children(net):
    step, bits = (4, 128) if net.version == 6 else (8, 32)
    target = min(bits, (net.prefixlen // step + 1) * step)
    return list(net.subnets(new_prefix=target))


def ripe_subblocks(net):
    """IPv6 only: top-level more-specific inet6num objects that RIPE has registered under `net`
    (customer assignments etc.). Returns a list of non-overlapping networks."""
    txt = whois_query(RIPE_HOST, f"-M -r -T inet6num {net}")
    err = next((l.strip() for l in txt.splitlines() if "ERROR" in l.upper()), "")
    if err:
        log(f"RIPE answered with: {err}")
    elif "inet6num:" not in txt:
        log(f"RIPE returned no inet6num objects ({len(txt)} bytes of reply)")
    subs = set()
    for line in txt.splitlines():
        if line.startswith("inet6num:"):
            try:
                n = ipaddress.ip_network(line.split(":", 1)[1].strip(), strict=False)
            except ValueError:
                continue
            if n != net and n.version == net.version and n.subnet_of(net):
                subs.add(n)
    keep, last_end = [], -1
    for n in sorted(subs, key=lambda n: (int(n.network_address), n.prefixlen)):
        if int(n.network_address) > last_end:
            keep.append(n)
            last_end = int(n.broadcast_address)
    return keep


def make_covered(seeds):
    """Returns f(net) -> True if net lies completely inside one of the (non-overlapping) seeds."""
    items = sorted((int(s.network_address), int(s.broadcast_address)) for s in seeds)
    starts, ends = [a for a, _ in items], [b for _, b in items]

    def covered(k):
        i = bisect.bisect_right(starts, int(k.network_address)) - 1
        return i >= 0 and ends[i] >= int(k.broadcast_address)
    return covered


def walk_reverse(root, max_queries, ex, seeds=()):
    """Find every address under `root` that has a PTR record (depth-first, so results show up
    early even when the query budget is too small for the whole block).
    `seeds` are sub-blocks to scan first and then leave out of the main walk.
    Returns (found{ip: hostname}, queries_used, failed_queries, truncated)."""
    bits = 128 if root.version == 6 else 32
    covered = make_covered(seeds) if seeds else (lambda k: False)
    found, used, failed, truncated, next_log = {}, 0, 0, False, 2000
    stack = [root] + list(seeds)                    # popped from the end: seeds first
    while stack:
        parents = [stack.pop() for _ in range(min(len(stack), 8))]
        # main walk skips sub-blocks that are scanned separately as seeds
        kids = [k for n in parents for k in children(n)
                if covered(n) or not covered(k)]
        if used + len(kids) > max_queries:
            kids = kids[:max(0, max_queries - used)]
            truncated = True
        if not kids:
            break
        results = list(ex.map(lambda n: (n, dns_probe(rev_name(n))), kids))
        if used == 0:                                  # first probes: show what DNS says
            tally = {}
            for _, res in results:
                label = "no answer" if res is None else ("exists" if res[0] == 0 else "NXDOMAIN")
                tally[label] = tally.get(label, 0) + 1
            log(f"{root}: first {len(results)} probes (e.g. {rev_name(results[0][0])}) -> {tally}")
        used += len(kids)
        for n, res in results:
            if res is None:
                failed += 1
                continue
            rcode, ptrs = res
            if rcode != 0:
                continue                          # NXDOMAIN: nothing below this prefix
            if n.prefixlen == bits:
                if ptrs:
                    found[n.network_address] = ptrs[0].rstrip(".")
            else:
                stack.append(n)
        set_state(done=used)
        if used >= next_log or truncated:
            next_log = used + 2000
            log(f"{root}: {used} queries, {len(found)} PTR records, {len(stack)} branches left")
        if truncated:
            break
    log(f"{root}: done - {used} queries, {len(found)} PTR records, {failed} failed")
    return found, used, failed, truncated


def whois_query(host, query):
    with socket.create_connection((host, 43), timeout=15) as s:
        s.sendall(f"{query}\r\n".encode())
        chunks = []
        while True:
            d = s.recv(4096)
            if not d:
                break
            chunks.append(d)
    return b"".join(chunks).decode("utf-8", "replace")


def object_range(text):
    for line in text.splitlines():
        if line.startswith("inetnum:"):
            a, _, b = line.split(":", 1)[1].partition("-")
            try:
                return ipaddress.ip_address(a.strip()), ipaddress.ip_address(b.strip())
            except ValueError:
                return None
        if line.startswith("inet6num:"):
            try:
                n = ipaddress.ip_network(line.split(":", 1)[1].strip(), strict=False)
                return n[0], n[-1]
            except ValueError:
                return None
    return None


SECOND_LEVEL = {"co", "com", "org", "net", "gov", "ac", "edu", "ltd", "plc", "me"}


def nl_domain(hostname):
    """Registrable domain of a hostname (any TLD), or None.
    (name kept for compatibility; handles co.uk / com.au style endings)"""
    if not hostname:
        return None
    labels = hostname.rstrip(".").lower().split(".")
    if len(labels) < 2 or not all(labels):
        return None
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in SECOND_LEVEL:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])
    return None


# ------------------------------------------------------------------ report formatting
FIELD_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9 _.\-/()]*?):\s*(.*)$")
WIDTH = 96
BAR = "=" * 78
THIN = "-" * 78


def parse_whois(text):
    """Split raw whois text into objects; each object is a list of [key, value]."""
    objs, cur = [], []
    for line in text.splitlines():
        if line.startswith(("%", "#", ">>>")):
            continue
        if not line.strip():
            if cur:
                objs.append(cur)
                cur = []
            continue
        if line[0] in " \t" and cur:                      # continuation / list item
            v = line.strip()
            cur[-1][1] = f"{cur[-1][1]}, {v}" if cur[-1][1] else v
            continue
        m = FIELD_RE.match(line)
        if m and not m.group(2).startswith("//"):
            cur.append([m.group(1).strip(), m.group(2).strip()])
        else:
            cur.append(["", line.strip()])
    if cur:
        objs.append(cur)
    return objs


def render_whois(text, indent="    "):
    """Aligned, wrapped, comment-free version of raw whois text."""
    objs = parse_whois(text)
    if not any(k for o in objs for k, _ in o):
        return "\n".join(indent + l for l in text.strip().splitlines())
    lines = []
    for n, obj in enumerate(objs):
        if n:
            lines.append("")
        width = min(max((len(k) for k, _ in obj), default=0) + 1, 24)
        for k, v in obj:
            prefix = indent + ((k + ":").ljust(width) + " " if k else "")
            body = textwrap.wrap(v, max(30, WIDTH - len(prefix))) or [""]
            lines.append(prefix + body[0])
            lines.extend(" " * len(prefix) + b for b in body[1:])
    return "\n".join(lines)


def first_field(text, *keys):
    for obj in parse_whois(text):
        for k, v in obj:
            if k.lower() in keys and v:
                return v
    return ""


def trunc(s, n):
    s = s or ""
    return s if len(s) <= n else s[:n - 1] + "…"


def table(headers, rows):
    widths = [max(len(h), *(len(r[i]) for r in rows)) if rows else len(h)
              for i, h in enumerate(headers)]
    fmt = "  ".join("{:<%d}" % w for w in widths)
    out = ["  " + fmt.format(*headers).rstrip(),
           "  " + "  ".join("-" * w for w in widths)]
    out += ["  " + fmt.format(*r).rstrip() for r in rows]
    return out


def section(title):
    return ["", BAR, f"  {title}", BAR, ""]


def host_label(ip, ptrs, discovered):
    """PTR hostname, or for addresses found by discovery without a PTR, '[hostname]'."""
    if ptrs.get(ip):
        return ptrs[ip]
    found = discovered.get(ip) or []
    return f"[{found[0][1]}]" if found else None


def nmap_available():
    return shutil.which(NMAP_BIN) is not None


def run_nmap_sl(ips, notes):
    """Reverse-DNS a list of addresses with nmap's -sL (list scan).

    -sL never sends a packet to the targets - it only does reverse-DNS (via
    the system resolver) and lists what it would have scanned. Run only
    against the addresses small enough to have been enumerated one-by-one;
    oversized blocks are handled by this tool's own DNS tree walk instead,
    since nmap has no equivalent and nothing sane to do with e.g. a /48.
    Returns {"hosts": {ip_str: hostname|None}, "error": str|None}."""
    if not ips:
        return {"hosts": {}, "error": None}
    if not nmap_available():
        notes.append("nmap -sL skipped: the 'nmap' binary was not found on this machine. "
                     "Install nmap (e.g. 'apt install nmap' / 'brew install nmap') to enable it.")
        return {"hosts": {}, "error": "nmap not installed"}
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
            tmp_path = tf.name
            for ip in ips:
                tf.write(str(ip) + "\n")
        timeout = min(NMAP_MAX_TIMEOUT, NMAP_BASE_TIMEOUT + NMAP_PER_ADDR_TIMEOUT * len(ips))
        proc = subprocess.run(
            [NMAP_BIN, "-sL", "-iL", tmp_path, "-oG", "-"],
            capture_output=True, text=True, timeout=timeout)
        if proc.returncode != 0:
            err = (proc.stderr or proc.stdout or "unknown error").strip().splitlines()
            notes.append(f"nmap -sL exited with an error: {err[-1] if err else 'unknown error'}")
            return {"hosts": {}, "error": "nmap exited with an error"}
        hosts = {}
        for line in proc.stdout.splitlines():
            m = re.match(r"^Host:\s+(\S+)\s+\(([^)]*)\)", line)
            if m:
                hosts[m.group(1)] = m.group(2) or None
        return {"hosts": hosts, "error": None}
    except subprocess.TimeoutExpired:
        notes.append(f"nmap -sL timed out after {timeout:.0f}s and was skipped for this run.")
        return {"hosts": {}, "error": "timed out"}
    except OSError as e:
        notes.append(f"nmap -sL failed to run: {e}")
        return {"hosts": {}, "error": str(e)}
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


def build_nmap_report(ips, walk_nets, nmap_out):
    out = [BAR, "  NMAP -sL (LIST SCAN) REPORT", BAR,
           f"  Generated : {datetime.now():%Y-%m-%d %H:%M:%S}", "",
           "  What this is: nmap's -sL list scan, run against every address small enough",
           "  to have been enumerated one-by-one in this run. Like the rest of this tool,",
           "  it never sends a packet to any of these addresses - it only does reverse-DNS",
           "  (via nmap's own resolver) and lists the result. It's a second opinion",
           "  alongside this tool's own PTR check.", ""]
    if walk_nets:
        out.append(f"  {len(walk_nets)} block(s) were too large to enumerate and were instead")
        out.append("  walked via this tool's own reverse-DNS tree walk (see the main report) -")
        out.append("  nmap has no equivalent to that and isn't run against them:")
        for net in walk_nets:
            out.append(f"    - {net}")
        out.append("")
    hosts = nmap_out.get("hosts", {})
    if nmap_out.get("error"):
        out.append(f"  nmap -sL did not complete: {nmap_out['error']}. See the log for detail.")
    elif not ips:
        out.append("  No addresses were small enough to enumerate - nothing to list.")
    else:
        rows, resolved = [], 0
        for ip in ips:
            host = hosts.get(str(ip))
            if host:
                resolved += 1
            rows.append([str(ip), host or "(none)"])
        out.append(f"  {resolved} of {len(ips)} address(es) resolved a hostname via nmap -sL")
        out.append("")
        out += table(["ADDRESS", "REVERSE DNS (nmap)"], rows)
    out += ["", "  End of report."]
    return "\n".join(out) + "\n"


def build_report(checked, notes, block_info, in_use, ptrs, ripe_text, domains, sidn,
                 discovered=None):
    discovered = discovered or {}
    ip_dom = {ip: d for d, dips in domains.items() for ip in dips}
    # group addresses by registered network
    nets = {}
    for ip in in_use:
        kind, val = ripe_text[ip]
        key = str(ip) if kind == "full" else val
        g = nets.setdefault(key, {"text": "", "ips": []})
        if kind == "full":
            g["text"] = val
        g["ips"].append(str(ip))
    net_no = {k: i for i, k in enumerate(nets, 1)}
    dom_no = {d: i for i, d in enumerate(domains, 1)}

    out = [BAR, "  IP WHOIS REPORT", BAR,
           f"  Generated   : {datetime.now():%Y-%m-%d %H:%M:%S}",
           f"  In use      : {len(in_use)}  (have a reverse-DNS record"
           + (f", or {len(discovered)} found via CT/DNSDumpster)" if discovered else ")"),
           f"  Networks    : {len(nets)}  (RIPE NCC whois)",
           f"  Domains     : {len(domains)}  (SIDN for .nl, registry whois for others)"]
    for i, c in enumerate(checked):
        out.append(("  Checked     : " if i == 0 else "                ") + c)
    for n in notes:
        out.append(textwrap.fill("WARNING: " + n, WIDTH, initial_indent="  ", subsequent_indent="           "))
    out += ["", "  Sections:  1. Overview   2. Networks   3. Domains"
            + ("   4. Discovered" if discovered else "")
            + ("   (+ block details)" if block_info else "")]

    # block details (big blocks walked via reverse DNS)
    if block_info:
        out += section("BLOCK DETAILS - RIPE whois of the blocks you entered")
        for blk, btxt in block_info:
            out.append(f"  {blk}")
            out.append("  " + "." * 60)
            out.append(render_whois(btxt))
            out += ["", THIN, ""]

    # 1. overview
    out += section("1. OVERVIEW - one line per address in use")
    rows = []
    for ip in in_use:
        kind, val = ripe_text[ip]
        key = str(ip) if kind == "full" else val
        txt = nets[key]["text"]
        host = host_label(ip, ptrs, discovered)
        d = ip_dom.get(ip)
        rows.append([str(ip), trunc(host or "-", 38),
                     f"#{net_no[key]} {trunc(first_field(txt, 'netname') or '-', 18)}",
                     trunc(first_field(txt, "org-name") or first_field(txt, "descr") or "-", 28),
                     f"#{dom_no[d]} {d}" if d else "-"])
    out += table(["IP", "REVERSE DNS", "NETWORK", "ORGANISATION", "DOMAIN"], rows)
    if discovered:
        out += ["", "  [hostname] = no reverse-DNS record; name comes from CT logs or DNSDumpster."]

    # 2. networks
    out += section("2. NETWORKS - RIPE NCC whois (one entry per registered block)")
    for key, g in nets.items():
        txt = g["text"]
        out.append(f"  [{net_no[key]}] {first_field(txt, 'netname') or 'network'}  "
                   f"({first_field(txt, 'inetnum', 'inet6num') or key})")
        out.append("  Addresses in use: " + ", ".join(g["ips"]))
        out.append("  " + "." * 60)
        out.append(render_whois(txt))
        out += ["", THIN, ""]

    # 3. domains
    out += section("3. DOMAINS - SIDN for .nl, registry/registrar whois for other TLDs")
    if not domains:
        out.append("  No domains found.")
    for d, dips in domains.items():
        src, dtxt = sidn.get(d, ("none", "(no result)"))
        out.append(f"  [{dom_no[d]}] {d}")
        out.append(f"  Source  : {src}")
        out.append("  Seen on: " + ", ".join(f"{ip} ({host_label(ip, ptrs, discovered)})"
                                             for ip in dips))
        out.append("  " + "." * 60)
        out.append(render_whois(dtxt))
        out += ["", THIN, ""]

    # 4. discovered
    if discovered:
        out += section("4. DISCOVERED - in-scope addresses found via CT logs / DNSDumpster")
        out.append("  These were added on top of the reverse-DNS results because a hostname from")
        out.append("  certificate transparency or DNSDumpster resolves to them.")
        out.append("")
        rows = []
        for ip in sorted(discovered, key=lambda i: (i.version, int(i))):
            srcs = discovered[ip]
            rows.append([str(ip), "yes" if ptrs.get(ip) else "no",
                         trunc(", ".join(sorted({s for s, _ in srcs})), 20),
                         trunc(", ".join(sorted({h for _, h in srcs})), 60)])
        out += table(["IP", "PTR", "FOUND VIA", "HOSTNAMES"], rows)
    out.append("  End of report.")
    return "\n".join(out) + "\n"


def build_shodan_report(in_use, ptrs, internetdb, shodan):
    """Separate report: everything InternetDB (free, keyless) and, if a paid key was given,
    the full Shodan host API already had on record for the in-use addresses.
    Passive only - this never triggers a new scan or probe of anything."""
    have_db = sum(1 for v in internetdb.values() if v.get("text"))
    have_sh = sum(1 for v in shodan.values() if v.get("text"))
    out = [BAR, "  SHODAN / INTERNETDB REPORT", BAR,
           f"  Generated        : {datetime.now():%Y-%m-%d %H:%M:%S}",
           f"  Addresses        : {len(in_use)} in-use addresses checked",
           f"  InternetDB data  : {have_db}  (free, no API key - internetdb.shodan.io)",
           f"  Shodan data      : {have_sh}" + ("" if shodan or not in_use else "  (no paid key given)"),
           "", "  This only reads data Shodan already collected on its own; it never asks",
           "  Shodan to scan, probe or re-check any address.", ""]
    for ip in in_use:
        db, sh = internetdb.get(ip), shodan.get(ip)
        out += [BAR, f"  {ip}" + (f"  ({ptrs[ip]})" if ptrs.get(ip) else ""), BAR, ""]
        out.append("  -- InternetDB (free) --")
        if db is None:
            out.append("  (not checked)")
        elif db["text"]:
            out.append(render_whois(db["text"]))
        else:
            out.append(f"  {db['error']}")
        if sh is not None:
            out += ["", "  -- Shodan (paid key) --"]
            if sh["text"]:
                out.append(render_whois(sh["text"]))
            else:
                out.append(f"  {sh['error']}")
        out.append("")
    out.append("  End of report.")
    return "\n".join(out) + "\n"


_tld_cache = {}
_tld_lock = threading.Lock()
NOISE_MARKERS = (">>>", "NOTICE:", "TERMS OF USE:", "For more information on Whois status codes")


def whois_server_for(tld):
    """.nl -> SIDN; any other TLD -> ask IANA which whois server is responsible."""
    if tld == "nl":
        return SIDN_HOST
    with _tld_lock:
        if tld in _tld_cache:
            return _tld_cache[tld]
    srv = None
    try:
        for line in whois_query("whois.iana.org", tld).splitlines():
            if line.lower().startswith(("refer:", "whois:")):
                srv = line.split(":", 1)[1].strip() or None
                if srv:
                    break
    except OSError:
        pass
    with _tld_lock:
        _tld_cache[tld] = srv
    return srv


def strip_noise(txt):
    cut = len(txt)
    for m in NOISE_MARKERS:
        i = txt.find(m)
        if i != -1:
            cut = min(cut, i)
    return txt[:cut].strip()


# ---- polite querying: SIDN (and others) rate-limit per IP address
INTERVALS = {SIDN_HOST: 2.0}      # minimum seconds between queries to one server (default 0.5)
RETRY_WAITS = [20, 45, 90]        # back-off after a "rate limit exceeded" answer
_throttle_lock = threading.Lock()
_next_ok = {}


def throttle(server):
    """Space out queries to the same server, across all worker threads."""
    with _throttle_lock:
        now = time.time()
        wait = max(0.0, _next_ok.get(server, 0.0) - now)
        _next_ok[server] = now + wait + INTERVALS.get(server, 0.5)
    if wait:
        time.sleep(wait)


def penalize(server, secs):
    with _throttle_lock:
        _next_ok[server] = max(_next_ok.get(server, 0.0), time.time() + secs)


def is_rate_limited(txt):
    t = txt.lower()
    return len(t) < 600 and any(w in t for w in (
        "ratelimit", "rate limit", "rate-limit", "too many", "quota", "limit exceeded", "access denied"))


def polite_whois(server, query):
    """whois query that waits between requests and backs off when rate-limited.
    Returns the text, or None if the server keeps refusing."""
    for attempt in range(len(RETRY_WAITS) + 1):
        throttle(server)
        txt = whois_query(server, query)
        if not is_rate_limited(txt):
            return txt
        if attempt < len(RETRY_WAITS):
            log(f"{server} rate-limited ({query}); waiting {RETRY_WAITS[attempt]}s")
            penalize(server, RETRY_WAITS[attempt])
    return None


def rdap_lookup(domain):
    """Fallback: RDAP (web API) via rdap.org, which redirects to the right registry."""
    import urllib.request
    req = urllib.request.Request(f"https://rdap.org/domain/{domain}", headers={
        "Accept": "application/rdap+json", "User-Agent": "ip-whois-collector"})
    with urllib.request.urlopen(req, timeout=20) as r:
        data = json.load(r)
    lines = [f"Domain name: {data.get('ldhName', domain)}",
             f"Status: {', '.join(data.get('status', []))}"]
    for ev in data.get("events", []):
        lines.append(f"{str(ev.get('eventAction', 'event')).title()}: {ev.get('eventDate', '')}")
    ns = [n.get("ldhName", "") for n in data.get("nameservers", [])]
    if ns:
        lines.append("Name servers: " + ", ".join(ns))
    for ent in data.get("entities", []):
        name = ""
        for item in (ent.get("vcardArray") or [None, []])[1]:
            if item and item[0] == "fn":
                name = item[3]
        lines.append(f"{', '.join(ent.get('roles', [])).title() or 'Entity'}: {name or ent.get('handle', '')}")
    sec = data.get("secureDNS")
    if sec:
        lines.append("DNSSEC: " + ("signed" if sec.get("delegationSigned") else "unsigned"))
    return "\n".join(lines)


def domain_lookup(domain):
    """.nl -> SIDN. Others (.com etc.) -> the TLD registry's whois, then the registrar's whois.
    If whois stays rate-limited, falls back to RDAP.
    Returns (domain, text, source_description)."""
    tld = domain.rsplit(".", 1)[-1]
    srv = whois_server_for(tld)
    if not srv:
        return domain, f"No WHOIS server known for .{tld}", "none"
    try:
        raw = polite_whois(srv, domain)
        if raw is None:                                   # still rate-limited: try RDAP
            try:
                return domain, rdap_lookup(domain), f"RDAP via rdap.org ({srv} rate-limited)"
            except Exception as e:  # noqa
                return domain, f"Rate-limited by {srv} and RDAP failed: {e}", srv
        txt = strip_noise(raw)
        source = srv + (" (SIDN)" if srv == SIDN_HOST else "")
        if srv != SIDN_HOST:
            m = re.search(r"(?im)^\s*Registrar WHOIS Server:\s*(\S+)", txt)
            reg = m.group(1).lower() if m else ""
            if reg.startswith(("http://", "https://")):
                reg = reg.split("//", 1)[1].split("/")[0]
            if reg and reg != srv:
                try:
                    raw2 = polite_whois(reg, domain)
                    txt2 = strip_noise(raw2) if raw2 else ""
                    if txt2:
                        txt += "\n\n" + txt2
                        source += f" + registrar whois {reg}"
                except OSError:
                    source += f" (registrar whois {reg} unreachable)"
        return domain, txt, source
    except OSError as e:
        return domain, f"Lookup failed: {e}", srv


# ------------------------------------------------------------------ Shodan
# The API key only lives in memory for the duration of a run: it is never written to the
# report, the log or the status page, and it is only sent to api.shodan.io over HTTPS.
def shodan_api(method, path, key, form=None, json_body=None):
    """Returns (http_status, parsed_json). status 0 = could not connect.
    Error details are deliberately generic so the key (part of the URL) can never leak."""
    import urllib.error
    import urllib.parse
    import urllib.request
    url = f"https://api.shodan.io{path}?key={urllib.parse.quote(key)}"
    data, headers = None, {"User-Agent": "ip-whois-collector"}
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    elif json_body is not None:
        data = json.dumps(json_body).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read().decode("utf-8", "replace") or "{}")
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read().decode("utf-8", "replace"))
        except Exception:  # noqa
            body = {}
        return e.code, body
    except (urllib.error.URLError, OSError, ValueError):
        return 0, {}


def shodan_err(code, body):
    msg = {0: "could not reach api.shodan.io",
           401: "invalid API key",
           402: "this needs a paid Shodan plan or more credits",
           403: "access denied - this API call needs a paid Shodan plan",
           429: "rate limit hit"}.get(code, f"HTTP {code}")
    extra = body.get("error") if isinstance(body, dict) else ""
    return f"{msg}" + (f" ({extra})" if extra and code not in (0, 401) else "")


def format_shodan(d):
    """Shodan host JSON -> 'key: value' text (rendered later like the whois data)."""
    lines = []

    def add(k, v):
        if v not in (None, "", [], {}):
            lines.append(f"{k}: {v}")

    add("Organisation", d.get("org"))
    add("ISP", d.get("isp"))
    add("ASN", d.get("asn"))
    add("Operating system", d.get("os"))
    add("Hostnames", ", ".join(d.get("hostnames") or []))
    add("Domains", ", ".join(d.get("domains") or []))
    add("Location", ", ".join(x for x in (d.get("city"), d.get("country_name")) if x))
    add("Open ports", ", ".join(str(p) for p in sorted(d.get("ports") or [])))
    add("Tags", ", ".join(d.get("tags") or []))
    add("Vulnerabilities", ", ".join(sorted(d.get("vulns") or [])))
    add("Last update", d.get("last_update"))
    for s in d.get("data") or []:
        lines.append("")
        prod = " ".join(x for x in (s.get("product"), s.get("version")) if x)
        lines.append(f"Service {s.get('port')}/{s.get('transport', 'tcp')}: {prod or '(unidentified)'}")
        add("Seen", s.get("timestamp"))
        http = s.get("http") or {}
        add("HTTP title", http.get("title"))
        add("HTTP server", http.get("server"))
        cert = ((s.get("ssl") or {}).get("cert") or {})
        add("TLS subject", (cert.get("subject") or {}).get("CN"))
        add("TLS issuer", (cert.get("issuer") or {}).get("O") or (cert.get("issuer") or {}).get("CN"))
        add("TLS expires", cert.get("expires"))
        add("Service CVEs", ", ".join(sorted(s.get("vulns") or [])))
        banner = " ".join((s.get("data") or "").split())
        add("Banner", banner[:160] + ("..." if len(banner) > 160 else ""))
    return "\n".join(lines)


FREE_PLAN_NAMES = {"dev", "free", "oss", "test"}
INTERNETDB_HOST = "internetdb.shodan.io"
INTERNETDB_WORKERS = 6
INTERNETDB_DELAY = 0.25   # no published rate limit, but stay well under the radar


def internetdb_lookup(ip):
    """InternetDB: Shodan's free, keyless lookup of its own existing data for one IP
    (open ports, hostnames, CPEs, known CVEs). No API key, no paid plan, no scanning -
    just reads back what Shodan already has on file for that address.
    Returns (status, parsed_json_or_{})."""
    import urllib.error
    import urllib.request
    req = urllib.request.Request(f"https://{INTERNETDB_HOST}/{ip}",
                                  headers={"User-Agent": "ip-whois-collector", "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, json.loads(r.read().decode("utf-8", "replace") or "{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode("utf-8", "replace"))
        except Exception:  # noqa
            return e.code, {}
    except (urllib.error.URLError, OSError, ValueError):
        return 0, {}


def format_internetdb(d):
    lines = []

    def add(k, v):
        if v not in (None, "", [], {}):
            lines.append(f"{k}: {v}")
    add("Open ports", ", ".join(str(p) for p in sorted(d.get("ports") or [])))
    add("Hostnames", ", ".join(d.get("hostnames") or []))
    add("CPEs (software/hardware guesses)", ", ".join(d.get("cpes") or []))
    add("Known vulnerabilities (CVEs)", ", ".join(sorted(d.get("vulns") or [])))
    add("Tags", ", ".join(d.get("tags") or []))
    return "\n".join(lines)


def run_internetdb(ips):
    """Free, keyless lookup for every in-use address. Returns
    {ip: {"ports": [...], "vulns": n, "text": str|None, "error": str|None}}"""
    out = {}
    with ThreadPoolExecutor(max_workers=INTERNETDB_WORKERS) as ex:
        def work(ip):
            time.sleep(INTERNETDB_DELAY)
            code, d = internetdb_lookup(ip)
            if code == 429:
                time.sleep(5)
                code, d = internetdb_lookup(ip)
            return ip, code, d
        n = 0
        for ip, code, d in ex.map(work, ips):
            n += 1
            if code == 200:
                out[ip] = {"ports": sorted(d.get("ports") or []), "vulns": len(d.get("vulns") or []),
                           "text": format_internetdb(d), "error": None, "cpes": d.get("cpes") or []}
            elif code == 404:
                out[ip] = {"ports": [], "vulns": 0, "text": None,
                           "error": "No information in InternetDB for this address.", "cpes": []}
            else:
                out[ip] = {"ports": [], "vulns": 0, "text": None, "cpes": [],
                           "error": f"InternetDB lookup failed (HTTP {code})" if code else
                                    "InternetDB lookup failed (no connection)"}
            set_state(done=n)
    log(f"InternetDB: {sum(1 for v in out.values() if v['text'])} of {len(ips)} addresses have data")
    return out


def run_shodan(key, ips, notes):
    """Passive lookup only: reads Shodan's existing record for each address via
    /shodan/host/{ip}. This never asks Shodan to scan or probe anything itself -
    it only returns data Shodan already collected on its own.
    Needs a paid Shodan plan (Freelancer+) or purchased query credits - see run_internetdb
    for the free, keyless equivalent that every run uses regardless of this.
    Returns {ip: {"ports": [...], "vulns": n, "text": str|None, "error": str|None}}"""
    out = {}
    code, info = shodan_api("GET", "/api-info", key)
    if code != 200:
        notes.append(f"Shodan: {shodan_err(code, info)} - skipped (InternetDB results still included).")
        return out
    plan = str(info.get("plan", "?"))
    log(f"Shodan plan: {plan}, query credits: {info.get('query_credits', '?')}")
    if plan.lower() in FREE_PLAN_NAMES or not info.get("query_credits"):
        notes.append(
            f"Shodan: your API key is on the '{plan}' (free) plan, which does not include host "
            f"lookups (/shodan/host) - that needs a paid membership (Freelancer or higher) or "
            f"purchased query credits. Skipped the extra Shodan lookup; InternetDB results "
            f"(free, no key needed) are still included below. See https://www.shodan.io/pricing "
            f"to upgrade.")
        return out
    for i, ip in enumerate(ips, 1):
        time.sleep(1.1)                               # Shodan allows about 1 request/second
        code, d = shodan_api("GET", f"/shodan/host/{ip}", key)
        if code == 429:
            time.sleep(5)
            code, d = shodan_api("GET", f"/shodan/host/{ip}", key)
        if code == 200:
            services = []
            for s in d.get("data") or []:
                prod = " ".join(x for x in (s.get("product"), s.get("version")) if x)
                http_server = ((s.get("http") or {}).get("server") or "")
                services.append({"port": s.get("port"), "transport": s.get("transport", "tcp"),
                                 "product": prod or http_server})
            out[ip] = {"ports": sorted(d.get("ports") or []), "vulns": len(d.get("vulns") or []),
                       "text": format_shodan(d), "error": None, "services": services}
        elif code == 404:
            out[ip] = {"ports": [], "vulns": 0, "text": None,
                       "error": "No information in Shodan for this address.", "services": []}
        else:
            out[ip] = {"ports": [], "vulns": 0, "text": None, "error": shodan_err(code, d), "services": []}
            if code in (401, 402, 403):
                notes.append(f"Shodan lookups stopped after {i} of {len(ips)} addresses: "
                             f"{shodan_err(code, d)}. See https://www.shodan.io/pricing to upgrade.")
                break
        set_state(done=i)
    log(f"Shodan: {sum(1 for v in out.values() if v['text'])} of {len(ips)} addresses have data")
    return out


# ------------------------------------------------------------------ DNSDumpster
# https://dnsdumpster.com/developer/ - passive DNS recon for a domain (A/CNAME/MX/NS/TXT,
# the ASN/netblock/country of each resolved IP, and any banner data DNSDumpster already has
# on file). Needs a free API key; this never sends anything to the domains or IPs it
# returns - it only reads DNSDumpster's own stored data for the domain name.
DNSDUMPSTER_HOST = "api.dnsdumpster.com"
INTERVALS[DNSDUMPSTER_HOST] = 2.1   # the API enforces 1 request / 2 seconds


def dnsdumpster_api(path, key):
    import urllib.error
    import urllib.request
    req = urllib.request.Request(f"https://{DNSDUMPSTER_HOST}{path}",
                                  headers={"X-API-Key": key, "User-Agent": "ip-whois-collector",
                                           "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read().decode("utf-8", "replace") or "{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode("utf-8", "replace"))
        except Exception:  # noqa
            return e.code, {}
    except (urllib.error.URLError, OSError, ValueError):
        return 0, {}


def dnsdumpster_err(code, body):
    msg = {0: "could not reach api.dnsdumpster.com", 401: "invalid API key",
           403: "access denied for this API key/plan", 404: "no data for this domain",
           429: "rate limit hit"}.get(code, f"HTTP {code}")
    extra = body.get("error") if isinstance(body, dict) else ""
    return msg + (f" ({extra})" if extra and code not in (0, 401, 429) else "")


def format_dnsdumpster(d):
    """DNSDumpster's /domain/{domain} JSON -> readable indented text (rendered as-is,
    not passed through the flat key:value whois renderer)."""
    lines = []

    def ip_lines(ipobj):
        bits = [ipobj.get("ip", "?")]
        extra = [x for x in (ipobj.get("asn_name"), ipobj.get("asn"), ipobj.get("asn_range"),
                              ipobj.get("country")) if x]
        if extra:
            bits.append("(" + ", ".join(str(x) for x in extra) + ")")
        if ipobj.get("ptr"):
            bits.append(f"PTR={ipobj['ptr']}")
        out = ["      " + " ".join(bits)]
        b = ipobj.get("banners") or {}
        for proto in ("http", "https"):
            p = b.get(proto)
            if p:
                detail = ", ".join(x for x in (p.get("server"), p.get("title")) if x)
                out.append(f"        {proto}: {detail or '(banner on file)'}")
        return out

    recs = d.get("a") or []
    if recs:
        lines.append(f"  A records ({d.get('total_a_recs', len(recs))}):")
        for rec in recs:
            lines.append(f"    {rec.get('host', '?')}")
            for ipobj in rec.get("ips") or []:
                lines.extend(ip_lines(ipobj))
    for key, label in (("cname", "CNAME records"), ("mx", "MX records"),
                        ("ns", "NS records"), ("txt", "TXT records")):
        vals = d.get(key) or []
        if vals:
            lines.append("")
            lines.append(f"  {label}:")
            for v in vals:
                if isinstance(v, dict):
                    v = v.get("host") or v.get("value") or json.dumps(v)
                lines.append(f"    {v}")
    return "\n".join(lines) if lines else "  (no records returned)"


def dnsdumpster_pairs(d):
    """(hostname, ip) pairs from every record type in a DNSDumpster answer that carries IPs
    (A, MX, NS ...). Used to feed in-scope addresses back into the run."""
    pairs = []
    for vals in d.values() if isinstance(d, dict) else []:
        if not isinstance(vals, list):
            continue
        for rec in vals:
            if not isinstance(rec, dict):
                continue
            host = str(rec.get("host") or "").rstrip(".").lower()
            for ipobj in rec.get("ips") or []:
                ip = ipobj.get("ip") if isinstance(ipobj, dict) else None
                if ip:
                    pairs.append((host, ip))
    return pairs


# ------------------------------------------------------------------ discovery (passive)
# Certificate transparency via crt.sh: reads crt.sh's database of certificates that CAs
# have logged; nothing is sent to the domain or its hosts. The hostnames found are then
# resolved through the public resolvers in DNS_SERVERS, never by contacting the hosts.
CRTSH_HOST = "crt.sh"
INTERVALS[CRTSH_HOST] = 3.0        # crt.sh is a free, shared service: be gentle
CRTSH_MAX_HOSTS = 3000             # per domain; big ISP/hoster domains can have far more
RESOLVE_WORKERS = 32


def crtsh_hostnames(domain):
    """Hostnames under `domain` seen in certificate transparency logs.
    Returns (sorted hostnames, error or None)."""
    import urllib.error
    import urllib.parse
    import urllib.request
    url = f"https://{CRTSH_HOST}/?q={urllib.parse.quote('%.' + domain)}&output=json"
    req = urllib.request.Request(url, headers={"User-Agent": "ip-whois-collector",
                                               "Accept": "application/json"})
    last_err = None
    for attempt in range(3):                       # crt.sh often answers 502/503 under load
        throttle(CRTSH_HOST)
        try:
            with urllib.request.urlopen(req, timeout=90) as r:
                rows = json.loads(r.read().decode("utf-8", "replace") or "[]")
            break
        except urllib.error.HTTPError as e:
            last_err = f"crt.sh HTTP {e.code}"
        except (urllib.error.URLError, OSError, ValueError) as e:
            last_err = f"crt.sh unreachable ({type(e).__name__})"
        penalize(CRTSH_HOST, 10 * (attempt + 1))
    else:
        return [], last_err
    names = {domain}
    for row in rows if isinstance(rows, list) else []:
        for n in str(row.get("name_value", "")).splitlines():
            n = n.strip().lower().rstrip(".")
            if n.startswith("*."):
                n = n[2:]
            if not n or " " in n or "@" in n:
                continue
            if n == domain or n.endswith("." + domain):
                names.add(n)
    names = sorted(names)
    if len(names) > CRTSH_MAX_HOSTS:
        return names[:CRTSH_MAX_HOSTS], (f"crt.sh returned {len(names)} hostnames; only the "
                                          f"first {CRTSH_MAX_HOSTS} were resolved")
    return names, None


# ------------------------------------------------------------------ liveness probe (ACTIVE)
# NOTE: unlike everything else in this tool, this connects directly to each host. The request
# reaches the target and appears in its web server logs with this machine's IP address. It is
# off by default and gated behind its own checkbox. Only run it on hosts you are authorised to.
PROBE_WORKERS = 16
PROBE_TIMEOUT = 8


def http_probe(host):
    """One GET to https://host/ (falling back to http://), following up to 3 redirects.
    Returns (scheme, status_code, title) or None if nothing answered. Does not verify TLS,
    so self-signed certs still count as 'up'."""
    import ssl
    import urllib.error
    import urllib.request
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}/"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (compatible; asset-check)"})
        try:
            with urllib.request.urlopen(req, timeout=PROBE_TIMEOUT, context=ctx) as r:
                code = r.getcode()
                body = r.read(65536)
                final = r.geturl()
        except urllib.error.HTTPError as e:          # 401/403/404/500 etc: something IS listening
            return scheme, e.code, ""
        except (urllib.error.URLError, ssl.SSLError, OSError, ValueError):
            continue                                  # try http, then give up
        m = re.search(rb"<title[^>]*>(.*?)</title>", body, re.I | re.S)
        title = ""
        if m:
            try:
                title = re.sub(r"\s+", " ", m.group(1).decode("utf-8", "replace")).strip()[:120]
            except Exception:  # noqa
                title = ""
        if final != url:
            title = (title + f"  ->{final}").strip()
        return scheme, code, title
    return None


def run_probes(hostnames):
    """Probe each hostname once, in parallel. Returns [(host, scheme, code, title)] for
    everything that answered, sorted by host."""
    results = []

    def work(h):
        r = http_probe(h)
        return (h, *r) if r else None
    with ThreadPoolExecutor(max_workers=PROBE_WORKERS) as ex:
        for i, res in enumerate(ex.map(work, hostnames), 1):
            if res:
                results.append(res)
            set_state(done=i)
    return sorted(results, key=lambda r: r[0])


def build_probe_report(results, probed_count):
    out = [BAR, "  LIVE WEB HOSTS  (ACTIVE SCAN)", BAR,
           f"  Generated : {datetime.now():%Y-%m-%d %H:%M:%S}",
           f"  Probed    : {probed_count} hostname(s)",
           f"  Responded : {len(results)}",
           "",
           "  WARNING: this scan connected directly to each host below. These requests",
           "  appear in the targets' web server logs with this machine's IP address.",
           ""]
    if not results:
        out.append("  No hosts responded.")
    else:
        rows = [[f"{scheme}://{host}/", str(code), trunc(title or "-", 60)]
                for host, scheme, code, title in results]
        out += table(["URL", "STATUS", "PAGE TITLE / REDIRECT"], rows)
        out += ["", "  URLs, one per line:"]
        out += [f"    {scheme}://{host}/" for host, scheme, code, title in results]
    out += ["", "  End of report."]
    return "\n".join(out) + "\n"


def resolve_hosts(hostnames):
    """Forward-resolve (A + AAAA) through the public resolvers. Returns {hostname: [ips]}."""
    out = {}

    def work(h):
        ips = []
        for qtype in (1, 28):
            res = dns_query(h, qtype)
            if res and res[0] == 0:
                ips += res[1]
        return h, ips
    with ThreadPoolExecutor(max_workers=RESOLVE_WORKERS) as ex:
        for h, ips in ex.map(work, hostnames):
            if ips:
                out[h] = ips
    return out


def make_scope(text):
    """Every network the user entered (small and big blocks), for 'is this address in
    scope?' checks. Returns f(ip_address) -> bool."""
    nets = []
    for raw in text.replace(",", "\n").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            if "-" in line:
                a, b = [ipaddress.ip_address(x.strip()) for x in line.split("-", 1)]
                if a.version == b.version and int(b) >= int(a):
                    nets.extend(ipaddress.summarize_address_range(a, b))
            else:
                nets.append(ipaddress.ip_network(line, strict=False))
        except ValueError:
            continue
    checks = {}
    for v in (4, 6):
        merged = list(ipaddress.collapse_addresses(n for n in nets if n.version == v))
        checks[v] = make_covered(merged) if merged else (lambda k: False)

    def in_scope(ip):
        return checks[ip.version](ipaddress.ip_network(ip))
    return in_scope


def run_dnsdumpster(key, domains, notes):
    """One lookup per unique domain name (the same domains gathered from reverse-DNS
    hostnames for the SIDN/registry whois step).
    Returns {domain: {"text": str|None, "error": str|None, "pairs": [(hostname, ip), ...]}}"""
    out = {}
    for i, d in enumerate(domains, 1):
        throttle(DNSDUMPSTER_HOST)
        code, body = dnsdumpster_api(f"/domain/{d}", key)
        if code == 429:
            penalize(DNSDUMPSTER_HOST, 10)
            throttle(DNSDUMPSTER_HOST)
            code, body = dnsdumpster_api(f"/domain/{d}", key)
        if code == 200:
            out[d] = {"text": format_dnsdumpster(body), "error": None,
                      "pairs": dnsdumpster_pairs(body)}
        else:
            out[d] = {"text": None, "error": dnsdumpster_err(code, body), "pairs": []}
            if code in (401, 403):
                notes.append(f"DNSDumpster lookups stopped: {dnsdumpster_err(code, body)}. "
                             f"Check your API key at https://dnsdumpster.com/developer/.")
                break
        set_state(done=i)
    log(f"DNSDumpster: {sum(1 for v in out.values() if v['text'])} of {len(domains)} domains have data")
    return out


def build_dnsdumpster_report(domains, dnsdumpster):
    have = sum(1 for v in dnsdumpster.values() if v.get("text"))
    out = [BAR, "  DNSDUMPSTER REPORT (passive DNS reconnaissance per domain)", BAR,
           f"  Generated   : {datetime.now():%Y-%m-%d %H:%M:%S}",
           f"  Domains     : {len(domains)} unique domains looked up",
           f"  With data   : {have}",
           "", "  This only reads data DNSDumpster already has on file for each domain name;",
           "  it does not scan or probe anything itself.", ""]
    for d, dips in domains.items():
        info = dnsdumpster.get(d)
        out += [BAR, f"  {d}", BAR]
        if dips:
            out.append("  Seen on: " + ", ".join(str(ip) for ip in dips))
        out.append("")
        if info is None:
            out.append("  (not checked)")
        elif info["text"]:
            out.append(info["text"])
        else:
            out.append(f"  {info['error']}")
        out.append("")
    out.append("  End of report.")
    return "\n".join(out) + "\n"


def grab_line(text, label):
    """Pull the value of 'Label: value' out of a plain formatted text block (not RIPE-style
    whois) - used to surface a couple of key facts from the Shodan/InternetDB text blobs."""
    if not text:
        return ""
    for line in text.splitlines():
        line = line.strip()
        if line.lower().startswith(label.lower() + ":"):
            return line.split(":", 1)[1].strip()
    return ""


def build_hostmap_report(all_hosts, domains):
    """A single flat table of every domain and subdomain seen, where it resolves,
    whether that IP is inside the scanned blocks, and which source it came from."""
    out = [BAR, "  DOMAINS & SUBDOMAINS", BAR,
           f"  Generated : {datetime.now():%Y-%m-%d %H:%M:%S}",
           f"  Hostnames : {len(all_hosts)} across {len(domains)} domain(s)", "",
           "  Every domain (apex) and subdomain found via reverse DNS, crt.sh and",
           "  DNSDumpster, where it resolves, whether that address is inside the blocks",
           "  you entered (in / out / mixed), and the source(s) it came from.", ""]
    if not all_hosts:
        out += ["  No hostnames were found.", "", "  End of report."]
        return "\n".join(out) + "\n"
    by_dom = {}
    for host, rec in all_hosts.items():
        by_dom.setdefault(rec["domain"], []).append(host)
    rows = []
    for dom in sorted(by_dom):
        hosts = by_dom[dom]
        ordered = ([dom] if dom in hosts else []) + sorted(h for h in hosts if h != dom)
        for host in ordered:
            rec = all_hosts[host]
            if rec["ips"]:
                vals = rec["ips"].values()
                scope = "in" if all(vals) else "out" if not any(vals) else "mixed"
                points = ", ".join(sorted(rec["ips"]))
            else:
                scope, points = "-", "(did not resolve)"
            rows.append([dom, "(apex)" if host == dom else host,
                         trunc(points, 38), scope, ", ".join(sorted(rec["srcs"]))])
    out += table(["DOMAIN", "HOST", "POINTS TO", "SCOPE", "SOURCE"], rows)
    out += ["", "  SCOPE: in = resolves inside your blocks, out = outside, mixed = both,",
            "         - = no A/AAAA record. SOURCE: PTR = reverse DNS, CT = crt.sh.",
            "", "  End of report."]
    return "\n".join(out) + "\n"


def build_combined_report(notes, in_use, ptrs, ripe_text, domains, sidn,
                           internetdb, shodan, dnsdumpster,
                           use_internetdb, shodan_key, dnsdumpster_key,
                           use_ct=False, discovered=None, subdomains=None):
    """One clear, domain-centric digest. For every domain found it lays out, in order:
    its registration (whois), its DNS records (DNSDumpster), the subdomains seen for it,
    and each in-use address that belongs to it with that address's network, open ports,
    services, software and CVEs. Addresses with no domain are listed in a final section.
    Full raw records stay in the other report files; this is the readable summary."""
    discovered = discovered or {}
    subdomains = subdomains or {}
    full_by_ip = {str(ip): txt for ip, (kind, txt) in ripe_text.items() if kind == "full"}

    def ripe_text_for(ip):
        kind, val = ripe_text.get(ip, (None, None))
        return val if kind == "full" else full_by_ip.get(val, "")

    ip_to_domain = {ip: d for d, ips in domains.items() for ip in ips}
    ipkey = lambda ip: (ip.version, int(ip))                 # noqa: E731
    enrich = use_internetdb or shodan_key

    def ports_for(ip):
        ports, sources = set(), []
        for label, store in (("InternetDB", internetdb), ("Shodan", shodan)):
            info = store.get(ip)
            if info and info.get("ports"):
                ports |= set(info["ports"])
                sources.append(label)
        return sorted(ports), sources

    def vulns_for(ip):
        vulns = set()
        for src in (internetdb.get(ip), shodan.get(ip)):
            if src and src.get("text"):
                line = (grab_line(src["text"], "Known vulnerabilities (CVEs)") or
                        grab_line(src["text"], "Vulnerabilities"))
                vulns |= {v.strip() for v in line.split(",") if v.strip() and v.strip() != "-"}
        return sorted(vulns)

    def addr_sort(ip):                                       # services first, then numeric
        return (0 if ports_for(ip)[0] else 1,) + ipkey(ip)

    # -- one address's indented detail block, shown under its domain ---------------
    PAD = "          "          # label column indent for address detail lines

    def render_address(ip):
        host = host_label(ip, ptrs, discovered)
        lines = ["  - " + str(ip) + (f"    {host}" if host else "    (no reverse DNS)")]
        if ip in discovered:
            lines.append(PAD + "found via : " + "; ".join(
                f"{s} ({h})" for s, h in sorted(set(discovered[ip]))))
        txt = ripe_text_for(ip)
        net_bits = [x for x in (first_field(txt, "netname"),
                                 first_field(txt, "org-name") or first_field(txt, "descr"),
                                 first_field(txt, "country")) if x]
        inr = first_field(txt, "inetnum", "inet6num")
        lines.append(PAD + "network   : " + (" / ".join(net_bits) if net_bits else "(no RIPE record)")
                     + (f"    [{inr}]" if inr else ""))
        ports, psources = ports_for(ip)
        if ports:
            lines.append(PAD + "open ports: " + ", ".join(str(p) for p in ports)
                         + f"    [{' + '.join(psources)}]")
        elif enrich:
            errs = [store[ip]["error"] for store in (internetdb, shodan)
                    if ip in store and store[ip].get("error")]
            lines.append(PAD + "open ports: " + (errs[0] if errs else "none found"))
        for s in (shodan.get(ip) or {}).get("services") or []:
            lines.append(PAD + f"  {s['port']}/{s['transport']}  {s['product'] or '(unidentified)'}")
        cpes = (internetdb.get(ip) or {}).get("cpes") or []
        if cpes:
            lines.append(PAD + "software  : " + ", ".join(cpes) + "    [InternetDB CPE guess]")
        vulns = vulns_for(ip)
        if vulns:
            lines.append(textwrap.fill(PAD + "CVEs      : " + ", ".join(vulns),
                                       WIDTH, subsequent_indent=PAD + "            "))
        org = grab_line((shodan.get(ip) or {}).get("text", ""), "Organisation")
        isp = grab_line((shodan.get(ip) or {}).get("text", ""), "ISP")
        if org or isp:
            lines.append(PAD + "shodan org: " + ", ".join(x for x in (org, isp) if x))
        lines.append("")
        return lines

    # ---- header -------------------------------------------------------------------
    srcs_used = ["reverse DNS", "RIPE WHOIS", "domain WHOIS"]
    if use_internetdb:
        srcs_used.append("InternetDB")
    if shodan_key:
        srcs_used.append("Shodan")
    if use_ct:
        srcs_used.append("crt.sh")
    if dnsdumpster_key:
        srcs_used.append("DNSDumpster")
    no_domain = sorted([ip for ip in in_use if ip not in ip_to_domain], key=addr_sort)

    out = [BAR, "  COMBINED REPORT - everything found, grouped by domain", BAR,
           f"  Generated     : {datetime.now():%Y-%m-%d %H:%M:%S}",
           f"  In use        : {len(in_use)} address(es)"
           + (f"  ({len(discovered)} added via discovery)" if discovered else ""),
           f"  Domains       : {len(domains)}" + (f"  (+ {len(no_domain)} address(es) with no domain)"
                                                   if no_domain else ""),
           f"  Sources used  : {', '.join(srcs_used)}",
           "",
           "  How to read: one block per domain, each with its registration, its DNS",
           "  records, then every address on that domain and what was found for it.",
           "  Full raw records live in ip_whois_report.txt, shodan_report.txt and",
           "  dnsdumpster_report.txt."]
    if notes:
        out += ["", "  Warnings from this run:"]
        for n in notes:
            out.append(textwrap.fill("    - " + n, WIDTH, subsequent_indent="      "))

    if not in_use:
        out += ["", "  No addresses in use were found.", "", "  End of report."]
        return "\n".join(out) + "\n"

    # ---- at-a-glance index --------------------------------------------------------
    dom_order = sorted(domains)
    out += section("AT A GLANCE")
    idx_rows = []
    for i, d in enumerate(dom_order, 1):
        dips = domains[d]
        allports = sorted({p for ip in dips for p in ports_for(ip)[0]})
        ncve = len({v for ip in dips for v in vulns_for(ip)})
        nsub = len(subdomains.get(d) or {})
        idx_rows.append([f"{i}", d, str(len(dips)), str(nsub) if nsub else "-",
                         trunc(", ".join(str(p) for p in allports) or "-", 28),
                         str(ncve) if ncve else "-"])
    if no_domain:
        allports = sorted({p for ip in no_domain for p in ports_for(ip)[0]})
        ncve = len({v for ip in no_domain for v in vulns_for(ip)})
        idx_rows.append(["-", "(no domain)", str(len(no_domain)), "-",
                         trunc(", ".join(str(p) for p in allports) or "-", 28),
                         str(ncve) if ncve else "-"])
    out += table(["#", "DOMAIN", "ADDRS", "SUBS", "OPEN PORTS", "CVES"], idx_rows)

    # ---- per-domain sections ------------------------------------------------------
    for i, d in enumerate(dom_order, 1):
        dips = sorted(domains[d], key=addr_sort)
        out += section(f"DOMAIN {i}/{len(dom_order)}  -  {d}")

        # registration (domain whois / SIDN)
        src, dtxt = sidn.get(d, ("", ""))
        out.append("  Registration")
        out.append("  " + "-" * 40)
        reg = [("Source", src or "(lookup failed)"),
               ("Status", first_field(dtxt, "status", "domain status")),
               ("Registrar", first_field(dtxt, "registrar", "sponsoring registrar")),
               ("Registrant", first_field(dtxt, "registrant", "registrant name", "org", "organisation")),
               ("Created", first_field(dtxt, "creation date", "created date", "created",
                                       "registered", "registration date")),
               ("Updated", first_field(dtxt, "updated date", "last updated", "updated",
                                       "changed", "modified")),
               ("Expires", first_field(dtxt, "registry expiry date", "expiry date",
                                       "expiration date", "paid-till", "expires")),
               ("Name servers", first_field(dtxt, "name server", "nserver", "nameservers"))]
        shown = False
        for label, val in reg:
            if val:
                out.append(f"    {label:<13}: {val}")
                shown = True
        if not shown:
            out.append("    (no registration detail parsed; see ip_whois_report.txt)")
        out.append(f"    Full record  : ip_whois_report.txt")
        out.append("")

        # DNS records (DNSDumpster), if this domain was looked up
        if dnsdumpster_key:
            out.append("  DNS records (DNSDumpster)")
            out.append("  " + "-" * 40)
            dd = dnsdumpster.get(d)
            if dd and dd.get("text"):
                out.append(textwrap.indent(dd["text"], "  "))
                out.append(f"    Full record  : dnsdumpster_report.txt")
            elif dd and dd.get("error"):
                out.append(f"    {dd['error']}")
            else:
                out.append("    (no records returned)")
            out.append("")

        # subdomains seen for this domain (from reverse DNS, crt.sh and DNSDumpster)
        subs = subdomains.get(d) or {}
        if subs:
            n_in = sum(1 for r in subs.values() if any(r["ips"].values()))
            out.append(f"  Subdomains seen ({len(subs)}; {n_in} resolve into your blocks)")
            out.append("  " + "-" * 40)
            srows = []
            for host in sorted(subs):
                rec = subs[host]
                if rec["ips"]:
                    vals = rec["ips"].values()
                    scope = ("in scope" if all(vals) else
                             "out of scope" if not any(vals) else "mixed")
                    ipstr = ", ".join(sorted(rec["ips"]))
                else:
                    scope, ipstr = "no DNS", "(did not resolve)"
                srows.append([trunc(host, 40), trunc(ipstr, 34), scope,
                              ", ".join(sorted(rec["srcs"]))])
            out += table(["SUBDOMAIN", "RESOLVES TO", "SCOPE", "SOURCE"], srows)
            out.append("")

        # addresses on this domain
        out.append(f"  Addresses on this domain ({len(dips)})")
        out.append("  " + "-" * 40)
        for ip in dips:
            out += render_address(ip)

    # ---- addresses with no domain -------------------------------------------------
    if no_domain:
        out += section(f"ADDRESSES WITH NO DOMAIN ({len(no_domain)})")
        out.append("  In-use addresses with no domain name from reverse DNS.")
        out.append("")
        for ip in no_domain:
            out += render_address(ip)

    out.append("  End of report.")
    return "\n".join(out) + "\n"


def worker(blocks_text, max_addrs, require_ptr, max_queries, shodan_key="", use_internetdb=False,
           dnsdumpster_key="", use_ct=False, use_probe=False, use_nmap=False):
    phases = (["rdns"] + (["discovery"] if (use_ct or dnsdumpster_key) else [])
              + ["ripe", "domains"] + (["shodan"] if (use_internetdb or shodan_key) else [])
              + (["nmap"] if use_nmap else [])
              + (["probe"] if use_probe else []))

    def ph(key, label):
        return f"{phases.index(key) + 1}/{len(phases)} {label}"
    try:
        ips, walk_nets, errors = parse_blocks(blocks_text, max_addrs)
        for e in errors:
            log("SKIPPED INPUT: " + e)
        notes = [f"Input skipped: {e}" for e in errors]
        set_state(done=0, total=len(ips), used=0, result="", phase=ph("rdns", "Checking reverse DNS"))

        # ---- phase 1a: parallel PTR lookups for small blocks
        ptrs = {}
        if ips:
            with ThreadPoolExecutor(max_workers=PTR_WORKERS) as ex:
                futs = {ex.submit(ptr, ip): ip for ip in ips}
                n = 0
                for f in as_completed(futs):
                    ptrs[futs[f]] = f.result()
                    n += 1
                    if n % 25 == 0 or n == len(ips):
                        set_state(done=n)
        in_use = [ip for ip in ips if ptrs.get(ip) or not require_ptr]
        checked = [f"{len(ips)} addresses checked one by one"] if ips else []

        # ---- phase 1b: big blocks (e.g. an IPv6 /48) are walked through the reverse-DNS tree
        block_info = []
        if walk_nets:
            set_state(phase=ph("rdns", "Walking reverse-DNS tree"), done=0, total=max_queries)
            budget = max_queries
            with ThreadPoolExecutor(max_workers=DNS_WORKERS) as ex:
                for net in walk_nets:
                    if budget <= 0:
                        notes.append(f"{net}: skipped, DNS query budget exhausted")
                        continue
                    seeds = []
                    if net.version == 6 and net.prefixlen < 48:
                        # use RIPE's list of registered sub-blocks to scan those first
                        try:
                            time.sleep(DELAY)
                            seeds = ripe_subblocks(net)
                            log(f"{net}: RIPE lists {len(seeds)} registered sub-blocks")
                        except OSError as e:
                            log(f"{net}: could not list RIPE sub-blocks ({e}); walking whole block")
                    found, used, failed, truncated = walk_reverse(net, budget, ex, seeds)
                    budget -= used
                    checked.append(f"{net} walked via reverse DNS ({used} queries, "
                                   f"{len(found)} PTR records"
                                   + (f", {len(seeds)} RIPE sub-blocks scanned first" if seeds else "") + ")")
                    if truncated:
                        notes.append(f"{net}: stopped at the query limit ({max_queries}); "
                                     f"results are incomplete. Raise the limit or enter smaller "
                                     f"blocks (e.g. the /48s you actually use).")
                    if used and failed == used:
                        notes.append(f"{net}: ALL DNS queries failed. Outbound UDP port 53 to "
                                     f"{', '.join(DNS_SERVERS)} is probably blocked on this network "
                                     f"(firewall, VPN or router).")
                    elif failed:
                        notes.append(f"{net}: {failed} of {used} DNS queries failed; "
                                     f"results may be incomplete.")
                    for ip, host in found.items():
                        ptrs[ip] = host
                        if ip not in in_use:
                            in_use.append(ip)
                    try:
                        time.sleep(DELAY)
                        block_info.append((str(net), whois_query(RIPE_HOST, str(net)).strip()))
                    except OSError as e:
                        block_info.append((str(net), f"WHOIS lookup failed: {e}"))
        in_use = sorted(set(in_use), key=lambda i: (i.version, int(i)))
        set_state(used=len(in_use))
        log(f"{len(in_use)} addresses in use")

        discovered = {}   # ip -> [(source, hostname)] for in-scope addresses added by discovery

        def domain_of(ip):
            d = nl_domain(ptrs.get(ip))
            if d:
                return d
            for _, h in sorted(discovered.get(ip, [])):
                d = nl_domain(h)
                if d:
                    return d
            return None

        # ---- optional discovery: CT logs (crt.sh) and DNSDumpster, per domain from reverse DNS.
        # Only addresses inside the entered blocks are kept; nothing is sent to the hosts.
        in_scope = make_scope(blocks_text)
        disc_hosts = {}   # every hostname seen via CT/DNSDumpster -> {"ips": set(str), "srcs": set()}
        dnsdumpster = {}
        if in_use and (use_ct or dnsdumpster_key):
            seed_domains = sorted({d for d in map(domain_of, in_use) if d})
            candidates = {}   # address string -> [(source, hostname)]
            if use_ct and seed_domains:
                set_state(phase=ph("discovery", "Certificate transparency (crt.sh)"),
                          done=0, total=len(seed_domains))
                for i, d in enumerate(seed_domains, 1):
                    names, err = crtsh_hostnames(d)
                    if err:
                        notes.append(f"{d}: {err}")
                    resolved = resolve_hosts(names) if names else {}
                    for h in names:
                        rec = disc_hosts.setdefault(h, {"ips": set(), "srcs": set()})
                        rec["srcs"].add("CT")
                        for a in resolved.get(h, []):
                            rec["ips"].add(a)
                            candidates.setdefault(a, []).append(("CT", h))
                    log(f"crt.sh: {d} -> {len(names)} hostnames, {len(resolved)} resolve")
                    set_state(done=i)
            if dnsdumpster_key and seed_domains:
                set_state(phase=ph("discovery", "DNSDumpster lookup"), done=0, total=len(seed_domains))
                dnsdumpster = run_dnsdumpster(dnsdumpster_key, seed_domains, notes)
                for info in dnsdumpster.values():
                    for h, a in info.get("pairs", []):
                        rec = disc_hosts.setdefault(h, {"ips": set(), "srcs": set()})
                        rec["srcs"].add("DNSDumpster")
                        rec["ips"].add(a)
                        candidates.setdefault(a, []).append(("DNSDumpster", h))
            have, outside = set(in_use), 0
            for a, srcs in candidates.items():
                try:
                    ip = ipaddress.ip_address(a)
                except ValueError:
                    continue
                if not in_scope(ip):
                    outside += 1
                elif ip not in have:
                    discovered[ip] = sorted(set(srcs))
            if discovered:                    # PTR for the new ones, same as phase 1
                with ThreadPoolExecutor(max_workers=PTR_WORKERS) as ex:
                    for ip, host in zip(discovered, ex.map(ptr, discovered)):
                        if host:
                            ptrs[ip] = host
                in_use = sorted(have | set(discovered), key=lambda i: (i.version, int(i)))
                set_state(used=len(in_use))
            checked.append(f"discovery: {len(candidates)} addresses from "
                           + " + ".join(x for x, on in (("CT logs", use_ct),
                                                         ("DNSDumpster", dnsdumpster_key)) if on)
                           + f", {len(discovered)} new in scope, {outside} outside your blocks (ignored)")
            log(f"discovery: {len(discovered)} new in-scope addresses, {outside} out of scope ignored")

        # ---- phase 2: RIPE lookups, one per registered block
        set_state(phase=ph("ripe", "RIPE WHOIS"), done=0, total=len(in_use))
        cache = []   # (start, end, text, first_ip)
        ripe_text = {}   # ip -> ("full", text) | ("ref", first_ip)
        for i, ip in enumerate(in_use, 1):
            hit = next((c for c in cache if c[0].version == ip.version and c[0] <= ip <= c[1]), None)
            if hit:
                ripe_text[ip] = ("ref", hit[3])
            else:
                try:
                    time.sleep(DELAY)
                    txt = whois_query(RIPE_HOST, str(ip)).strip()
                except OSError as e:
                    txt = f"WHOIS lookup failed: {e}"
                rng = object_range(txt)
                if rng:
                    cache.append((rng[0], rng[1], txt, str(ip)))
                ripe_text[ip] = ("full", txt)
            set_state(done=i)

        # ---- phase 3: domain lookups, one per unique domain (.nl -> SIDN, others -> registry whois)
        domains = {}
        for ip in in_use:
            d = domain_of(ip)
            if d:
                domains.setdefault(d, []).append(ip)
        set_state(phase=ph("domains", "Domain lookups"), done=0, total=len(domains))
        sidn = {}
        if domains:
            with ThreadPoolExecutor(max_workers=SIDN_WORKERS) as ex:
                futs = [ex.submit(domain_lookup, d) for d in domains]
                for n, f in enumerate(as_completed(futs), 1):
                    d, txt, src = f.result()
                    sidn[d] = (src, txt)
                    log(f"domain: {d} ({src})")
                    set_state(done=n)

        # ---- phase 4 (optional): InternetDB (free, keyless) and/or a paid Shodan key
        internetdb = {}
        shodan = {}
        if in_use and (use_internetdb or shodan_key):
            if use_internetdb:
                set_state(phase=ph("shodan", "InternetDB lookup"), done=0, total=len(in_use))
                internetdb = run_internetdb(in_use)
            if shodan_key:
                set_state(phase=ph("shodan", "Shodan lookup"), done=0, total=len(in_use))
                shodan = run_shodan(shodan_key, in_use, notes)

        # ---- collect every hostname seen (apex domains + subdomains), from PTRs, CT and
        #      DNSDumpster, each with its resolved IP(s), scope, and source(s).
        all_hosts = {}   # hostname -> {"domain": d, "ips": {ipstr: in_scope_bool}, "srcs": set()}

        def add_host(host, ipstr, inscope, srcs):
            dom = nl_domain(host)
            if not dom:
                return
            rec = all_hosts.setdefault(host, {"domain": dom, "ips": {}, "srcs": set()})
            rec["srcs"].update(srcs)
            if ipstr is not None:
                rec["ips"][ipstr] = rec["ips"].get(ipstr, False) or inscope

        for ip in in_use:                                   # hostnames seen in reverse DNS
            h = ptrs.get(ip)
            if h:
                add_host(h, str(ip), True, {"PTR"})
        for ip, srcs in discovered.items():                 # in-scope hosts added by discovery
            for s, h in srcs:
                add_host(h, str(ip), True, {s})
        for h, info in disc_hosts.items():                  # all CT/DNSDumpster names (incl. out-of-scope)
            if info["ips"]:
                for ipstr in info["ips"]:
                    try:
                        sc = in_scope(ipaddress.ip_address(ipstr))
                    except ValueError:
                        sc = False
                    add_host(h, ipstr, sc, info["srcs"])
            else:
                add_host(h, None, False, info["srcs"])
        for d in domains:                                   # ensure every apex domain has a row,
            all_hosts.setdefault(d, {"domain": d, "ips": {}, "srcs": {"domain"}})
            # (its own A/AAAA is filled in above only if the apex name itself was seen/resolved;
            #  otherwise it shows as not-resolved - its member addresses are the subdomain rows)

        # subdomains view (apex excluded) for the combined report's per-domain tables
        subdomains = {}
        for host, rec in all_hosts.items():
            if host != rec["domain"]:
                subdomains.setdefault(rec["domain"], {})[host] = {"ips": rec["ips"],
                                                                  "srcs": rec["srcs"]}

        # ---- build reports
        report = build_report(checked, notes, block_info, in_use, ptrs, ripe_text, domains, sidn,
                              discovered)
        shodan_report = (build_shodan_report(in_use, ptrs, internetdb, shodan)
                          if in_use and (use_internetdb or shodan_key) else "")
        dnsdumpster_report = (build_dnsdumpster_report(domains, dnsdumpster)
                               if domains and dnsdumpster_key else "")
        combined_report = build_combined_report(
            notes, in_use, ptrs, ripe_text, domains, sidn, internetdb, shodan, dnsdumpster,
            use_internetdb, shodan_key, dnsdumpster_key, use_ct, discovered, subdomains)
        hostmap_report = build_hostmap_report(all_hosts, domains) if all_hosts else ""
        set_state(result=report, shodan_result=shodan_report, dnsdumpster_result=dnsdumpster_report,
                  combined_result=combined_report, hostmap_result=hostmap_report, phase="Finished")

        # ---- optional: nmap -sL cross-check (nmap's own reverse-DNS, no packets to targets)
        if use_nmap:
            set_state(phase=ph("nmap", "nmap -sL cross-check"), done=0, total=len(ips))
            nmap_out = run_nmap_sl(ips, notes)
            if nmap_out.get("error"):
                log(f"nmap -sL: {nmap_out['error']}")
            else:
                log(f"nmap -sL: {len(nmap_out.get('hosts', {}))} hostname(s) resolved")
            set_state(nmap_result=build_nmap_report(ips, walk_nets, nmap_out))

        # ---- optional ACTIVE step: connect to each known hostname and see if a site answers.
        # Kept entirely separate: its own file, nothing merged into the reports above.
        if use_probe:
            targets = sorted({h for h in ptrs.values() if h}
                             | {h for srcs in discovered.values() for _, h in srcs
                                if not h.startswith("[")})
            if targets:
                set_state(phase=ph("probe", "ACTIVE: probing web hosts"), done=0, total=len(targets))
                log(f"ACTIVE probe: connecting to {len(targets)} hostname(s)")
                results = run_probes(targets)
                set_state(probe_result=build_probe_report(results, len(targets)))
                log(f"ACTIVE probe: {len(results)} of {len(targets)} responded")
            else:
                set_state(probe_result=build_probe_report([], 0))
                log("ACTIVE probe: no hostnames to probe")

        set_state(phase="Finished")
        log("Finished.")
    except Exception as e:  # noqa
        log(f"ERROR: {e}")
        set_state(phase="Error")
    finally:
        set_state(running=False)


PAGE = """<!doctype html><meta charset=utf-8><title>BlockScraper</title>
<meta name=viewport content="width=device-width,initial-scale=1">
<style>
:root{
  --bg:#1a1d23; --panel:#20242b; --panel-2:#1d2128; --border:#333842; --border-soft:#2a2e36;
  --text:#d6d9de; --head:#eceef1; --muted:#80868f; --faint:#5f656e;
  --accent:#4f86c6; --accent-hi:#5c93d1; --ok:#5aa469;
  --danger:#d98c3f; --danger-bg:#2a2016; --danger-border:#5c4326;
  --mono:"SF Mono",Consolas,"Liberation Mono",Menlo,monospace;
}
*{box-sizing:border-box}
body{
  font-family:"Segoe UI",Helvetica,Arial,sans-serif;
  background:var(--bg); color:var(--text); max-width:760px; margin:0 auto;
  padding:2rem 1.25rem 3rem; line-height:1.5; font-size:14px;
}
header{border-bottom:1px solid var(--border); padding-bottom:1rem; margin-bottom:1.6rem}
h1{font-size:1.15rem; font-weight:600; color:var(--head); margin:0 0 .3rem; letter-spacing:.01em}
header p{color:var(--muted); font-size:.82rem; margin:0; max-width:60ch}
header .by{color:var(--faint); font-size:.74rem; margin-top:.35rem}

/* a group = one labelled card holding related scan types */
.group{border:1px solid var(--border-soft); border-radius:7px; background:var(--panel-2);
  padding:1rem 1.1rem; margin-bottom:1.1rem}
.group > h2{
  font-size:.72rem; font-weight:700; letter-spacing:.08em; text-transform:uppercase;
  color:var(--head); margin:0 0 .2rem;
}
.group > .lead{color:var(--muted); font-size:.79rem; margin:0 0 .9rem}
.group.core > h2{color:var(--accent)}
.group.passive > h2{color:var(--ok)}

.sub{font-size:.73rem; font-weight:600; letter-spacing:.03em; color:var(--text);
  margin:1rem 0 .5rem; padding-top:.8rem; border-top:1px solid var(--border-soft)}
.sub:first-of-type{border-top:none; padding-top:0; margin-top:.2rem}

.field{margin:.75rem 0}
.field > label{display:block; font-size:.84rem; color:var(--text); margin-bottom:.3rem; font-weight:500}
.field .desc{display:block; font-size:.77rem; color:var(--muted); margin-top:.3rem}
.check{display:flex; align-items:flex-start; gap:.55rem; margin:.65rem 0}
.check input{margin-top:.2rem; flex:none}
.check .t{font-size:.84rem; color:var(--text); font-weight:500}
.check .desc{display:block; font-size:.77rem; color:var(--muted); margin-top:.2rem}
.row{display:flex; gap:1rem; flex-wrap:wrap}
.row .field{flex:1; min-width:13rem}

textarea,input[type=number],input[type=password],input[type=text]{
  width:100%; background:#14161b; color:var(--text); border:1px solid var(--border);
  border-radius:4px; padding:.5rem .6rem; font-family:var(--mono); font-size:.83rem;
}
textarea{height:118px; resize:vertical; line-height:1.5}
textarea::placeholder,input::placeholder{color:var(--faint)}
textarea:focus,input:focus{outline:none; border-color:var(--accent); box-shadow:0 0 0 2px rgba(79,134,198,.15)}
input[type=number]{width:100%}
input[type=checkbox]{width:15px; height:15px; accent-color:var(--accent); cursor:pointer}
code{background:#14161b; border:1px solid var(--border-soft); border-radius:3px;
  padding:.05rem .3rem; font-size:.85em; color:var(--text)}
.note{font-size:.77rem; color:var(--muted); margin:.9rem 0 0; padding-top:.8rem;
  border-top:1px solid var(--border-soft)}
.note b{color:var(--ok); font-weight:600}

/* active-scan group: visually set apart */
.group.danger{border-color:var(--danger-border); background:var(--danger-bg)}
.group.danger > h2{color:var(--danger)}
.group.danger .lead{color:#c9a978}
.group.danger .desc{color:#c9a978}
.badge{display:inline-block; background:var(--danger); color:#1a1d23; font-size:.6rem;
  font-weight:700; letter-spacing:.07em; padding:.12rem .42rem; border-radius:3px;
  vertical-align:middle; margin-left:.5rem; text-transform:uppercase}

.actions{display:flex; align-items:center; gap:.7rem; flex-wrap:wrap; margin:1.6rem 0 1rem}
button{
  background:var(--accent); color:#fff; border:1px solid var(--accent);
  padding:.5rem 1.4rem; font-size:.85rem; font-weight:600; border-radius:4px; cursor:pointer;
}
button:hover:not(:disabled){background:var(--accent-hi); border-color:var(--accent-hi)}
button:disabled{opacity:.4; cursor:not-allowed}

#downloads{margin:.4rem 0 1rem}
#downloads .dlhead{font-size:.68rem; font-weight:700; letter-spacing:.08em; text-transform:uppercase;
  color:var(--muted); margin-bottom:.6rem}
.dlgrid{display:flex; gap:.6rem; flex-wrap:wrap}
a.dl{
  color:var(--text); text-decoration:none; font-size:.81rem;
  border:1px solid var(--border); padding:.46rem .95rem; border-radius:4px; background:var(--panel);
}
a.dl:hover{border-color:var(--accent); color:var(--accent)}
a.dl.primary{border-color:var(--accent); color:#fff; background:var(--accent); font-weight:600}
a.dl.primary:hover{background:var(--accent-hi)}
a.dl.active{border-color:var(--danger-border); color:var(--danger)}
a.dl.active:hover{border-color:var(--danger)}

.bar{height:3px; background:var(--border-soft); margin:0 0 .6rem; overflow:hidden; border-radius:2px}
.bar div{height:100%; width:0; background:var(--accent); transition:width .3s ease}
#st{font-size:.8rem; color:var(--muted); margin-bottom:.7rem; font-family:var(--mono)}
#st b{color:var(--text); font-weight:600}
pre{
  background:#121418; border:1px solid var(--border); border-radius:4px;
  padding:.7rem .85rem; height:190px; overflow:auto; font-size:.76rem;
  font-family:var(--mono); color:#9aa0a8; margin:0;
}
</style>

<header>
  <h1>BlockScraper</h1>
  <p>Resolve IPv4 / IPv6 blocks to their in-use addresses, then compile RIPE, domain, Shodan and
  DNS data into clean text reports. Passive by default &mdash; nothing is sent to your addresses
  unless you turn on the active check at the bottom.</p>
  <p class=by>by Jari van der Werf</p>
</header>

<section class=group>
  <h2>Target blocks</h2>
  <div class=field>
    <textarea id=blocks placeholder="192.0.2.0/28&#10;2001:db8::/124&#10;192.0.2.1-192.0.2.20"></textarea>
    <span class=desc>One block per line &mdash; CIDR (<code>192.0.2.0/28</code>, <code>2001:db8::/120</code>)
    or a range (<code>192.0.2.1-192.0.2.20</code>). Only scan blocks you own or are authorised to assess.</span>
  </div>
</section>

<section class="group core">
  <h2>Reverse DNS &amp; in-use detection</h2>
  <p class=lead>How addresses are found to be in use. Always runs. All of this only reads DNS &mdash;
  no packet is sent to the addresses themselves.</p>
  <div class=row>
    <div class=field>
      <label for=max>Enumerate blocks up to</label>
      <input id=max type=number value=4096 min=1 max=65536>
      <span class=desc>Addresses per block checked one-by-one. Bigger blocks (e.g. an IPv6 /48) use the
      reverse-DNS tree walk instead.</span>
    </div>
    <div class=field>
      <label for=maxq>DNS query budget (tree walk)</label>
      <input id=maxq type=number value=100000 min=100 max=2000000>
      <span class=desc>Upper limit on DNS queries spent exploring an over-sized block.</span>
    </div>
  </div>
  <div class=check>
    <input id=ptr type=checkbox checked>
    <div><span class=t>Skip addresses without a reverse-DNS record</span>
      <span class=desc>Treats an address with no PTR record as not in use. Turn off to keep every address.</span></div>
  </div>
  <div class=check>
    <input id=nmapchk type=checkbox>
    <div><span class=t>Cross-check with <code>nmap -sL</code> (list scan)</span>
      <span class=desc>Runs nmap's own reverse-DNS resolver over the enumerated addresses as a second
      opinion. <code>-sL</code> sends no packets to the targets &mdash; it only resolves and lists. Needs
      nmap installed; over-sized blocks still use the tree walk. Written to <code>nmap_report.txt</code>.</span></div>
  </div>
</section>

<section class="group passive">
  <h2>Passive enrichment <span style="text-transform:none;font-weight:400;letter-spacing:0;color:var(--muted)">(optional)</span></h2>
  <p class=lead>Read-only lookups of data these services already hold. Nothing here contacts your hosts.</p>

  <div class=sub>Open ports, services &amp; CVEs &mdash; Shodan</div>
  <div class=check>
    <input id=idb type=checkbox>
    <div><span class=t>InternetDB &mdash; open ports &amp; known CVEs</span>
      <span class=desc>Shodan's free, keyless lookup of its own existing data. No account required.</span></div>
  </div>
  <div class=field>
    <label for=shodankey>Shodan API key</label>
    <input id=shodankey type=password placeholder="leave empty to skip">
    <span class=desc>Optional, paid plans only. Adds banners, organisation, ISP and TLS detail on top of
    InternetDB. Used only for this run, never stored. &rarr; <code>shodan_report.txt</code></span>
  </div>

  <div class=sub>Extra hostname discovery</div>
  <div class=check>
    <input id=ct type=checkbox>
    <div><span class=t>Certificate transparency (crt.sh)</span>
      <span class=desc>Looks up each domain on crt.sh and resolves the certificate hostnames through
      public resolvers. Any that land inside your blocks are added to the run, even without a PTR record;
      anything outside your blocks is ignored.</span></div>
  </div>
  <div class=field>
    <label for=ddkey>DNSDumpster API key</label>
    <input id=ddkey type=password placeholder="leave empty to skip">
    <span class=desc>Free key from dnsdumpster.com/developer/. Pulls A/CNAME/MX/NS/TXT records, each
    resolved IP's ASN/netblock, and any on-file banner data. Hosts that resolve inside your blocks are
    added to the run, like the crt.sh results. &rarr; <code>dnsdumpster_report.txt</code></span>
  </div>

  <p class=note><b>All passive.</b> Reverse DNS, RIPE/registry WHOIS, InternetDB/Shodan, crt.sh and
  DNSDumpster only query third-party records &mdash; no address or domain in your blocks is ever
  contacted directly.</p>
</section>

<section class="group danger">
  <h2>Active check <span class=badge>sends traffic</span></h2>
  <p class=lead>The one option that connects directly to your hosts. Off by default.</p>
  <div class=check>
    <input id=probe type=checkbox>
    <div><span class=t>HTTP liveness probe &mdash; see which hostnames serve a website</span>
      <span class=desc><b>This is an active scan.</b> It opens a direct connection to each discovered
      hostname (HTTPS, then HTTP) and records the status returned. These requests reach the targets and
      appear in their web-server logs with this machine's IP address. Only enable it for hosts you own or
      are authorised to test. Results stay in their own file (<code>live_hosts.txt</code>), never mixed
      into the other reports.</span></div>
  </div>
</section>

<div class=actions>
  <button id=go onclick=start()>Run scan</button>
</div>

<div class=bar><div id=b></div></div>
<div id=st>Idle</div>

<div id=downloads style="display:none">
  <div class=dlhead>Reports</div>
  <div class=dlgrid>
    <a id=dlc class="dl primary" href=/download_combined style="display:none">Combined report</a>
    <a id=dl class=dl href=/download style="display:none">RIPE / domain</a>
    <a id=dls class=dl href=/download_shodan style="display:none">Shodan / InternetDB</a>
    <a id=dld class=dl href=/download_dnsdumpster style="display:none">DNSDumpster</a>
    <a id=dlh class=dl href=/download_hostmap style="display:none">Domains &amp; subdomains</a>
    <a id=dln class=dl href=/download_nmap style="display:none">nmap -sL</a>
    <a id=dlp class="dl active" href=/download_probe style="display:none">Live hosts (active)</a>
  </div>
</div>

<pre id=log></pre>

<script>
async function start(){
  const r=await fetch('/start',{method:'POST',body:JSON.stringify({
    blocks:blocks.value,max:+max.value,maxq:+maxq.value,ptr:ptr.checked,
    internetdb:idb.checked,shodan_key:shodankey.value,dnsdumpster_key:ddkey.value,
    ct:ct.checked,probe:probe.checked,nmap:nmapchk.checked})});
  if(!r.ok){alert(await r.text());return}
  for(const id of ['dlc','dl','dls','dld','dlh','dln','dlp']) document.getElementById(id).style.display='none';
  downloads.style.display='none';
  poll();
}
function show(id){document.getElementById(id).style.display='inline-block'; downloads.style.display='block';}
async function poll(){
  const s=await (await fetch('/status')).json();
  b.style.width=(s.total?100*s.done/s.total:0)+'%';
  st.innerHTML=s.phase+' &mdash; <b>'+s.done+' / '+s.total+'</b> checked, <b>'+s.used+'</b> in use';
  log.textContent=s.log.join('\\n');log.scrollTop=log.scrollHeight;
  go.disabled=s.running;
  if(s.running){setTimeout(poll,1000);return}
  if(s.has_result)show('dl');
  if(s.has_shodan_result)show('dls');
  if(s.has_dnsdumpster_result)show('dld');
  if(s.has_combined_result)show('dlc');
  if(s.has_hostmap_result)show('dlh');
  if(s.has_nmap_result)show('dln');
  if(s.has_probe_result)show('dlp');
}
poll();
</script>"""


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def send(self, code, body, ctype="text/plain; charset=utf-8", extra=None):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/":
            self.send(200, PAGE, "text/html; charset=utf-8")
        elif self.path == "/status":
            with lock:
                s = dict(state, has_result=bool(state["result"]),
                         has_shodan_result=bool(state["shodan_result"]),
                         has_dnsdumpster_result=bool(state["dnsdumpster_result"]),
                         has_combined_result=bool(state["combined_result"]),
                         has_probe_result=bool(state["probe_result"]),
                         has_nmap_result=bool(state["nmap_result"]),
                         has_hostmap_result=bool(state["hostmap_result"]))
                s.pop("result")
                s.pop("shodan_result")
                s.pop("dnsdumpster_result")
                s.pop("combined_result")
                s.pop("probe_result")
                s.pop("nmap_result")
                s.pop("hostmap_result")
            self.send(200, json.dumps(s), "application/json")
        elif self.path == "/download":
            with lock:
                res = state["result"]
            self.send(200, res, "text/plain; charset=utf-8",
                      {"Content-Disposition": 'attachment; filename="ip_whois_report.txt"'})
        elif self.path == "/download_shodan":
            with lock:
                res = state["shodan_result"]
            self.send(200, res, "text/plain; charset=utf-8",
                      {"Content-Disposition": 'attachment; filename="shodan_report.txt"'})
        elif self.path == "/download_dnsdumpster":
            with lock:
                res = state["dnsdumpster_result"]
            self.send(200, res, "text/plain; charset=utf-8",
                      {"Content-Disposition": 'attachment; filename="dnsdumpster_report.txt"'})
        elif self.path == "/download_combined":
            with lock:
                res = state["combined_result"]
            self.send(200, res, "text/plain; charset=utf-8",
                      {"Content-Disposition": 'attachment; filename="combined_report.txt"'})
        elif self.path == "/download_probe":
            with lock:
                res = state["probe_result"]
            self.send(200, res, "text/plain; charset=utf-8",
                      {"Content-Disposition": 'attachment; filename="live_hosts.txt"'})
        elif self.path == "/download_nmap":
            with lock:
                res = state["nmap_result"]
            self.send(200, res, "text/plain; charset=utf-8",
                      {"Content-Disposition": 'attachment; filename="nmap_report.txt"'})
        elif self.path == "/download_hostmap":
            with lock:
                res = state["hostmap_result"]
            self.send(200, res, "text/plain; charset=utf-8",
                      {"Content-Disposition": 'attachment; filename="domains_subdomains.txt"'})
        else:
            self.send(404, "not found")

    def do_POST(self):
        if self.path != "/start":
            return self.send(404, "not found")
        n = int(self.headers.get("Content-Length", 0))
        d = json.loads(self.rfile.read(n) or b"{}")
        with lock:
            if state["running"]:
                return self.send(409, "A run is already in progress")
            if not d.get("blocks", "").strip():
                return self.send(400, "Enter at least one IP block")
            state.update(running=True, log=[], result="", shodan_result="",
                         dnsdumpster_result="", combined_result="", probe_result="",
                         nmap_result="", hostmap_result="", phase="Starting")
        threading.Thread(target=worker, daemon=True, args=(
            d["blocks"], max(1, min(int(d.get("max", 4096)), 65536)), bool(d.get("ptr", True)),
            max(100, min(int(d.get("maxq", 100000)), 2000000)),
            (d.get("shodan_key") or "").strip(), bool(d.get("internetdb", False)),
            (d.get("dnsdumpster_key") or "").strip(), bool(d.get("ct", False)),
            bool(d.get("probe", False)), bool(d.get("nmap", False)))).start()
        self.send(200, "ok")


BANNER = r"""
   ____  __    ____  ________ __
  / __ )/ /   / __ \/ ____/ //_/
 / __  / /   / / / / /   / ,<
/ /_/ / /___/ /_/ / /___/ /| |
/_____/_____/\____/\____/_/ |_|_  __________
  / ___// ____/ __ \/   |  / __ \/ ____/ __ \
  \__ \/ /   / /_/ / /| | / /_/ / __/ / /_/ /
 ___/ / /___/ _, _/ ___ |/ ____/ /___/ _, _/
/____/\____/_/ |_/_/  |_/_/   /_____/_/ |_|
                 by Jari van der Werf
"""

if __name__ == "__main__":
    print(BANNER)
    print(f"Open http://localhost:{PORT}  (Ctrl+C to stop)")
    ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
