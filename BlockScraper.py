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
Everything else ends up in one text file (ip_whois_report.txt).
Uses only the Python standard library.
"""
import ipaddress
import json
import bisect
import random
import re
import socket
import struct
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

state = {"running": False, "log": [], "done": 0, "total": 0, "used": 0,
         "phase": "Idle", "result": "", "shodan_result": "", "dnsdumpster_result": "",
         "combined_result": ""}
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
    qname = b"".join(bytes([len(l)]) + l.encode() for l in name.split(".")) + b"\x00"
    start = random.randrange(len(DNS_SERVERS))
    for attempt in range(min(4, len(DNS_SERVERS))):
        server = DNS_SERVERS[(start + attempt) % len(DNS_SERVERS)]
        qid = random.randrange(65536)
        pkt = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0) + qname + struct.pack(">HH", 12, 1)
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
            off, ptrs = 12, []
            for _ in range(qd):
                _, off = _read_name(data, off)
                off += 4
            for _ in range(an):
                _, off = _read_name(data, off)
                rtype, _, _, rdlen = struct.unpack(">HHIH", data[off:off + 10])
                off += 10
                if rtype == 12:
                    ptrs.append(_read_name(data, off)[0])
                off += rdlen
            return rcode, ptrs
        except (IndexError, struct.error):
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


def build_report(checked, notes, block_info, in_use, ptrs, ripe_text, domains, sidn):
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
           f"  In use      : {len(in_use)}  (have a reverse-DNS record)",
           f"  Networks    : {len(nets)}  (RIPE NCC whois)",
           f"  Domains     : {len(domains)}  (SIDN for .nl, registry whois for others)"]
    for i, c in enumerate(checked):
        out.append(("  Checked     : " if i == 0 else "                ") + c)
    for n in notes:
        out.append(textwrap.fill("WARNING: " + n, WIDTH, initial_indent="  ", subsequent_indent="           "))
    out += ["", "  Sections:  1. Overview   2. Networks   3. Domains"
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
        host = ptrs.get(ip)
        d = nl_domain(host)
        rows.append([str(ip), trunc(host or "-", 38),
                     f"#{net_no[key]} {trunc(first_field(txt, 'netname') or '-', 18)}",
                     trunc(first_field(txt, "org-name") or first_field(txt, "descr") or "-", 28),
                     f"#{dom_no[d]} {d}" if d else "-"])
    out += table(["IP", "REVERSE DNS", "NETWORK", "ORGANISATION", "DOMAIN"], rows)

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
        out.append("  Seen on: " + ", ".join(f"{ip} ({ptrs.get(ip)})" for ip in dips))
        out.append("  " + "." * 60)
        out.append(render_whois(dtxt))
        out += ["", THIN, ""]
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


def run_dnsdumpster(key, domains, notes):
    """One lookup per unique domain name (the same domains gathered from reverse-DNS
    hostnames for the SIDN/registry whois step). Returns {domain: {"text": str|None, "error": str|None}}"""
    out = {}
    for i, d in enumerate(domains, 1):
        throttle(DNSDUMPSTER_HOST)
        code, body = dnsdumpster_api(f"/domain/{d}", key)
        if code == 429:
            penalize(DNSDUMPSTER_HOST, 10)
            throttle(DNSDUMPSTER_HOST)
            code, body = dnsdumpster_api(f"/domain/{d}", key)
        if code == 200:
            out[d] = {"text": format_dnsdumpster(body), "error": None}
        else:
            out[d] = {"text": None, "error": dnsdumpster_err(code, body)}
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


def build_combined_report(notes, in_use, ptrs, ripe_text, domains, sidn,
                           internetdb, shodan, dnsdumpster,
                           use_internetdb, shodan_key, dnsdumpster_key):
    """One file that pulls together, per address, everything gathered from every
    source used in this run (RIPE, domain whois/SIDN, InternetDB, Shodan, DNSDumpster).
    Full raw records stay in the other report files; this is the readable digest."""
    full_by_ip = {str(ip): txt for ip, (kind, txt) in ripe_text.items() if kind == "full"}

    def ripe_text_for(ip):
        kind, val = ripe_text.get(ip, (None, None))
        return val if kind == "full" else full_by_ip.get(val, "")

    ip_to_domain = {ip: d for d, ips in domains.items() for ip in ips}

    def combined_vulns(ip):
        vulns = set()
        for src in (internetdb.get(ip), shodan.get(ip)):
            if src and src.get("text"):
                line = (grab_line(src["text"], "Known vulnerabilities (CVEs)") or
                        grab_line(src["text"], "Vulnerabilities"))
                vulns |= {v.strip() for v in line.split(",") if v.strip()}
        return sorted(vulns)

    out = [BAR, "  COMBINED REPORT - everything gathered, per address", BAR,
           f"  Generated     : {datetime.now():%Y-%m-%d %H:%M:%S}",
           f"  Addresses     : {len(in_use)} in use",
           f"  Domains       : {len(domains)}",
           f"  InternetDB    : {'enabled' if use_internetdb else 'not enabled this run'}",
           f"  Shodan        : {'key provided' if shodan_key else 'not enabled this run'}",
           f"  DNSDumpster   : {'key provided' if dnsdumpster_key else 'not enabled this run'}",
           "", "  This file merges every source into one per-address digest. Full raw records",
           "  stay in ip_whois_report.txt, shodan_report.txt and dnsdumpster_report.txt."]
    if notes:
        out += ["", "  Warnings from this run:"]
        for n in notes:
            out.append(textwrap.fill("    - " + n, WIDTH, subsequent_indent="      "))
    out.append("")

    if not in_use:
        out.append("  No addresses in use were found.")
        out.append("")
        out.append("  End of report.")
        return "\n".join(out) + "\n"

    def ports_for(ip):
        ports, sources = set(), []
        for label, store in (("InternetDB", internetdb), ("Shodan", shodan)):
            info = store.get(ip)
            if info and info.get("ports"):
                ports |= set(info["ports"])
                sources.append(label)
        return sorted(ports), sources

    def render_ip_block(ip):
        host = ptrs.get(ip)
        blk = [BAR, f"  {ip}" + (f"  ({host})" if host else "  (no reverse DNS)"), BAR]

        txt = ripe_text_for(ip)
        net_bits = [x for x in (first_field(txt, "netname"),
                                 first_field(txt, "org-name") or first_field(txt, "descr"),
                                 first_field(txt, "country")) if x]
        blk.append(f"  Network      : {' / '.join(net_bits) if net_bits else '(no RIPE record)'}")

        d = ip_to_domain.get(ip)
        if d:
            src, dtxt = sidn.get(d, ("", ""))
            dom_bits = [x for x in (first_field(dtxt, "status", "domain status"),
                                     first_field(dtxt, "registrar", "sponsoring registrar")) if x]
            blk.append(f"  Domain       : {d}" + (f"  ({', '.join(dom_bits)})" if dom_bits else "")
                      + (f"  [{src}]" if src else "  [lookup failed]"))
            if d in dnsdumpster:
                dd = dnsdumpster[d]
                if dd.get("text"):
                    m = re.search(r"A records \((\d+)\)", dd["text"])
                    blk.append(f"  DNS records  : {m.group(1) + ' A record(s), ' if m else ''}"
                              f"see dnsdumpster_report.txt for {d}")
                else:
                    blk.append(f"  DNS records  : {dd.get('error', 'not checked')}")
        else:
            blk.append("  Domain       : (none found in reverse DNS)")

        ports, sources = ports_for(ip)
        if ports:
            blk.append(f"  Open ports   : {', '.join(str(p) for p in ports)}  "
                       f"[{' + '.join(sources)}]")
        elif use_internetdb or shodan_key:
            errs = [store[ip]["error"] for store in (internetdb, shodan)
                    if ip in store and store[ip].get("error")]
            blk.append(f"  Open ports   : {errs[0] if errs else 'none found'}")

        services = (shodan.get(ip) or {}).get("services") or []
        if services:
            blk.append("  Services     : " + "; ".join(
                f"{s['port']}/{s['transport']} {s['product'] or '(unidentified)'}" for s in services))
        cpes = (internetdb.get(ip) or {}).get("cpes") or []
        if cpes:
            blk.append(f"  Software     : {', '.join(cpes)}  [InternetDB CPE guesses]")

        vulns = combined_vulns(ip)
        if vulns:
            blk.append(f"  Known CVEs   : {', '.join(vulns)}")

        org = grab_line((shodan.get(ip) or {}).get("text", ""), "Organisation")
        isp = grab_line((shodan.get(ip) or {}).get("text", ""), "ISP")
        if org or isp:
            blk.append(f"  Shodan org   : {', '.join(x for x in (org, isp) if x)}")

        blk.append("")
        return blk

    with_services = [ip for ip in in_use if ports_for(ip)[0]]
    without_services = [ip for ip in in_use if ip not in with_services]

    if with_services and (use_internetdb or shodan_key):
        out += section(f"ADDRESSES WITH DETECTED SERVICES ({len(with_services)})")
        for ip in with_services:
            out += render_ip_block(ip)
        if without_services:
            out += section(f"REMAINING ADDRESSES - no open ports found ({len(without_services)})")
        for ip in without_services:
            out += render_ip_block(ip)
    else:
        for ip in in_use:
            out += render_ip_block(ip)

    out.append("  End of report.")
    return "\n".join(out) + "\n"


def worker(blocks_text, max_addrs, require_ptr, max_queries, shodan_key="", use_internetdb=False,
           dnsdumpster_key=""):
    NP = 3 + (1 if (use_internetdb or shodan_key) else 0) + (1 if dnsdumpster_key else 0)
    try:
        ips, walk_nets, errors = parse_blocks(blocks_text, max_addrs)
        for e in errors:
            log("SKIPPED INPUT: " + e)
        notes = [f"Input skipped: {e}" for e in errors]
        set_state(done=0, total=len(ips), used=0, result="", phase=f"1/{NP} Checking reverse DNS")

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
            set_state(phase=f"1/{NP} Walking reverse-DNS tree", done=0, total=max_queries)
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

        # ---- phase 2: RIPE lookups, one per registered block
        set_state(phase=f"2/{NP} RIPE WHOIS", done=0, total=len(in_use))
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
            d = nl_domain(ptrs.get(ip))
            if d:
                domains.setdefault(d, []).append(ip)
        set_state(phase=f"3/{NP} Domain lookups", done=0, total=len(domains))
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
                set_state(phase=f"4/{NP} InternetDB lookup", done=0, total=len(in_use))
                internetdb = run_internetdb(in_use)
            if shodan_key:
                set_state(phase=f"4/{NP} Shodan lookup", done=0, total=len(in_use))
                shodan = run_shodan(shodan_key, in_use, notes)

        # ---- phase 5 (optional): DNSDumpster, one lookup per unique domain
        dnsdumpster = {}
        if domains and dnsdumpster_key:
            dd_phase = 4 + (1 if (use_internetdb or shodan_key) else 0)
            set_state(phase=f"{dd_phase}/{NP} DNSDumpster lookup", done=0, total=len(domains))
            dnsdumpster = run_dnsdumpster(dnsdumpster_key, domains, notes)

        # ---- build reports
        report = build_report(checked, notes, block_info, in_use, ptrs, ripe_text, domains, sidn)
        shodan_report = (build_shodan_report(in_use, ptrs, internetdb, shodan)
                          if in_use and (use_internetdb or shodan_key) else "")
        dnsdumpster_report = (build_dnsdumpster_report(domains, dnsdumpster)
                               if domains and dnsdumpster_key else "")
        combined_report = build_combined_report(
            notes, in_use, ptrs, ripe_text, domains, sidn, internetdb, shodan, dnsdumpster,
            use_internetdb, shodan_key, dnsdumpster_key)
        set_state(result=report, shodan_result=shodan_report, dnsdumpster_result=dnsdumpster_report,
                  combined_result=combined_report, phase="Finished")
        log("Finished.")
    except Exception as e:  # noqa
        log(f"ERROR: {e}")
        set_state(phase="Error")
    finally:
        set_state(running=False)


PAGE = """<!doctype html><meta charset=utf-8><title>IP WHOIS Collector</title>
<meta name=viewport content="width=device-width,initial-scale=1">
<style>
:root{
  --bg:#1a1d23; --panel:#20242b; --border:#333842; --border-soft:#2a2e36;
  --text:#d6d9de; --head:#eceef1; --muted:#80868f; --accent:#4f86c6; --mono:"SF Mono",Consolas,"Liberation Mono",Menlo,monospace;
}
*{box-sizing:border-box}
body{
  font-family:"Segoe UI",Helvetica,Arial,sans-serif;
  background:var(--bg); color:var(--text); max-width:740px; margin:0 auto;
  padding:2rem 1.25rem 3rem; line-height:1.5; font-size:14px;
}
header{border-bottom:1px solid var(--border); padding-bottom:.9rem; margin-bottom:1.5rem}
h1{font-size:1.05rem; font-weight:600; color:var(--head); margin:0 0 .25rem; letter-spacing:0}
header p{color:var(--muted); font-size:.82rem; margin:0}
section{margin-bottom:1.4rem}
section > h2{
  font-size:.7rem; font-weight:600; letter-spacing:.07em; text-transform:uppercase;
  color:var(--muted); margin:0 0 .7rem; padding-bottom:.45rem; border-bottom:1px solid var(--border-soft);
}
.field{margin:.8rem 0}
.field:first-child{margin-top:0}
.field > label{display:block; font-size:.85rem; color:var(--text); margin-bottom:.3rem}
.field .desc{display:block; font-size:.78rem; color:var(--muted); margin-top:.3rem}
.check{display:flex; align-items:flex-start; gap:.5rem; margin:.7rem 0}
.check input{margin-top:.2rem}
.check .t{font-size:.85rem; color:var(--text)}
.check .desc{display:block; font-size:.78rem; color:var(--muted); margin-top:.15rem}
textarea,input[type=number],input[type=password],input[type=text]{
  width:100%; background:#14161b; color:var(--text); border:1px solid var(--border);
  border-radius:3px; padding:.5rem .6rem; font-family:var(--mono); font-size:.83rem;
}
textarea{height:120px; resize:vertical}
textarea:focus,input:focus{outline:none; border-color:var(--accent)}
input[type=number]{width:8rem}
input[type=checkbox]{width:14px; height:14px; accent-color:var(--accent); cursor:pointer}
code{background:#14161b; border:1px solid var(--border-soft); border-radius:3px;
  padding:.05rem .3rem; font-size:.85em; color:var(--text)}
.actions{display:flex; align-items:center; gap:.7rem; flex-wrap:wrap; margin:1.4rem 0 1rem}
button{
  background:var(--accent); color:#fff; border:1px solid var(--accent);
  padding:.45rem 1.1rem; font-size:.85rem; font-weight:600; border-radius:3px; cursor:pointer;
}
button:hover:not(:disabled){background:#5c93d1}
button:disabled{opacity:.4; cursor:not-allowed}
a.dl{
  color:var(--text); text-decoration:none; font-size:.82rem;
  border:1px solid var(--border); padding:.44rem .9rem; border-radius:3px; background:var(--panel);
}
a.dl:hover{border-color:var(--accent); color:var(--accent)}
.bar{height:3px; background:var(--border-soft); margin:0 0 .6rem; overflow:hidden}
.bar div{height:100%; width:0; background:var(--accent)}
#st{font-size:.8rem; color:var(--muted); margin-bottom:.7rem; font-family:var(--mono)}
#st b{color:var(--text); font-weight:600}
pre{
  background:#121418; border:1px solid var(--border); border-radius:3px;
  padding:.7rem .85rem; height:200px; overflow:auto; font-size:.76rem;
  font-family:var(--mono); color:#9aa0a8; margin:0;
}
hr.sep{border:none; border-top:1px solid var(--border-soft); margin:1rem 0}
</style>

<header>
  <h1>IP WHOIS Collector</h1>
  <p>Resolve IPv4/IPv6 blocks to in-use addresses and compile RIPE, domain and Shodan data into text reports.</p>
</header>

<section>
  <h2>Input</h2>
  <div class=field>
    <label for=blocks>IP blocks</label>
    <textarea id=blocks placeholder="192.0.2.0/28&#10;2001:db8::/124"></textarea>
    <span class=desc>One per line. CIDR notation (<code>192.0.2.0/28</code>, <code>2001:db8::/120</code>) or a range (<code>192.0.2.1-192.0.2.20</code>).</span>
  </div>
</section>

<section>
  <h2>Scan settings</h2>
  <div class=field>
    <label for=max>Enumerate blocks up to this size</label>
    <input id=max type=number value=4096 min=1 max=65536>
    <span class=desc>Larger blocks (e.g. an IPv6 /48) are explored through the reverse-DNS tree instead of checked address-by-address.</span>
  </div>
  <div class=field>
    <label for=maxq>DNS query budget for tree-walked blocks</label>
    <input id=maxq type=number value=100000 min=100 max=2000000>
  </div>
  <div class=check>
    <input id=ptr type=checkbox checked>
    <div><span class=t>Skip addresses without a reverse-DNS record</span>
      <span class=desc>Treats addresses with no PTR record as not in use.</span></div>
  </div>
</section>

<section>
  <h2>Shodan / InternetDB <span style="text-transform:none; font-weight:400">(optional)</span></h2>
  <div class=check>
    <input id=idb type=checkbox>
    <div><span class=t>Look up open ports and known CVEs via InternetDB</span>
      <span class=desc>Shodan's free, keyless lookup of its own existing data. No account required.</span></div>
  </div>
  <div class=field>
    <label for=shodankey>Shodan API key</label>
    <input id=shodankey type=password placeholder="leave empty to skip">
    <span class=desc>Optional, paid plans only. Adds banner, organisation and TLS detail on top of InternetDB.</span>
  </div>
  <hr class=sep>
  <span class=desc>Both sources are read-only: this reads data Shodan already collected and never scans or probes
  an address itself. Results are written to a separate file. The key is used only for this run and is never stored.</span>
</section>

<section>
  <h2>DNSDumpster <span style="text-transform:none; font-weight:400">(optional)</span></h2>
  <div class=field>
    <label for=ddkey>DNSDumpster API key</label>
    <input id=ddkey type=password placeholder="leave empty to skip">
    <span class=desc>Free account from dnsdumpster.com/developer/. Looks up each domain found in reverse DNS
    for its A/CNAME/MX/NS/TXT records, ASN/netblock of each resolved IP, and any banner data on file.
    Read-only, one request per unique domain, written to a separate file.</span>
  </div>
</section>

<div class=actions>
  <button id=go onclick=start()>Run</button>
  <a id=dlc class=dl href=/download_combined style="display:none;font-weight:700">Download combined report</a>
  <a id=dl class=dl href=/download style="display:none">RIPE/domain report</a>
  <a id=dls class=dl href=/download_shodan style="display:none">Shodan results</a>
  <a id=dld class=dl href=/download_dnsdumpster style="display:none">DNSDumpster results</a>
</div>

<div class=bar><div id=b></div></div>
<div id=st>Idle</div>
<pre id=log></pre>

<script>
async function start(){
  const r=await fetch('/start',{method:'POST',body:JSON.stringify({
    blocks:blocks.value,max:+max.value,maxq:+maxq.value,ptr:ptr.checked,
    internetdb:idb.checked,shodan_key:shodankey.value,dnsdumpster_key:ddkey.value})});
  if(!r.ok){alert(await r.text());return}
  dl.style.display='none';dls.style.display='none';dld.style.display='none';
  dlc.style.display='none';poll();
}
async function poll(){
  const s=await (await fetch('/status')).json();
  b.style.width=(s.total?100*s.done/s.total:0)+'%';
  st.innerHTML=s.phase+' &mdash; <b>'+s.done+' / '+s.total+'</b> checked, <b>'+s.used+'</b> in use';
  log.textContent=s.log.join('\\n');log.scrollTop=log.scrollHeight;
  go.disabled=s.running;
  if(s.running){setTimeout(poll,1000);return}
  if(s.has_result)dl.style.display='inline-block';
  if(s.has_shodan_result)dls.style.display='inline-block';
  if(s.has_dnsdumpster_result)dld.style.display='inline-block';
  if(s.has_combined_result)dlc.style.display='inline-block';
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
                         has_combined_result=bool(state["combined_result"]))
                s.pop("result")
                s.pop("shodan_result")
                s.pop("dnsdumpster_result")
                s.pop("combined_result")
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
                         dnsdumpster_result="", combined_result="", phase="Starting")
        threading.Thread(target=worker, daemon=True, args=(
            d["blocks"], max(1, min(int(d.get("max", 4096)), 65536)), bool(d.get("ptr", True)),
            max(100, min(int(d.get("maxq", 100000)), 2000000)),
            (d.get("shodan_key") or "").strip(), bool(d.get("internetdb", False)),
            (d.get("dnsdumpster_key") or "").strip())).start()
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
