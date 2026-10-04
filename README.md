# IP WHOIS Collector

**Author:** Jari van der Werf

A small, self-contained local web tool for turning a list of IPv4/IPv6 blocks
into a readable report: which addresses are actually in use, who they're
registered to, which domains point at them, and — optionally — what's
running on them according to public passive-recon services.

It's a single Python file with **no third-party dependencies** (standard
library only) and runs entirely on your own machine. Nothing is uploaded
anywhere except the lookups described below, each of which is passive —
the tool never scans, probes, or sends a packet to an address in your
input blocks itself (see [How it works](#how-it-works) for the full
breakdown of what talks to what).

## What it does

1. **Parses your IP blocks** — CIDR notation (`192.0.2.0/28`,
   `2001:db8::/120`) or an explicit range (`192.0.2.1-192.0.2.20`), one
   per line.
2. **Finds which addresses are in use** by checking reverse DNS (PTR
   records) for each one, in parallel. An address with no PTR record is
   treated as not in use (this can be turned off).
3. **Looks up each in-use address at RIPE NCC** (`whois.ripe.net`), the
   regional registry for Europe/the Middle East, to find its network,
   organisation and country. Addresses in the same registered block
   share one lookup.
4. **Looks up the domain of each address's hostname**:
   - `.nl` domains → SIDN (`whois.domain-registry.nl`)
   - every other TLD → that registry's own WHOIS server (found via
     IANA), plus the registrar's WHOIS if the registry refers to one,
     with an RDAP fallback if WHOIS keeps rate-limiting
5. **Optionally checks InternetDB and/or Shodan** for open ports, known
   CVEs, and (with a paid Shodan key) service banners — see
   [Shodan / InternetDB](#shodan--internetdb-optional) below.
6. **Optionally checks DNSDumpster** for each domain's DNS records,
   resolved IPs' ASN/netblock, and any on-file banner data — see
   [DNSDumpster](#dnsdumpster-optional) below.
7. **Writes everything to plain-text report files**, each downloadable
   from the page once the run finishes.

Addresses too large to check one by one (anything above the configured
limit, e.g. an IPv6 `/48` or a large IPv4 block) are instead **walked
through the reverse-DNS tree** — querying DNS one prefix level at a time
and pruning branches that come back `NXDOMAIN` — rather than skipped.
See [Large blocks](#large-blocks) below.

## Why "passive" matters here

Every lookup this tool makes asks a **third party's existing records**
about an address or domain — it never connects to, probes, or sends
traffic to any address in your input blocks itself. Concretely:

| Step | Talks to | Never talks to |
|---|---|---|
| Reverse DNS / tree walk | your DNS resolver, or 1.1.1.1 / 9.9.9.9 / 8.8.8.8 | the address being looked up |
| RIPE / SIDN / registry WHOIS | the registry's WHOIS server (port 43) | the address or domain itself |
| InternetDB / Shodan | `internetdb.shodan.io` / `api.shodan.io` | the address itself |
| DNSDumpster | `api.dnsdumpster.com` | the domain or its IPs |

If you need to know whether a host is actually responding right now —
something no passive database can tell you — that's a different kind of
tool (an active port scanner such as `nmap`), and a fundamentally more
intrusive one, since it does send packets to each target. This tool
intentionally doesn't do that.

**Only scan or look up blocks you own or are authorised to assess.**
Even though every lookup here is passive, compiling detailed
infrastructure data about a network you don't control can still be
inappropriate or against the terms of the services involved.

## Requirements

- Python 3.8 or later
- No pip packages — everything is in the standard library
- Outbound network access to: your configured DNS resolver, `1.1.1.1`,
  `9.9.9.9`, `8.8.8.8` (UDP port 53), `whois.ripe.net`,
  `whois.domain-registry.nl`, `whois.iana.org`, and, if you enable them,
  `internetdb.shodan.io`, `api.shodan.io`, `api.dnsdumpster.com` and
  `rdap.org` (all over HTTPS, except the WHOIS servers which use the
  WHOIS protocol over TCP port 43)

## Usage

```bash
python3 ip_whois_tool.py
```

Then open **http://localhost:8765** in your browser. The tool is a tiny
HTTP server bound to `127.0.0.1` — it isn't exposed to your network and
isn't meant to be.

1. Paste your IP blocks into the text box, one per line.
2. Adjust the scan settings if needed (defaults are sensible for most
   cases — see below).
3. Optionally fill in an InternetDB checkbox and/or a Shodan /
   DNSDumpster API key.
4. Click **Run**. Progress, including which phase it's on and a live
   log, shows below the button.
5. Download links appear as each report finishes. The **combined
   report** is the one to read first.

Stop the server with `Ctrl+C` in the terminal.

### Scan settings

| Setting | Default | What it does |
|---|---|---|
| Enumerate blocks up to this size | 4096 | Blocks at or under this many addresses are checked one by one. Larger blocks are walked via reverse DNS instead (see below). Max 65536. |
| DNS query budget for tree-walked blocks | 100000 | Upper limit on DNS queries spent exploring a block too large to enumerate. Raise it for very large or sparsely-documented blocks; the report says plainly if it was hit before finishing. |
| Skip addresses without reverse DNS | on | Treats an address with no PTR record as not in use. Turn this off to also look up every address even without a hostname (slower, and most whois/Shodan lookups will simply come back empty for those). |

## Shodan / InternetDB (optional)

Both are **read-only lookups of data Shodan already collected on its
own** — neither one ever triggers a new scan of anything.

- **InternetDB** (`internetdb.shodan.io`) is free and needs no account or
  API key at all. Tick the checkbox to enable it. It returns open ports,
  hostnames, CPE software/hardware guesses, and known CVEs.
- **Shodan's full host API** (`api.shodan.io/shodan/host/{ip}`) needs a
  **paid** Shodan plan (Freelancer tier or higher) or purchased query
  credits — a free API key only grants `/api-info`, not host lookups,
  and the tool detects this up front and tells you plainly rather than
  failing silently on every address. With a paid key, it adds banners,
  organisation, ISP, and TLS certificate detail on top of InternetDB.

Results from both go to **`shodan_report.txt`**.

## DNSDumpster (optional)

Needs a free API key from
[dnsdumpster.com/developer](https://dnsdumpster.com/developer/). Enter
it in the field provided to enable this step.

For each unique domain found in reverse DNS, it queries
`api.dnsdumpster.com/domain/{domain}` for A/CNAME/MX/NS/TXT records, the
ASN/netblock/country of every resolved IP, and any banner data
DNSDumpster already has on file. The API enforces one request every two
seconds; the tool respects that and backs off further on a 429.

The free tier caps results at 50 records per domain and only supports
domain-based lookup — the IP/CIDR "banners" endpoint needs their paid
Plus tier, so this tool only ever uses the domain endpoint.

Results go to **`dnsdumpster_report.txt`**.

## Large blocks

A block above the "enumerate up to" size (an IPv6 `/48`, for instance,
has roughly 1.2 × 10²⁴ addresses — far too many to check one at a time)
is explored differently: the tool walks the reverse-DNS tree
(`ip6.arpa` / `in-addr.arpa`), querying one prefix level at a time. Per
[RFC 8020](https://www.rfc-editor.org/rfc/rfc8020), an `NXDOMAIN`
response means nothing exists below that prefix, so empty branches are
pruned immediately and only branches that actually contain records are
followed. This keeps a mostly-empty block cheap to explore.

For IPv6 blocks between a `/48` and your enumeration limit, the tool
also asks RIPE which sub-blocks are actually registered underneath, and
explores those first — so results show up even if the DNS query budget
runs out before the whole block is covered.

**Limitations of this approach:**
- Only addresses with a PTR record are found this way — a live host
  with no reverse DNS is invisible to it, same as with small blocks.
- A provider that auto-generates a PTR record for every address in a
  huge range can exhaust the query budget quickly; the report says so
  if this happens.
- If every DNS query fails, that usually means outbound UDP port 53 is
  blocked on your network (a firewall, VPN, or restrictive router) — the
  report flags this explicitly rather than reporting a suspiciously
  empty block.

## Output files

| File | Always written? | Contents |
|---|---|---|
| `combined_report.txt` | if any addresses are in use | **Start here.** One digest entry per in-use address, merging RIPE, domain, InternetDB, Shodan and DNSDumpster data. Addresses with detected open ports/services are grouped together at the top. |
| `ip_whois_report.txt` | always | Full RIPE WHOIS and domain WHOIS/SIDN detail, plus an overview table. |
| `shodan_report.txt` | if InternetDB or Shodan was enabled | Full InternetDB and/or Shodan records per address. |
| `dnsdumpster_report.txt` | if a DNSDumpster key was given | Full DNSDumpster record per domain. |

All files are plain text, written with aligned fields and wrapped lines
for readability, and are generated fresh on each run (nothing is
appended across runs).

## How it works

Everything lives in one file, `ip_whois_tool.py`:

- A minimal `http.server`-based web app serves the page and handles
  three things: starting a run (`POST /start`), polling progress
  (`GET /status`), and downloading the finished reports
  (`GET /download*`).
- The actual work runs in a background thread (`worker()`), so the page
  can poll progress without blocking, and reports are built once
  everything finishes.
- Each data source — reverse DNS, the tree walk, RIPE, domain
  WHOIS/RDAP, InternetDB, Shodan, DNSDumpster — is its own set of
  functions, called in sequence, each gated by whether it's relevant or
  was enabled for that run.
- State (progress, logs, finished reports) lives in a single
  dictionary, guarded by a lock, and is cleared at the start of each run.

There's no database, no config file, and nothing persists between runs
other than what's in the downloaded report files themselves.

## Known limitations

- **Passive-only by design** (see above) — it reflects what's already
  documented about an address, not what's live right now. A host with
  no reverse DNS, no WHOIS footprint, and nothing in Shodan's or
  DNSDumpster's index is invisible to every source this tool uses.
- **Domain extraction is best-effort.** The domain for an address comes
  from its PTR hostname (e.g. `mail.example.com` → `example.com`).
  Common two-part endings like `.co.uk` are handled, but unusual ones
  may be cut incorrectly, and a single large host (e.g.
  `x.amazonaws.com`) will only be looked up once, not per customer.
- **Rate limits are real.** SIDN, DNSDumpster and Shodan all throttle;
  the tool paces requests and backs off on a 429, but a large run with
  many unique domains can still take a while.
- **Single run at a time.** Starting a new run while one is in progress
  is refused until the current one finishes.
- **Local only.** The server binds to `127.0.0.1` and has no
  authentication — it's meant to run on your own machine, not be
  exposed to a network.

## License

Add whichever license you prefer for your repository (MIT is a common
default for a tool like this). None is bundled by default.

## Author

Jari van der Werf
