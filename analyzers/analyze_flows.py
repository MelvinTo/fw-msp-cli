#!/usr/bin/env python3
"""
Flow security analyzer — supports both NDJSON and JSON {results:[]} formats.

Usage:
  python3 analyze_flows.py [file]          # defaults to flows_<today>.ndjson in /tmp
  python3 analyze_flows.py /tmp/export.json
"""
import json, sys, collections, ipaddress, datetime, os, re

DEFAULT_FILE = f"/tmp/flows_{datetime.date.today()}.ndjson"

# ── Trusted root domains (suppress noise in untrusted-domain checks) ─────────
TRUSTED_DOMAINS = {
    "apple.com", "cdn-apple.com", "icloud.com", "icloud-content.com",
    "aaplimg.com", "apple-dns.net", "me.com",
    "google.com", "googleapis.com", "gstatic.com", "youtube.com",
    "googlevideo.com", "googleusercontent.com", "google-analytics.com",
    "amazon.com", "amazonaws.com", "amazon.dev", "ring.com",
    "rings.solutions", "a2z.com",
    "slack.com", "slackb.com", "slack-edge.com",
    "microsoft.com", "office.com", "msftconnecttest.com", "live.com",
    "firewalla.com", "firewalla.net", "firewalla.org",
    "zendesk.com", "brilliant.tech",
    "netflix.com", "nflxvideo.net", "nflxso.net",
    "akamaiedge.net", "akadns.net", "cloudfront.net", "fastly.net",
    "fastly-edge.com", "edgekey.net", "cloudflare.com", "cloudinary.com",
    "digicert.com", "letsencrypt.org",
    "dropbox.com", "dropboxstatic.com", "d.dropbox.com",
    "grammarly.com", "grammarly.io",
    "chatgpt.com", "openai.com",
    "yahoo.com", "gmail.com",
    "shopify.com", "shopifycloud.com", "shopifyapps.com", "shopifysvc.com",
    "glance.net", "redditspace.com", "reddit.com", "redd.it",
    "facebook.com", "fbcdn.net", "instagram.com", "cdninstagram.com",
    "braze.com", "braze-images.com",
    "aweber.com", "aweber-static.com",
    "crashlytics.com", "doubleclick.net",
    "bankofamerica.com", "fidelity.com",
    "tubitv.com", "tubi.io",
    "datadoghq.com",
    "playstation.net", "playstation.com",
    "ubnt.com", "ui.com",
    "dns.google",
    # Well-known services
    "ntp.org", "one.one", "skype.com", "sentry.io",
    "qq.com", "baidu.com", "alipay.com",
    "taobao.com", "alicdn.com",
    "bilibili.com", "ytimg.com",
    # Chinese content/social
    "xiaohongshu.com", "xhscdn.com",
    "douyincdn.com", "amemv.com",
    "zhihu.com", "zhimg.com",
    "meituan.com", "meituan.net", "dianping.com",
    "weibo.cn", "pinduoduo.com",
    # IoT/device vendors
    "roborock.com", "smartmidea.net", "hpeprint.com",
    "synology.com", "hicloud.com",
    # Infra/tools
    "syncthing.net", "ipify.org", "schlund.de",
}

NOISE_TAGS = {"noise"}
UNUSUAL_PORT_WHITELIST = {80, 443, 53, 123, 8080, 8443, 5228, 5353, 8888, 8008}

# ── Helpers ───────────────────────────────────────────────────────────────────
def get_root_domain(domain):
    if not domain:
        return None
    parts = domain.strip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain

def is_private_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return False

def is_trusted(domain):
    rd = get_root_domain(domain)
    return rd in TRUSTED_DOMAINS if rd else False

def is_ip_address(s):
    """Return True if s looks like an IPv4 or IPv6 address (not a domain)."""
    try:
        ipaddress.ip_address(s)
        return True
    except Exception:
        return False

def redact_ips(text):
    """Replace IPv4 addresses with [x.x.x.x] and truncate IPv6 to prefix."""
    text = re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', '[x.x.x.x]', text)
    text = re.sub(r'([0-9a-fA-F]{1,4}:){3,}[0-9a-fA-F:/]+', '[ipv6]', text)
    return text

def strip_gid(rule_id):
    """Replace box GID prefix in rule IDs with [box], keeping the rule number."""
    if ':' in rule_id:
        parts = rule_id.rsplit(':', 1)
        return f"[box]:{parts[-1]}"
    return rule_id

def mb(b):
    return round(b / 1024 / 1024, 2)

def kb(b):
    return round(b / 1024, 1)

def ts_to_str(ts):
    try:
        return datetime.datetime.fromtimestamp(ts).strftime("%m-%d %H:%M")
    except Exception:
        return "?"

def hour_of(ts):
    try:
        return datetime.datetime.fromtimestamp(ts).hour
    except Exception:
        return -1

# ── Load flows (NDJSON or JSON {results:[]}) ──────────────────────────────────
def load_flows(path):
    with open(path) as f:
        first_char = f.read(1)
    with open(path) as f:
        if first_char == "[":
            return json.load(f)
        elif first_char == "{":
            # Could be a single JSON object {results:[]} or NDJSON (multiple lines)
            try:
                data = json.load(f)
                return data.get("results", [])
            except json.JSONDecodeError:
                pass  # fall through to NDJSON
        # NDJSON: one JSON object per line
        with open(path) as f:
            flows, errors = [], 0
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    flows.append(json.loads(line))
                except Exception:
                    errors += 1
            if errors:
                print(f"[warn] {errors} NDJSON parse errors", file=sys.stderr)
            return flows

# ── Main analysis (only runs when executed directly) ─────────────────────────
if __name__ == "__main__":
    FILE = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_FILE
    flows = load_flows(FILE)
    total = len(flows)

    # ── Accumulators ─────────────────────────────────────────────────────────
    blocked_flows      = []
    blocked_by_type    = collections.Counter()
    blocked_by_rule    = collections.Counter()
    blocked_domains    = collections.Counter()
    raw_ip_large       = []
    non_us             = []
    unusual_ports      = []
    high_volume        = []
    potential_beacons  = []
    ad_tracker_hits    = []
    category_counts    = collections.Counter()
    device_upload      = collections.defaultdict(int)
    device_download    = collections.defaultdict(int)
    device_flows       = collections.Counter()
    domain_bytes_map   = collections.defaultdict(int)
    domain_flow_count  = collections.Counter()
    region_bytes       = collections.defaultdict(int)
    region_flows       = collections.Counter()
    hour_flows         = collections.Counter()
    hour_bytes         = collections.defaultdict(int)
    user_upload        = collections.defaultdict(int)
    user_flows         = collections.Counter()
    protocol_counts    = collections.Counter()
    inbound_count      = 0
    outbound_count     = 0
    rare_untrusted     = collections.Counter()

    for flow in flows:
        tags       = set(flow.get("flowTags") or [])
        blocked    = flow.get("block", False)
        block_type = flow.get("blockType", "") or ""
        blocked_by = flow.get("blockedby", "") or ""
        domain     = flow.get("domain", "") or ""
        dest       = flow.get("destination", {}) or {}
        dest_ip    = dest.get("ip", "") or ""
        src        = flow.get("source", {}) or {}
        direction  = flow.get("direction", "") or ""
        upload     = flow.get("upload", 0) or 0
        download   = flow.get("download", 0) or 0
        total_b    = flow.get("total", 0) or upload + download
        region     = flow.get("region", "") or ""
        protocol   = flow.get("protocol", "") or ""
        category   = flow.get("category", "") or ""
        duration   = flow.get("duration", 0) or 0
        count      = flow.get("count", 1) or 1
        ts         = flow.get("ts", 0) or 0
        device     = flow.get("device", {}) or {}
        device_name = device.get("name", "unknown")
        user       = flow.get("user", {}) or {}
        user_name  = user.get("name", "unknown")
        port_info  = dest.get("portInfo", {}) or {}
        dest_port  = port_info.get("port", 0) or 0
        root_domain = get_root_domain(domain)
        dt_str     = ts_to_str(ts)

        # Aggregations
        device_upload[device_name]   += upload
        device_download[device_name] += download
        device_flows[device_name]    += 1
        user_upload[user_name]       += upload
        user_flows[user_name]        += 1
        protocol_counts[protocol or "unknown"] += 1
        category_counts[category or "(none)"]  += 1
        region_flows[region or "??"]           += 1
        region_bytes[region or "??"]           += total_b
        if ts:
            h = hour_of(ts)
            hour_flows[h] += 1
            hour_bytes[h] += total_b
        if root_domain:
            domain_bytes_map[root_domain] += total_b
            domain_flow_count[root_domain] += 1

        if direction == "outbound":
            outbound_count += 1
        elif direction == "inbound":
            inbound_count  += 1

        # ── Blocked flows ────────────────────────────────────────────────────
        if blocked:
            blocked_by_type[block_type or "unknown"] += 1
            if blocked_by:
                blocked_by_rule[blocked_by] += 1
            if root_domain and not is_ip_address(root_domain):
                blocked_domains[root_domain] += 1
            blocked_flows.append({
                "device": device_name, "dest": domain or dest_ip,
                "block_type": block_type, "rule": blocked_by,
                "region": region, "upload_kb": kb(upload), "dt": dt_str,
            })
            continue

        if NOISE_TAGS & tags:
            continue

        # ── Ad/tracker hits (not blocked) ────────────────────────────────────
        if category == "ad":
            ad_tracker_hits.append({
                "device": device_name, "dest": domain or dest_ip,
                "upload_kb": kb(upload), "dt": dt_str,
            })

        # ── Large upload to raw IP ───────────────────────────────────────────
        if direction == "outbound" and not domain and dest_ip and upload > 5*1024*1024:
            if not is_private_ip(dest_ip):
                raw_ip_large.append({
                    "device": device_name, "dest_ip": dest_ip,
                    "upload_mb": mb(upload), "region": region,
                    "port": dest_port, "protocol": protocol, "dt": dt_str,
                })

        # ── Non-US traffic to untrusted domains ─────────────────────────────
        if region and region not in ("US",) and not is_trusted(domain):
            if upload > 500*1024 or download > 5*1024*1024:
                non_us.append({
                    "device": device_name, "dest": domain or dest_ip,
                    "region": region, "upload_mb": mb(upload),
                    "download_mb": mb(download), "dt": dt_str,
                })

        # ── Unusual low dest port ────────────────────────────────────────────
        if dest_port and dest_port not in UNUSUAL_PORT_WHITELIST and dest_port < 1024:
            if not is_trusted(domain):
                unusual_ports.append({
                    "device": device_name, "dest": domain or dest_ip,
                    "port": dest_port, "protocol": protocol,
                    "upload_kb": kb(upload), "dt": dt_str,
                })

        # ── High-volume upload to untrusted domain (>50 MB) ─────────────────
        if upload > 50*1024*1024 and not is_trusted(domain) and direction == "outbound":
            high_volume.append({
                "device": device_name, "dest": domain or dest_ip,
                "upload_mb": mb(upload), "region": region, "dt": dt_str,
            })

        # ── Beacon/C2 pattern ────────────────────────────────────────────────
        if (direction == "outbound" and duration > 300 and total_b < 50*1024
                and count >= 5 and not is_trusted(domain)):
            potential_beacons.append({
                "device": device_name, "dest": domain or dest_ip,
                "duration_min": round(duration/60, 1), "total_kb": kb(total_b),
                "count": count, "region": region, "dt": dt_str,
            })

        # ── Rare untrusted domains with any upload ──────────────────────────
        if root_domain and not is_trusted(domain) and upload > 50*1024:
            rare_untrusted[root_domain] += 1

    # ── Output ───────────────────────────────────────────────────────────────
    def section(title, count=None):
        label = f" ({count})" if count is not None else ""
        print(f"\n{'─'*60}")
        print(f"  {title}{label}")
        print(f"{'─'*60}")

    top_uploaders   = sorted(device_upload.items(),    key=lambda x: -x[1])[:10]
    top_dl_devices  = sorted(device_download.items(),  key=lambda x: -x[1])[:10]
    top_domains_bw  = sorted(domain_bytes_map.items(), key=lambda x: -x[1])[:15]
    top_domains_cnt = sorted(domain_flow_count.items(),key=lambda x: -x[1])[:15]
    top_regions     = sorted(region_flows.items(),     key=lambda x: -x[1])[:10]

    print("=" * 60)
    print("  FIREWALLA FLOW SECURITY ANALYSIS")
    print("=" * 60)
    print(f"  File    : {FILE}")
    print(f"  Flows   : {total:,}")
    print(f"  Outbound: {outbound_count:,}  |  Inbound: {inbound_count:,}")
    print(f"  Blocked : {len(blocked_flows):,}  ({round(len(blocked_flows)/total*100,1)}%)")

    section("PROTOCOL BREAKDOWN")
    for p, c in protocol_counts.most_common():
        print(f"  {p:<8} {c:>7,} flows")

    section("TRAFFIC CATEGORIES")
    for cat, c in category_counts.most_common():
        print(f"  {cat:<20} {c:>7,} flows")

    section("TRAFFIC BY REGION (top 10)")
    for reg, c in top_regions:
        bw = region_bytes.get(reg, 0)
        print(f"  {reg or '??':<6} {c:>7,} flows  {mb(bw):>9.1f} MB")

    section("HOURLY TRAFFIC PATTERN (flows by hour)")
    peak_hour = max(hour_flows, key=hour_flows.get) if hour_flows else 0
    for h in range(24):
        c = hour_flows.get(h, 0)
        bar = "█" * (c * 40 // max(hour_flows.values(), default=1))
        marker = " ← peak" if h == peak_hour else ""
        print(f"  {h:02d}:00  {bar:<40} {c:>5}{marker}")

    section("BLOCKED FLOWS", len(blocked_flows))
    print(f"  By block type : {dict(blocked_by_type)}")
    print(f"  Top blocked domains:")
    for dom, c in blocked_domains.most_common(15):
        print(f"    {c:>5}x  {dom}")
    print(f"  Top blocking rules:")
    for rule, c in blocked_by_rule.most_common(5):
        print(f"    {c:>5}x  {strip_gid(rule)}")

    section("AD/TRACKER HITS NOT BLOCKED", len(ad_tracker_hits))
    for a in ad_tracker_hits[:15]:
        print(f"  [{a['dt']}] [{a['device']}] -> {a['dest']} | up {a['upload_kb']} KB")
    if len(ad_tracker_hits) > 15:
        print(f"  ... and {len(ad_tracker_hits)-15} more")

    section("LARGE UPLOADS TO RAW IPs (>5 MB, no domain)", len(raw_ip_large))
    for r in raw_ip_large[:20]:
        print(f"  [{r['dt']}] [{r['device']}] -> {r['dest_ip']}:{r['port']} ({r['protocol']}) | {r['upload_mb']} MB | {r['region']}")
    if len(raw_ip_large) > 20:
        print(f"  ... and {len(raw_ip_large)-20} more")

    section("NON-US TRAFFIC TO UNTRUSTED DESTINATIONS", len(non_us))
    for n in non_us[:20]:
        print(f"  [{n['dt']}] [{n['region']}] [{n['device']}] -> {n['dest']} | up {n['upload_mb']} MB / down {n['download_mb']} MB")
    if len(non_us) > 20:
        print(f"  ... and {len(non_us)-20} more")

    section("HIGH VOLUME UPLOADS TO UNTRUSTED DOMAINS (>50 MB)", len(high_volume))
    for h in high_volume[:15]:
        print(f"  [{h['dt']}] [{h['device']}] -> {h['dest']} | {h['upload_mb']} MB | {h['region']}")
    if len(high_volume) > 15:
        print(f"  ... and {len(high_volume)-15} more")

    section("POTENTIAL BEACON/C2 PATTERNS", len(potential_beacons))
    print("  (outbound, duration>5min, <50KB total, ≥5 connections, untrusted domain)")
    for b in potential_beacons[:20]:
        print(f"  [{b['dt']}] [{b['device']}] -> {b['dest']} | {b['duration_min']}min | {b['total_kb']} KB | {b['count']} conns | {b['region']}")
    if len(potential_beacons) > 20:
        print(f"  ... and {len(potential_beacons)-20} more")

    section("UNUSUAL LOW DEST PORTS (not 80/443/53, <1024, untrusted)", len(unusual_ports))
    for u in unusual_ports[:15]:
        print(f"  [{u['dt']}] [{u['device']}] -> {u['dest']}:{u['port']} ({u['protocol']}) | {u['upload_kb']} KB")
    if len(unusual_ports) > 15:
        print(f"  ... and {len(unusual_ports)-15} more")

    section("TOP 10 DEVICES BY UPLOAD")
    for name, b in top_uploaders:
        print(f"  {mb(b):>9.1f} MB  {name}")

    section("TOP 10 DEVICES BY DOWNLOAD")
    for name, b in top_dl_devices:
        print(f"  {mb(b):>9.1f} MB  {name}")

    section("TOP 15 DOMAINS BY BANDWIDTH")
    for dom, b in top_domains_bw:
        trust = "✓" if dom in TRUSTED_DOMAINS else " "
        print(f"  {trust} {mb(b):>9.1f} MB  {domain_flow_count.get(dom,0):>6} flows  {dom}")

    section("TOP 15 DOMAINS BY CONNECTION COUNT")
    for dom, c in top_domains_cnt:
        trust = "✓" if dom in TRUSTED_DOMAINS else " "
        print(f"  {trust} {c:>7,} flows  {dom}")

    section("RARE UNTRUSTED DOMAINS WITH UPLOADS (top 20)")
    for dom, c in sorted(rare_untrusted.items(), key=lambda x: -x[1])[:20]:
        print(f"  {c:>5}x  {dom}")

    section("PER-USER UPLOAD SUMMARY")
    for uname, b in sorted(user_upload.items(), key=lambda x: -x[1])[:10]:
        print(f"  {mb(b):>9.1f} MB  {uname}  ({user_flows[uname]} flows)")
