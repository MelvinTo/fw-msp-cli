#!/usr/bin/env python3
"""
Generate a focused, human-language security report from a state file.

Only high-priority findings are included. Written for technical users who
aren't security specialists — short explanations are added so each section
is understandable at a glance.

Usage:
  python3 analyzers/report_from_state.py [state_file]
"""
import json, sys, os, collections

# Allow imports from the analyzers directory
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from analyze_flows import (
    is_trusted, get_root_domain, mb, kb, strip_gid, TRUSTED_DOMAINS,
)
from incremental_state import load_state, get_totals


def _section(lines, title, count=None):
    label = f" ({count})" if count is not None else ""
    lines.append(f"\n{'─' * 60}")
    lines.append(f"  {title}{label}")
    lines.append(f"{'─' * 60}")


def _note(lines, text):
    """Short plain-English explanation under a section header."""
    lines.append(f"  ▸ {text}")
    lines.append("")


def render_report(state, state_file_label=None):
    """Render a focused, human-language report from state. Returns a string."""
    lines = []
    t = get_totals(state)

    total       = t["flow_count"]
    blocked     = t["blocked_count"]
    inbound     = t["inbound_count"]
    outbound    = t["outbound_count"]
    blocked_pct = round(blocked / total * 100, 1) if total else 0.0

    # ── Header ───────────────────────────────────────────────────────────────
    lines.append("=" * 60)
    lines.append("  FIREWALLA — 24h SECURITY REPORT")
    lines.append("=" * 60)
    if state_file_label:
        lines.append(f"  Source : {state_file_label}")
    lines.append(f"  As of  : {state.get('last_run_iso', 'n/a')}")
    lines.append(f"  Flows  : {total:,}   (outbound {outbound:,} / inbound {inbound:,})")
    lines.append(f"  Blocked: {blocked:,}  ({blocked_pct}% — Firewalla rules doing their job)")

    # Count how many items need attention
    high_priority_buckets = [
        "inbound_untrusted_recent",
        "long_lived_recent",
        "dga_candidates",
        "upload_ratio_recent",
        "raw_ip_large_recent",
        "high_volume_recent",
        "beacon_candidates",
        "new_device_recent",
        "unusual_ports_recent",
    ]
    attention_count = sum(len(state.get(b, [])) for b in high_priority_buckets)
    lines.append(f"  Items needing attention: {attention_count}")
    if attention_count == 0:
        lines.append("\n  ✅ Nothing unusual detected in the last 24 hours.")
        return "\n".join(lines) + "\n"

    # ── INBOUND FROM UNTRUSTED REGIONS ───────────────────────────────────────
    inb = state.get("inbound_untrusted_recent", [])
    if inb:
        _section(lines, "🚨 SUSPICIOUS INCOMING CONNECTIONS", len(inb))
        _note(lines, "Someone outside your network (not in the US) connected to a device on your LAN. This usually means a port is exposed to the internet — investigate whether the listed device should be reachable from the outside world.")
        for i in inb[:20]:
            lines.append(
                f"  [{i['dt']}] from {i['src_ip']} ({i['region']}) -> {i['device']} on port {i['port']}/{i['protocol']}"
                f"  ({i.get('upload_kb',0)} KB up / {i.get('download_kb',0)} KB down)"
            )
        if len(inb) > 20:
            lines.append(f"  ... and {len(inb)-20} more")

    # ── LONG-LIVED UNTRUSTED CONNECTIONS ─────────────────────────────────────
    ll = state.get("long_lived_recent", [])
    if ll:
        _section(lines, "🚨 LONG-RUNNING CONNECTIONS TO UNTRUSTED HOSTS", len(ll))
        _note(lines, "A device kept a connection open with an outside server for over an hour. This is normal for VPNs and SSH, but unusual for everything else — could be a persistent backdoor if you don't recognize the destination.")
        for l in ll[:15]:
            lines.append(
                f"  [{l['dt']}] {l['device']} -> {l['dest']}:{l['port']}/{l['protocol']}"
                f"  ({l['duration_min']} min, {l.get('upload_kb',0)} KB up / {l.get('download_kb',0)} KB down, {l['region']})"
            )
        if len(ll) > 15:
            lines.append(f"  ... and {len(ll)-15} more")

    # ── DGA / HIGH-ENTROPY DOMAINS ───────────────────────────────────────────
    dga = state.get("dga_candidates", [])
    if dga:
        _section(lines, "🚨 RANDOM-LOOKING DOMAIN NAMES", len(dga))
        _note(lines, "These domain names look algorithmically generated (jumbled letters). Malware often uses such domains to reach its command server. Verify whether the listed apps explain them — if not, this is a strong malware signal.")
        for d in dga[:15]:
            lines.append(
                f"  [{d['dt']}] {d['device']} -> {d['domain']}  (entropy {d['entropy']}, {d.get('upload_kb',0)} KB up, {d['region']})"
            )
        if len(dga) > 15:
            lines.append(f"  ... and {len(dga)-15} more")

    # ── UPLOAD/DOWNLOAD RATIO ANOMALIES ──────────────────────────────────────
    ratio = state.get("upload_ratio_recent", [])
    if ratio:
        _section(lines, "🚨 POSSIBLE DATA EXFILTRATION (LOTS OF UPLOAD, LITTLE DOWNLOAD)", len(ratio))
        _note(lines, "A device uploaded much more data than it downloaded. Normal browsing/streaming is the opposite. Large lopsided uploads to untrusted hosts are a classic exfiltration signal — confirm if it's a known backup or sync.")
        for r in ratio[:15]:
            lines.append(
                f"  [{r['dt']}] {r['device']} -> {r['dest']}"
                f"  (uploaded {r['upload_mb']} MB, downloaded only {r['download_mb']} MB — ratio {r['ratio']}:1, {r['region']})"
            )
        if len(ratio) > 15:
            lines.append(f"  ... and {len(ratio)-15} more")

    # ── LARGE UPLOADS TO RAW IPs (no DNS name) ───────────────────────────────
    raw = state.get("raw_ip_large_recent", [])
    if raw:
        _section(lines, "⚠️  BIG UPLOADS TO BARE IPs (no domain name)", len(raw))
        _note(lines, "A device sent >5 MB to an IP address that wasn't resolved through DNS — there's no domain we can use to identify the destination. This is normal for VPN/WireGuard tunnels (port 51820/udp), but unusual otherwise.")
        for r in raw[:20]:
            lines.append(
                f"  [{r['dt']}] {r['device']} -> {r['dest_ip']}:{r['port']}/{r['protocol']}"
                f"  ({r['upload_mb']} MB, {r['region']})"
            )
        if len(raw) > 20:
            lines.append(f"  ... and {len(raw)-20} more")

    # ── HIGH VOLUME UPLOADS TO UNTRUSTED DOMAINS ─────────────────────────────
    hv = state.get("high_volume_recent", [])
    if hv:
        _section(lines, "⚠️  LARGE UPLOADS TO UNTRUSTED DOMAINS (>50 MB)", len(hv))
        _note(lines, "A device sent more than 50 MB to a domain that isn't on the trusted list. Probably a cloud backup or file sync — verify it's intentional.")
        for h in hv[:15]:
            lines.append(
                f"  [{h['dt']}] {h['device']} -> {h['dest']}  ({h['upload_mb']} MB, {h['region']})"
            )
        if len(hv) > 15:
            lines.append(f"  ... and {len(hv)-15} more")

    # ── POSSIBLE BEACONING (C2-style) ────────────────────────────────────────
    beacon = state.get("beacon_candidates", [])
    if beacon:
        _section(lines, "⚠️  POSSIBLE BEACONING (heartbeat-style traffic)", len(beacon))
        _note(lines, "Outbound connections that lasted >5 min but exchanged <50 KB over 5+ separate connections. This 'phone home' pattern is typical of malware checking in with a control server — but it also fits legitimate analytics SDKs (e.g., appsflyersdk).")
        for b in beacon[:20]:
            lines.append(
                f"  [{b['dt']}] {b['device']} -> {b['dest']}"
                f"  ({b['duration_min']} min, {b['total_kb']} KB across {b['count']} conns, {b['region']})"
            )
        if len(beacon) > 20:
            lines.append(f"  ... and {len(beacon)-20} more")

    # ── UNUSUAL DESTINATION PORTS ────────────────────────────────────────────
    ports = state.get("unusual_ports_recent", [])
    if ports:
        _section(lines, "⚠️  CONNECTIONS ON UNUSUAL PORTS", len(ports))
        _note(lines, "Outbound traffic to a low-numbered port that isn't 80/443/53. Most apps use standard ports — non-standard ones can indicate custom protocols or sneaky services.")
        for u in ports[:15]:
            lines.append(
                f"  [{u['dt']}] {u['device']} -> {u['dest']}:{u['port']}/{u['protocol']}  ({u.get('upload_kb',0)} KB up)"
            )
        if len(ports) > 15:
            lines.append(f"  ... and {len(ports)-15} more")

    # ── NEW DEVICES ──────────────────────────────────────────────────────────
    nd = state.get("new_device_recent", [])
    if nd:
        _section(lines, "🆕 NEW DEVICES ON THE NETWORK", len(nd))
        _note(lines, "Devices we haven't seen before in this 24h window. If you didn't add anything new (no guest, no IoT install), an unknown device could be a sign of unauthorized access.")
        for n in nd[-20:]:
            lines.append(
                f"  [{n['dt']}] {n['device']}  (first connected to {n.get('first_dest','?')})"
            )
        if len(nd) > 20:
            lines.append(f"  ... and {len(nd)-20} more")
        known_count = len(state.get("known_devices", {}))
        lines.append(f"  Total known devices on the network: {known_count}")

    # ── Footer: minimal context ──────────────────────────────────────────────
    _section(lines, "CONTEXT (for reference, not alerts)")
    # Top 5 by upload
    top_up = sorted(t["device_upload"].items(), key=lambda x: -x[1])[:5]
    lines.append("  Biggest uploaders today:")
    for name, b in top_up:
        lines.append(f"    {mb(b):>8.1f} MB  {name}")
    # Top 5 untrusted bandwidth domains
    top_dom = [(d, b) for d, b in sorted(t["domain_bytes"].items(), key=lambda x: -x[1])
               if d not in TRUSTED_DOMAINS][:5]
    if top_dom:
        lines.append("\n  Top untrusted bandwidth domains:")
        for dom, b in top_dom:
            fc = t["domain_flows"].get(dom, 0)
            lines.append(f"    {mb(b):>8.1f} MB  ({fc:,} flows)  {dom}")

    # Known set sizes (helpful trend metric)
    known_devices = len(state.get("known_devices", {}))
    known_domains = len(state.get("known_domains", {}))
    lines.append(f"\n  Tracking {known_devices} devices and {known_domains} untrusted domains across all history.")

    return "\n".join(lines) + "\n"


def main():
    state_file = sys.argv[1] if len(sys.argv) > 1 else "/tmp/flow_state.json"
    state = load_state(state_file)
    report = render_report(state, state_file_label=state_file)
    print(report, end="")


if __name__ == "__main__":
    main()
