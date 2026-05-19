#!/usr/bin/env python3
"""
Incremental flow state management — maintains a rolling 24h window of
aggregated flow counters and ring buffers for notable events.
"""
import json, os, copy

from analyze_flows import (
    is_trusted, get_root_domain, is_private_ip, is_ip_address,
    mb, kb, ts_to_str, hour_of, redact_ips, strip_gid,
    TRUSTED_DOMAINS, NOISE_TAGS, UNUSUAL_PORT_WHITELIST,
)

# Ring buffer max sizes
_RING_LIMITS = {
    "ad_tracker_recent": 50,
    "raw_ip_large_recent": 30,
    "non_us_recent": 30,
    "high_volume_recent": 20,
    "beacon_candidates": 50,
    "unusual_ports_recent": 20,
    "new_device_recent": 30,
    "upload_ratio_recent": 30,
    "first_seen_domain_recent": 50,
    "inbound_untrusted_recent": 30,
    "long_lived_recent": 30,
    "dga_candidates": 30,
}


def _shannon_entropy(s):
    """Compute Shannon entropy of a string. DGA domains usually score >4.0."""
    if not s:
        return 0.0
    import math, collections
    counts = collections.Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())

EMPTY_BUCKET = {
    "flow_count": 0, "blocked_count": 0,
    "inbound_count": 0, "outbound_count": 0,
    "protocol_counts": {},
    "category_counts": {},
    "region_flows": {}, "region_bytes": {},
    "device_upload": {}, "device_download": {}, "device_flows": {},
    "domain_bytes": {}, "domain_flows": {},
    "user_upload": {}, "user_flows": {},
    "blocked_by_type": {}, "blocked_by_rule": {}, "blocked_domains": {},
    "rare_untrusted": {},
}


def _initial_state():
    return {
        "state_version": 2,
        "last_fetch_ts": 0,
        "window_start_ts": 0,
        "last_run_iso": "",
        "hourly_buckets": {},
        "ad_tracker_recent": [],
        "raw_ip_large_recent": [],
        "non_us_recent": [],
        "high_volume_recent": [],
        "beacon_candidates": [],
        "unusual_ports_recent": [],
        "new_device_recent": [],
        "upload_ratio_recent": [],
        "first_seen_domain_recent": [],
        "inbound_untrusted_recent": [],
        "long_lived_recent": [],
        "dga_candidates": [],
        # Persistent sets (not aged out with hourly buckets)
        "known_devices": {},          # name -> first_seen_ts
        "known_domains": {},          # root_domain -> first_seen_ts
    }


def load_state(path):
    """Load JSON state file.  Return empty initial state if missing."""
    if not os.path.exists(path):
        return _initial_state()
    try:
        with open(path) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return _initial_state()


def save_state(state, path):
    """Atomic write — write to .tmp then rename."""
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(state, f, separators=(",", ":"))
    os.rename(tmp, path)


def age_out(state, cutoff_ts):
    """Remove hourly buckets and ring buffer entries older than cutoff_ts."""
    # Evict old hourly buckets
    keys_to_remove = [
        k for k in state["hourly_buckets"]
        if int(k) < cutoff_ts
    ]
    for k in keys_to_remove:
        del state["hourly_buckets"][k]

    # Evict old ring buffer entries
    for ring_name in _RING_LIMITS:
        state[ring_name] = [
            e for e in state.get(ring_name, [])
            if e.get("ts", 0) >= cutoff_ts
        ]

    # Update window_start_ts
    if state["hourly_buckets"]:
        state["window_start_ts"] = min(int(k) for k in state["hourly_buckets"])
    else:
        state["window_start_ts"] = cutoff_ts


def get_bucket_key(ts):
    """Return hour-aligned epoch as string."""
    return str(int(ts // 3600) * 3600)


def _inc(d, key, val=1):
    """Increment a counter in a dict."""
    d[key] = d.get(key, 0) + val


def _ring_append(state, ring_name, entry):
    """Append to ring buffer, evicting oldest when full."""
    buf = state.setdefault(ring_name, [])
    limit = _RING_LIMITS[ring_name]
    if len(buf) >= limit:
        buf.pop(0)
    buf.append(entry)


def merge_flow(state, flow):
    """Process one flow into the state — update bucket counters and ring buffers."""
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

    if not ts:
        return

    # ── Bucket counters ──────────────────────────────────────────────────────
    bk = get_bucket_key(ts)
    buckets = state.setdefault("hourly_buckets", {})
    if bk not in buckets:
        buckets[bk] = copy.deepcopy(EMPTY_BUCKET)
    b = buckets[bk]

    b["flow_count"] += 1

    if blocked:
        b["blocked_count"] += 1

    if direction == "inbound":
        b["inbound_count"] += 1
    elif direction == "outbound":
        b["outbound_count"] += 1

    _inc(b["protocol_counts"], protocol or "unknown")
    _inc(b["category_counts"], category or "(none)")
    _inc(b["region_flows"], region or "??")
    _inc(b["region_bytes"], region or "??", total_b)
    _inc(b["device_upload"], device_name, upload)
    _inc(b["device_download"], device_name, download)
    _inc(b["device_flows"], device_name)
    if root_domain:
        _inc(b["domain_bytes"], root_domain, total_b)
        _inc(b["domain_flows"], root_domain)
    _inc(b["user_upload"], user_name, upload)
    _inc(b["user_flows"], user_name)

    # ── Blocked flow counters ────────────────────────────────────────────────
    if blocked:
        _inc(b["blocked_by_type"], block_type or "unknown")
        if blocked_by:
            _inc(b["blocked_by_rule"], blocked_by)
        if root_domain and not is_ip_address(root_domain):
            _inc(b["blocked_domains"], root_domain)

    # ── Heuristic ring buffers (skip blocked for security checks) ────────────
    if blocked:
        # Update last_fetch_ts
        if ts > state.get("last_fetch_ts", 0):
            state["last_fetch_ts"] = ts
        return

    if NOISE_TAGS & tags:
        if ts > state.get("last_fetch_ts", 0):
            state["last_fetch_ts"] = ts
        return

    # Ad/tracker hits (not blocked)
    if category == "ad":
        _ring_append(state, "ad_tracker_recent", {
            "ts": ts, "dt": dt_str, "device": device_name,
            "dest": domain or dest_ip, "upload_kb": kb(upload),
        })

    # Large upload to raw IP (>5 MB, no domain, outbound)
    if direction == "outbound" and not domain and dest_ip and upload > 5 * 1024 * 1024:
        if not is_private_ip(dest_ip):
            _ring_append(state, "raw_ip_large_recent", {
                "ts": ts, "dt": dt_str, "device": device_name,
                "dest_ip": dest_ip, "region": region,
                "upload_mb": mb(upload), "port": dest_port,
                "protocol": protocol,
            })

    # Non-US traffic to untrusted destinations
    if region and region not in ("US",) and not is_trusted(domain):
        if upload > 500 * 1024 or download > 5 * 1024 * 1024:
            _ring_append(state, "non_us_recent", {
                "ts": ts, "dt": dt_str, "device": device_name,
                "dest": domain or dest_ip, "region": region,
                "upload_mb": mb(upload), "download_mb": mb(download),
            })

    # High volume upload to untrusted domain (>50 MB)
    if upload > 50 * 1024 * 1024 and not is_trusted(domain) and direction == "outbound":
        _ring_append(state, "high_volume_recent", {
            "ts": ts, "dt": dt_str, "device": device_name,
            "dest": domain or dest_ip, "region": region,
            "upload_mb": mb(upload),
        })

    # Beacon/C2 pattern
    if (direction == "outbound" and duration > 300 and total_b < 50 * 1024
            and count >= 5 and not is_trusted(domain)):
        _ring_append(state, "beacon_candidates", {
            "ts": ts, "dt": dt_str, "device": device_name,
            "dest": domain or dest_ip, "region": region,
            "duration_min": round(duration / 60, 1),
            "total_kb": kb(total_b), "count": count,
        })

    # Unusual low dest ports
    if dest_port and dest_port not in UNUSUAL_PORT_WHITELIST and dest_port < 1024:
        if not is_trusted(domain):
            _ring_append(state, "unusual_ports_recent", {
                "ts": ts, "dt": dt_str, "device": device_name,
                "dest": domain or dest_ip, "port": dest_port,
                "protocol": protocol, "upload_kb": kb(upload),
            })

    # Rare untrusted domains with upload
    if root_domain and not is_trusted(domain) and upload > 50 * 1024:
        _inc(b["rare_untrusted"], root_domain)

    # ── New device detection ────────────────────────────────────────────────
    known_devices = state.setdefault("known_devices", {})
    if device_name and device_name != "unknown":
        if device_name not in known_devices:
            known_devices[device_name] = ts
            _ring_append(state, "new_device_recent", {
                "ts": ts, "dt": dt_str, "device": device_name,
                "first_dest": domain or dest_ip or "?",
                "direction": direction,
            })

    # ── First-seen domain detection ─────────────────────────────────────────
    known_domains = state.setdefault("known_domains", {})
    if root_domain and not is_trusted(domain) and not is_ip_address(root_domain):
        if root_domain not in known_domains:
            known_domains[root_domain] = ts
            _ring_append(state, "first_seen_domain_recent", {
                "ts": ts, "dt": dt_str, "domain": root_domain,
                "device": device_name, "direction": direction,
                "upload_kb": kb(upload), "download_kb": kb(download),
            })

    # ── Upload/download ratio anomaly ───────────────────────────────────────
    # Flag outbound flows where upload > 10 MB and upload > 3x download
    # (inverted ratio — normal browsing is download-heavy)
    if (direction == "outbound" and upload > 10 * 1024 * 1024
            and download > 0 and upload > 3 * download
            and not is_trusted(domain)):
        ratio = round(upload / download, 1)
        _ring_append(state, "upload_ratio_recent", {
            "ts": ts, "dt": dt_str, "device": device_name,
            "dest": domain or dest_ip, "region": region,
            "upload_mb": mb(upload), "download_mb": mb(download),
            "ratio": ratio,
        })

    # ── Inbound from untrusted region ───────────────────────────────────────
    # An inbound flow from a non-US, non-private source is suspicious —
    # suggests an exposed service or scan landing on a LAN device.
    src_ip = src.get("ip", "") or ""
    if (direction == "inbound" and region and region != "US"
            and src_ip and not is_private_ip(src_ip)
            and not is_trusted(domain)):
        _ring_append(state, "inbound_untrusted_recent", {
            "ts": ts, "dt": dt_str, "device": device_name,
            "src_ip": src_ip, "region": region,
            "port": dest_port, "protocol": protocol,
            "upload_kb": kb(upload), "download_kb": kb(download),
        })

    # ── Long-lived untrusted connection ─────────────────────────────────────
    # Duration > 1h to an untrusted destination is unusual outside of
    # legitimate VPN/SSH — possible persistent backdoor or reverse shell.
    if (direction == "outbound" and duration > 3600
            and not is_trusted(domain)):
        _ring_append(state, "long_lived_recent", {
            "ts": ts, "dt": dt_str, "device": device_name,
            "dest": domain or dest_ip, "region": region,
            "duration_min": round(duration / 60, 1),
            "upload_kb": kb(upload), "download_kb": kb(download),
            "protocol": protocol, "port": dest_port,
        })

    # ── DGA candidate (high-entropy domain) ─────────────────────────────────
    # Shannon entropy >4.0 on the root-domain stem suggests algorithmic
    # generation. Pair with untrusted + outbound + upload to reduce noise.
    if (root_domain and not is_trusted(domain) and not is_ip_address(root_domain)
            and direction == "outbound" and upload > 1024):
        # Strip TLD for entropy calculation
        stem = root_domain.rsplit(".", 1)[0]
        if len(stem) >= 8:
            ent = _shannon_entropy(stem)
            if ent > 4.0:
                _ring_append(state, "dga_candidates", {
                    "ts": ts, "dt": dt_str, "device": device_name,
                    "domain": root_domain, "entropy": round(ent, 2),
                    "region": region, "upload_kb": kb(upload),
                })

    # Track latest timestamp
    if ts > state.get("last_fetch_ts", 0):
        state["last_fetch_ts"] = ts


def get_totals(state):
    """Sum across all hourly buckets to produce aggregate counters dict."""
    totals = copy.deepcopy(EMPTY_BUCKET)
    for _bk, bucket in state.get("hourly_buckets", {}).items():
        totals["flow_count"] += bucket.get("flow_count", 0)
        totals["blocked_count"] += bucket.get("blocked_count", 0)
        totals["inbound_count"] += bucket.get("inbound_count", 0)
        totals["outbound_count"] += bucket.get("outbound_count", 0)
        for key in ("protocol_counts", "category_counts", "region_flows",
                     "region_bytes", "device_upload", "device_download",
                     "device_flows", "domain_bytes", "domain_flows",
                     "user_upload", "user_flows", "blocked_by_type",
                     "blocked_by_rule", "blocked_domains", "rare_untrusted"):
            src_dict = bucket.get(key, {})
            dst_dict = totals[key]
            for k, v in src_dict.items():
                dst_dict[k] = dst_dict.get(k, 0) + v
    return totals
