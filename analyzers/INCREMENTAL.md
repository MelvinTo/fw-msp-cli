# Incremental Flow Analysis

A streaming pipeline that maintains a rolling 24-hour view of Firewalla
flow analytics — without keeping the raw NDJSON in memory. Designed to
run every few minutes from cron, so spikes in flow volume don't translate
into spikes in CPU/memory or AI cost.

The output is a short, human-readable security report that highlights
only items worth a human's attention.

---

## Why this exists

The original `analyze_flows.py` ingests a full 24-hour NDJSON export
(50–500 MB) on every run. That's fine for a one-off audit but expensive
to re-run hourly. The incremental flow keeps a compact JSON **state**
file (~180 KB) on disk and merges only new flows into it on each tick.

| | Full re-analysis (`analyze_flows.py`) | Incremental |
|---|---|---|
| Input | 50–500 MB NDJSON | 1–5 MB delta NDJSON |
| State on disk | none | ~180 KB JSON |
| Window | one-shot | rolling 24h (auto-ages out) |
| Re-run cost | high | tiny |

---

## What's in this directory

| File | Role |
|---|---|
| `analyze_flows.py` | Original one-shot 24h analyzer (still works). Exports helpers + trusted-domain list used by the incremental pipeline. |
| `incremental_state.py` | Hourly-bucket counters + ring buffers; `merge_flow()` and detection heuristics live here. |
| `analyze_incremental.py` | CLI driver: reads NDJSON from stdin or a file, merges into state, ages out, writes the report. |
| `report_from_state.py` | Renders a focused human-language report from a state file alone — no raw flows needed. |
| `analyze_alarms.py`, `analyze_recon.py` | Other analyzers, unrelated. |

Plus, at the repo root:

| File | Role |
|---|---|
| `fetch-flows-incremental.js` | Fetches flows from the MSP API since `last_fetch_ts`, writes to stdout for piping. |
| `fetch-flows-24h.js` | Bulk 24h fetcher (used for backfill or one-shot audits). |

---

## Setup

### 1. Install dependencies

```bash
npm install                 # node deps (axios, dotenv, etc.)
# Python 3.9+ — no external packages required
```

### 2. Configure credentials

Either export env vars or create a `.env` file at the repo root:

```bash
FIREWALLA_MSP_TOKEN=...         # MSP API token
FIREWALLA_MSP_ID=your-org.firewalla.net
FIREWALLA_BOX_GID=...           # the box you want to monitor
```

### 3. Choose state/report paths (optional)

Defaults are fine for a single box. Override only if you're monitoring
multiple boxes or want them stored elsewhere:

```bash
FLOW_STATE_FILE=/tmp/flow_state.json     # state JSON
FLOW_REPORT_FILE=/tmp/flow_report.txt    # rendered report
FLOW_ARCHIVE_DIR=/tmp                    # daily raw NDJSON archive
FETCH_INTERVAL_MIN=5                     # lookback minutes if no state
```

---

## Running it

### One-shot incremental tick

The simplest pipeline: fetch since `last_fetch_ts`, pipe to the analyzer,
update state and report.

```bash
node fetch-flows-incremental.js | python3 analyzers/analyze_incremental.py
```

What this does:
1. Reads `last_fetch_ts` from `$FLOW_STATE_FILE` (defaults to "now minus 5 min")
2. Pages through `/flows` for that time range
3. Writes each flow to stdout **and** appends to a daily NDJSON archive
4. Python side: parses NDJSON, merges into hourly buckets, populates ring
   buffers, ages out anything older than 24 h, renders the report

After the run:
- `$FLOW_STATE_FILE` — updated state (atomic write)
- `$FLOW_REPORT_FILE` — refreshed human-language report
- `$FLOW_ARCHIVE_DIR/flows_YYYY-MM-DD.ndjson` — appended raw flows

### Run from cron / scheduled task

```cron
# every 5 minutes
*/5 * * * * cd /path/to/fw-msp-cli && \
  node fetch-flows-incremental.js 2>/tmp/fetch.log | \
  python3 analyzers/analyze_incremental.py 2>>/tmp/fetch.log
```

Or via `launchd` / systemd timer — same pipeline.

### Backfill from an existing NDJSON file

Useful for bootstrapping the state from a full 24h export:

```bash
python3 analyzers/analyze_incremental.py --backfill /tmp/flows_2026-05-18.ndjson
```

`--backfill` means "skip the stdin/pipe and read everything from this
file". You can run it more than once — the state will keep merging.

### Render the report without touching the API

If you just want the latest report from existing state:

```bash
python3 analyzers/report_from_state.py /tmp/flow_state.json
```

---

## What the report looks like

Each section appears only if it has hits. Empty sections are skipped.

```
============================================================
  FIREWALLA — 24h SECURITY REPORT
============================================================
  As of  : 2026-05-19T17:26:46
  Flows  : 93,524   (outbound 61,509 / inbound 32,015)
  Blocked: 60,778  (65.0% — Firewalla rules doing their job)
  Items needing attention: 72

─────────────── 🚨 POSSIBLE DATA EXFILTRATION ──────────────
  ▸ A device uploaded much more data than it downloaded …
  [05-18 18:28] iPhone -> tencentcos.cn  (uploaded 436.9 MB,
                downloaded only 0.16 MB — ratio 2672:1, CN)
  …
```

Each section header gets a one-paragraph **plain-English** explanation
of what triggered the finding and what's normal vs. concerning — written
for technical users who aren't security specialists.

---

## What it detects

| Section | What it flags |
|---|---|
| 🚨 Suspicious incoming connections | Inbound from non-US, non-private source — exposed service signal |
| 🚨 Long-running connections to untrusted hosts | Single flow > 1h to untrusted dest — persistent backdoor / reverse shell |
| 🚨 Random-looking domain names | Shannon entropy > 4.0 on root — algorithmic / DGA candidate |
| 🚨 Possible data exfiltration | Outbound > 10 MB and upload > 3× download |
| ⚠️  Big uploads to bare IPs | > 5 MB to a destination with no DNS resolution |
| ⚠️  Large uploads to untrusted domains | > 50 MB outbound to a non-trusted domain |
| ⚠️  Possible beaconing | Long duration, tiny bytes, ≥5 connections — C2 cadence |
| ⚠️  Connections on unusual ports | Low-numbered ports other than 80/443/53 |
| 🆕 New devices on the network | Devices seen for the first time |

Two **persistent** sets (don't age out with the 24h window) drive a few
of these: `known_devices` and `known_domains`. They grow over time so
"first-seen" alerts become meaningful after a few days of running.

---

## Tuning

### Trusting more domains

Edit `analyze_flows.py` → `TRUSTED_DOMAINS`. The set is shared by all
detections — adding a domain there will suppress it from beacon checks,
high-volume checks, first-seen checks, etc.

### Adjusting heuristic thresholds

All thresholds live in `incremental_state.py` → `merge_flow()`. Search
for the relevant condition:

| Threshold | Where |
|---|---|
| Beacon duration / size / count | `duration > 300 and total_b < 50*1024 and count >= 5` |
| Raw IP upload size | `upload > 5 * 1024 * 1024` |
| High-volume upload | `upload > 50 * 1024 * 1024` |
| Non-US qualifying volume | `upload > 500 * 1024 or download > 5 * 1024 * 1024` |
| Upload ratio | `upload > 10*1024*1024 and upload > 3 * download` |
| Long-lived | `duration > 3600` |
| DGA entropy | `> 4.0` on a stem of length ≥ 8 |

### Resetting state

Just delete the state file:

```bash
rm -f /tmp/flow_state.json
```

The next run will start with an empty window and the next 24h will
rebuild from `--backfill` or from incremental fetches.

---

## Storage budget

| Item | Typical size (home box) | Typical size (office box) |
|---|---|---|
| Daily NDJSON archive | 80–100 MB/day | 1.5–2 GB/day |
| State JSON | ~180 KB | ~600 KB |
| Report | ~5 KB | ~15 KB |

You can rotate or purge the NDJSON archive freely — only `flow_state.json`
is required to keep the rolling window intact.

---

## Adding an AI briefing layer

The report file is small enough (~5 KB) to send to an LLM directly. Cost
estimates assume 24 hourly briefings per day (~720/month) and ~400
output tokens per briefing.

### Per-day / per-month cost

| Model | Report only (~1.2K in) | Report + state JSON (~46K in) | With prompt caching |
|---|---|---|---|
| **Sonnet 4.5** ($3 / $15 per M) | $0.23/day · $7/mo | $3.46/day · $104/mo | $0.43/day · $13/mo |
| **Haiku 4.5** ($1 / $5 per M)   | $0.08/day · $2.30/mo | $1.15/day · $35/mo | $0.14/day · $4.30/mo |
| **Haiku 3.5** ($0.80 / $4 per M) | $0.06/day · $1.87/mo | $0.92/day · $28/mo | — |

### Can Haiku do it?

Yes — for the routine hourly briefing. The input is small, structured,
and already digested by the analyzer. Haiku 4.5 can comfortably
categorize findings, spot hour-over-hour deltas, and produce a short
plain-English briefing.

Save Sonnet for the work that benefits from richer reasoning:
- One-off 24-hour audits where false-positive triage matters
- Deep dives on a specific finding ("what is 7yu.io?")
- Cross-referencing patterns against known C2 indicators

**Suggested split:**

| Schedule | Model | Monthly |
|---|---|---|
| Hourly briefing (24/day) | Haiku 4.5, report only | ~$2.30 |
| Daily deep audit (1/day)  | Sonnet 4.5, report only | ~$0.30 |
| **Total** | | **~$2.60** |

Tip: pass only `flow_report.txt` — the ring-buffer entries are already
distilled into the report. Reading the state JSON triples cost without
adding much signal for the routine briefing case.

---

## Multiple boxes

Run a separate pipeline per box by setting different state/report paths:

```bash
# Box A
FLOW_STATE_FILE=/tmp/boxA/state.json \
FLOW_REPORT_FILE=/tmp/boxA/report.txt \
FLOW_ARCHIVE_DIR=/tmp/boxA \
FIREWALLA_BOX_GID=<gid-A> \
node fetch-flows-incremental.js | python3 analyzers/analyze_incremental.py

# Box B (separate state, separate report)
FLOW_STATE_FILE=/tmp/boxB/state.json \
…
```

Each box gets its own rolling window and its own report.

---

## Troubleshooting

**`MODULE_NOT_FOUND` on `dotenv`** → run `npm install` first.

**`400 TIMEOUT_EXCEEDED` from the MSP API** → the API gets unhappy when
the `gid` query param is combined with `ts` qualifiers. The fetcher
already uses the supported form (`box.id:<gid> ts:<from>-<to>` inside
the `query` parameter). If you see this error, you may be on an older
revision — pull the latest `fetch-flows-incremental.js`.

**Pagination stalls past offset 9 500** → keep individual time chunks
small enough that pagination depth stays well under 10 000. The
incremental fetcher uses 5-minute lookbacks by default, which keeps
this comfortably bounded.

**Report says "Nothing unusual detected"** → that's the intended output
when none of the ring buffers have entries. The header still shows
flow count, blocked %, and known-device/-domain totals for context.

---

## Architecture in one diagram

```
   ┌──────────────────────────┐
   │  Firewalla MSP API       │
   │  /v2/flows               │
   └──────────────┬───────────┘
                  │  GET ?query=box.id:<gid> ts:<from>-<to>
                  ▼
   ┌──────────────────────────┐
   │ fetch-flows-incremental  │
   │   - reads last_fetch_ts  │
   │   - pages, retries 429   │
   │   - writes stdout +      │
   │     daily NDJSON archive │
   └──────────────┬───────────┘
                  │  NDJSON over stdout
                  ▼
   ┌──────────────────────────┐
   │ analyze_incremental.py   │
   │   merge_flow() per flow: │
   │     - hourly buckets     │
   │     - 12 ring buffers    │
   │     - known sets         │
   │   age_out(>24h)          │
   └──────────────┬───────────┘
                  │
        ┌─────────┴──────────┐
        ▼                    ▼
   flow_state.json     flow_report.txt
   (atomic write)      (human-readable)
                            │
                            ▼ (optional)
                       LLM briefing
```
