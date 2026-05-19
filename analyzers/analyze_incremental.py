#!/usr/bin/env python3
"""
Incremental flow analyzer — processes new flows into a rolling 24h state
and regenerates the security report.

Usage:
  # Piped from fetcher
  node fetch-flows-incremental.js | python3 analyzers/analyze_incremental.py

  # From a file
  python3 analyzers/analyze_incremental.py /tmp/flows_new.ndjson

  # Backfill from a full NDJSON export
  python3 analyzers/analyze_incremental.py --backfill /tmp/flows_2026-05-19.ndjson
"""
import json, sys, os, time, datetime

# Allow imports from the analyzers directory
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from incremental_state import load_state, save_state, merge_flow, age_out
from report_from_state import render_report

FLOW_STATE_FILE  = os.environ.get("FLOW_STATE_FILE", "/tmp/flow_state.json")
FLOW_REPORT_FILE = os.environ.get("FLOW_REPORT_FILE", "/tmp/flow_report.txt")


def read_ndjson(source):
    """Yield parsed JSON objects from an NDJSON stream (file or stdin)."""
    errors = 0
    for line in source:
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            # Handle {results:[]} wrapper
            if isinstance(obj, dict) and "results" in obj and isinstance(obj["results"], list):
                for item in obj["results"]:
                    yield item
                continue
            # Handle bare arrays
            if isinstance(obj, list):
                for item in obj:
                    yield item
                continue
            yield obj
        except json.JSONDecodeError:
            errors += 1
    if errors:
        print(f"[warn] {errors} NDJSON parse errors", file=sys.stderr)


def main():
    args = sys.argv[1:]
    backfill = False
    filepath = None

    if "--backfill" in args:
        backfill = True
        args.remove("--backfill")

    if args:
        filepath = args[0]

    # Load existing state
    state = load_state(FLOW_STATE_FILE)

    # Read flows
    new_count = 0
    if filepath:
        with open(filepath) as f:
            for flow in read_ndjson(f):
                merge_flow(state, flow)
                new_count += 1
    else:
        # Read from stdin
        for flow in read_ndjson(sys.stdin):
            merge_flow(state, flow)
            new_count += 1

    # Age out old data (keep 24h window)
    now = time.time()
    age_out(state, now - 86400)

    # Update run metadata
    state["last_run_iso"] = datetime.datetime.now().isoformat()

    # Save state
    save_state(state, FLOW_STATE_FILE)

    # Generate report
    report = render_report(state)
    with open(FLOW_REPORT_FILE, "w") as f:
        f.write(report)

    # Count total flows in window
    total_in_window = sum(
        b.get("flow_count", 0)
        for b in state.get("hourly_buckets", {}).values()
    )

    print(
        f"Processed {new_count} new flows. "
        f"State: {total_in_window:,} total flows in 24h window. "
        f"Report: {FLOW_REPORT_FILE}",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
