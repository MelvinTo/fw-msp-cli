#!/usr/bin/env node
/**
 * Incremental flow fetcher for Firewalla MSP.
 *
 * Reads last_fetch_ts from a state file, fetches new flows since then,
 * appends them to a daily NDJSON archive, writes them to stdout for piping,
 * and updates the state file.
 *
 * Env vars:
 *   FLOW_STATE_FILE     — path to state JSON (default: /tmp/flow_state.json)
 *   FLOW_ARCHIVE_DIR    — dir for daily NDJSON files (default: /tmp)
 *   FETCH_INTERVAL_MIN  — lookback minutes if no state (default: 5)
 *   FIREWALLA_MSP_TOKEN — MSP API token
 *   FIREWALLA_MSP_ID    — MSP ID
 *   FIREWALLA_BOX_GID   — box group ID
 *
 * Usage:
 *   node fetch-flows-incremental.js | python3 analyzers/analyze_incremental.py
 */
require('dotenv').config();
const fs = require('fs');
const path = require('path');
const { getClient, resolveBoxGid } = require('./cli/src/api/client');

const BATCH_SIZE = 500;
const STATE_FILE = process.env.FLOW_STATE_FILE || '/tmp/flow_state.json';
const ARCHIVE_DIR = process.env.FLOW_ARCHIVE_DIR || '/tmp';
const DEFAULT_LOOKBACK_MIN = parseInt(process.env.FETCH_INTERVAL_MIN || '5', 10);

const log = (...args) => process.stderr.write(args.join(' ') + '\n');

function readState() {
  try {
    return JSON.parse(fs.readFileSync(STATE_FILE, 'utf8'));
  } catch {
    return {};
  }
}

function writeState(patch) {
  const existing = readState();
  const merged = { ...existing, ...patch };
  const tmp = STATE_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(merged, null, 2) + '\n');
  fs.renameSync(tmp, STATE_FILE);
}

function archivePath() {
  const date = new Date().toISOString().slice(0, 10);
  return path.join(ARCHIVE_DIR, `flows_${date}.ndjson`);
}

async function fetchFlows(client, gid, fromTs, toTs) {
  const flows = [];
  let cursor = null;

  do {
    const params = {
      limit: BATCH_SIZE,
      query: `box.id:${gid} ts:${fromTs}-${toTs}`,
    };
    if (cursor) params.cursor = cursor;

    let data;
    let delay = 5000;
    for (let attempt = 1; attempt <= 10; attempt++) {
      try {
        ({ data } = await client.get('/flows', {
          params,
          headers: { 'Accept-Encoding': 'gzip, deflate, br' },
          decompress: true,
        }));
        break;
      } catch (err) {
        const status = err.response?.status;
        if ((status === 429 || status === 400) && attempt < 10) {
          log(`[retry] ${status === 429 ? 'Rate limited' : 'Server timeout'}, attempt ${attempt}/10, waiting ${delay / 1000}s...`);
          await new Promise(r => setTimeout(r, delay));
          delay = Math.min(delay * 2, 120000);
        } else {
          throw err;
        }
      }
    }

    const results = data.results || [];
    flows.push(...results);
    cursor = data.next_cursor || null;

    log(`[fetch] ${flows.length} flows so far...`);

    if (cursor) await new Promise(r => setTimeout(r, 1500));
  } while (cursor);

  return flows;
}

async function main() {
  const options = {};
  const gid = await resolveBoxGid(process.env.FIREWALLA_BOX_GID, options);
  const client = getClient(options);

  const nowTs = Math.floor(Date.now() / 1000);
  const state = readState();
  const fromTs = state.last_fetch_ts || (nowTs - DEFAULT_LOOKBACK_MIN * 60);

  if (fromTs >= nowTs) {
    log('[skip] last_fetch_ts is at or ahead of now, nothing to fetch.');
    return;
  }

  log(`[start] Fetching flows from ${new Date(fromTs * 1000).toISOString()} to ${new Date(nowTs * 1000).toISOString()}`);

  const flows = await fetchFlows(client, gid, fromTs, nowTs);

  if (flows.length === 0) {
    log('[done] No new flows.');
    writeState({
      last_fetch_ts: nowTs,
      last_run_iso: new Date().toISOString(),
    });
    return;
  }

  // Find max ts for state update
  let maxTs = fromTs;
  for (const flow of flows) {
    const ts = flow.ts || 0;
    if (ts > maxTs) maxTs = ts;
  }

  // Append to daily archive
  const archive = archivePath();
  const archiveStream = fs.createWriteStream(archive, { flags: 'a' });
  for (const flow of flows) {
    const line = JSON.stringify(flow) + '\n';
    archiveStream.write(line);
    process.stdout.write(line);
  }
  await new Promise(resolve => archiveStream.end(resolve));

  // Update state (atomic write, preserves other keys)
  writeState({
    last_fetch_ts: maxTs,
    last_run_iso: new Date().toISOString(),
  });

  log(`[done] ${flows.length} flows written to stdout and ${archive}`);
  log(`[state] last_fetch_ts updated to ${maxTs} (${new Date(maxTs * 1000).toISOString()})`);
}

main().catch(err => {
  log(`[error] ${err.message}`);
  process.exit(1);
});
