#!/usr/bin/env node
/**
 * Fetch recent flows in 1-hour chunks, write NDJSON to a file.
 * FETCH_HOURS  — how many hours back to fetch (default: 24)
 * OUTPUT_DIR   — output directory (default: /tmp)
 * MAX_MB       — stop if output file exceeds this size in MB (default: 100)
 */
require('dotenv').config();
const fs = require('fs');
const path = require('path');
const { getClient, resolveBoxGid } = require('./cli/src/api/client');

const CHUNK_HOURS = 1;
const TOTAL_HOURS = parseInt(process.env.FETCH_HOURS || '24', 10);
const BATCH_SIZE = 500;
const MAX_MB = parseInt(process.env.MAX_MB || '500', 10);
const MAX_BYTES = MAX_MB * 1024 * 1024;
const OUTPUT_DIR = process.env.OUTPUT_DIR || '/tmp';
const OUTPUT_FILE = path.join(OUTPUT_DIR, `flows_${new Date().toISOString().slice(0,10)}.ndjson`);

// Returns { count, limitHit }
async function fetchChunk(client, gid, fromTs, toTs, label) {
  let cursor = null;
  let total = 0;
  let limitHit = false;
  const out = fs.createWriteStream(OUTPUT_FILE, { flags: 'a' });

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
          process.stderr.write(`[${label}] ${status === 429 ? 'Rate limited' : 'Timeout'}, retrying in ${delay / 1000}s...\n`);
          await new Promise(r => setTimeout(r, delay));
          delay = Math.min(delay * 2, 120000);
        } else {
          throw err;
        }
      }
    }

    const results = data.results || [];
    for (const flow of results) {
      out.write(JSON.stringify(flow) + '\n');
    }
    total += results.length;
    cursor = data.next_cursor || null;

    const fileSize = fs.statSync(OUTPUT_FILE).size;
    process.stdout.write(`[${label}] fetched ${total} flows so far (${(fileSize / 1024 / 1024).toFixed(1)} MB)...\r`);

    if (fileSize >= MAX_BYTES) {
      process.stderr.write(`\n[${label}] File size limit reached (${(fileSize / 1024 / 1024).toFixed(1)} MB), stopping.\n`);
      limitHit = true;
      break;
    }

    if (cursor) await new Promise(r => setTimeout(r, 1500));
  } while (cursor);

  await new Promise(resolve => out.end(resolve));
  return { count: total, limitHit };
}

async function main() {
  const options = {};
  const gid = await resolveBoxGid(process.env.FIREWALLA_BOX_GID, options);
  const client = getClient(options);

  const now = Math.floor(Date.now() / 1000);
  const chunks = [];
  for (let i = 0; i < TOTAL_HOURS / CHUNK_HOURS; i++) {
    const toTs = now - i * CHUNK_HOURS * 3600;
    const fromTs = toTs - CHUNK_HOURS * 3600;
    const label = `chunk ${i + 1}/${TOTAL_HOURS / CHUNK_HOURS} (${i}h–${i + 1}h ago)`;
    chunks.push({ fromTs, toTs, label });
  }

  // Clear file if it exists
  fs.writeFileSync(OUTPUT_FILE, '');
  console.log(`Writing to: ${OUTPUT_FILE}\n`);

  let grandTotal = 0;
  for (const { fromTs, toTs, label } of chunks) {
    process.stdout.write(`Starting ${label}...\n`);
    const { count, limitHit } = await fetchChunk(client, gid, fromTs, toTs, label);
    process.stdout.write(`\n[${label}] done — ${count} flows\n`);
    grandTotal += count;
    if (limitHit) break;
  }

  console.log(`\nAll done. Total flows: ${grandTotal}`);
  console.log(`Saved to: ${OUTPUT_FILE}`);
}

main().catch(err => {
  console.error('Error:', err.message);
  process.exit(1);
});
