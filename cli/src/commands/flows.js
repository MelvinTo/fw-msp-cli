const { getClient, resolveBoxGid } = require('../api/client');

// Parse time string to Unix timestamp
// Supports: "2h", "30m", "1d", "2024-01-01", "2024-01-01T12:00:00"
function parseTime(timeStr) {
  const now = Date.now() / 1000;
  const match = timeStr.match(/^(\d+)([smhd])$/);
  if (match) {
    const value = parseInt(match[1]);
    const unit = match[2];
    const multipliers = { s: 1, m: 60, h: 3600, d: 86400 };
    return now - (value * multipliers[unit]);
  }
  const date = new Date(timeStr);
  if (isNaN(date.getTime())) {
    throw new Error(`Invalid time format: ${timeStr}`);
  }
  return date.getTime() / 1000;
}

const Flows = {
  report: async (options) => {
    const gid = await resolveBoxGid(options.box, options);
    const client = getClient(options);
    console.log('Fetching raw flow report (this may take a moment)...');
    try {
      const { data } = await client.get(`/boxes/${gid}/behavior-inspector/flow-report`, {
        responseType: 'text',
        transformResponse: [(d) => d]
      });

      if (options.output) {
        const fs = require('fs');
        fs.writeFileSync(options.output, data);
        console.log(`Wrote report to ${options.output}`);
      } else {
        process.stdout.write(data);
      }
    } catch (err) {
      const status = err.response?.status;
      const body = err.response?.data;
      let parsed = body;
      if (typeof body === 'string') {
        try { parsed = JSON.parse(body); } catch (_) { /* keep raw text */ }
      }
      console.error(JSON.stringify({ error: "Flow report fetch failed", status, details: parsed || err.message }));
      process.exit(1);
    }
  },

  aiReport: async (options) => {
    const gid = await resolveBoxGid(options.box, options);
    const client = getClient(options);
    console.log('Starting AI flow report analysis (this may take a moment)...');
    try {
      // Step 1: Start the async AI task
      const { data: task } = await client.post('/fireai/ask', { type: 'flow_report', meta: { gid }, ignoreCache: true });
      const taskId = task.taskId;
      if (!taskId) {
        throw new Error(`Unexpected response from /fireai/ask: ${JSON.stringify(task)}`);
      }
      process.stderr.write(`Task started (id: ${taskId}), waiting for result...\n`);

      // Step 2: Poll /tasks/:id until status is 'succeeded'
      const content = await new Promise((resolve, reject) => {
        const timer = setInterval(async () => {
          try {
            const { data: result } = await client.get(`/tasks/${taskId}`);
            if (result.status === 'succeeded') {
              clearInterval(timer);
              resolve(result.result?.content ?? '');
            } else if (result.status === 'failed' || result.status === 'error') {
              clearInterval(timer);
              reject(new Error(`Task ${taskId} ${result.status}: ${JSON.stringify(result.result || result.error)}`));
            }
            // still pending/running — keep waiting
          } catch (err) {
            clearInterval(timer);
            reject(err);
          }
        }, 1000);
      });

      if (options.output) {
        const fs = require('fs');
        fs.writeFileSync(options.output, content);
        console.log(`Wrote AI report to ${options.output}`);
      } else {
        process.stdout.write(content);
      }
    } catch (err) {
      const status = err.response?.status;
      const body = err.response?.data;
      let parsed = body;
      if (typeof body === 'string') {
        try { parsed = JSON.parse(body); } catch (_) { /* keep raw text */ }
      }
      console.error(JSON.stringify({ error: "AI flow report fetch failed", status, details: parsed || err.message }));
      process.exit(1);
    }
  },

  list: async (options) => {
    const gid = await resolveBoxGid(options.box, options);
    const client = getClient(options);
    
    let apiParams = { gid };
    let queryParts = [];
    
    // Build query from convenience flags
    if (options.since) {
      const ts = parseTime(options.since);
      queryParts.push(`ts:>${ts}`);
    }
    
    if (options.until) {
      const ts = parseTime(options.until);
      queryParts.push(`ts:<${ts}`);
    }
    
    if (options.blocked) {
      queryParts.push('status:blocked');
    }
    
    // Add user-provided query
    if (options.query) {
      queryParts.push(options.query);
    }
    
    if (queryParts.length > 0) {
      apiParams.query = queryParts.join(' ');
    }
    
    if (options.groupBy) {
      apiParams.groupBy = options.groupBy;
    }
    
    if (options.sortBy) {
      apiParams.sortBy = options.sortBy;
    }
    
    let targetLimit = null;
    if (options.limit) {
      targetLimit = parseInt(options.limit);
      if (isNaN(targetLimit) || targetLimit <= 0) {
        console.error(JSON.stringify({ error: "Invalid limit value. Must be a positive integer." }));
        process.exit(1);
      }
    }
    
    if (options.cursor) {
      apiParams.cursor = options.cursor;
    }
    
    // Support raw params for advanced users
    if (options.params) {
      const parsedParams = JSON.parse(options.params);
      const supportedParams = ['query', 'groupBy', 'sortBy', 'limit', 'cursor'];
      supportedParams.forEach(param => {
        if (parsedParams[param] !== undefined) {
          apiParams[param] = parsedParams[param];
        }
      });
    }

    try {
      // Auto-pagination when limit > 500 or --all flag
      const shouldPaginate = options.all || (targetLimit && targetLimit > 500);
      
      if (shouldPaginate) {
        const allFlows = [];
        let cursor = apiParams.cursor || null;
        const batchSize = 500;
        
        do {
          const params = { ...apiParams, limit: batchSize };
          if (cursor) params.cursor = cursor;

          let data;
          let delay = 2000;
          for (let attempt = 1; attempt <= 5; attempt++) {
            try {
              ({ data } = await client.get('/flows', { params }));
              break;
            } catch (err) {
              if (err.response?.status === 429 && attempt < 5) {
                process.stderr.write(`Rate limited, retrying in ${delay / 1000}s... (attempt ${attempt}/5)\n`);
                await new Promise(r => setTimeout(r, delay));
                delay *= 2;
              } else {
                throw err;
              }
            }
          }

          allFlows.push(...(data.results || []));
          cursor = data.next_cursor || null;

          if (cursor) await new Promise(r => setTimeout(r, 500));

          // Stop if we've reached the target limit
          if (targetLimit && allFlows.length >= targetLimit) {
            allFlows.length = targetLimit; // Trim to exact limit
            break;
          }
        } while (cursor);
        
        if (options.stats) {
          const stats = computeStats(allFlows);
          console.log(JSON.stringify(stats, null, 2));
        } else {
          console.log(JSON.stringify({ results: allFlows, count: allFlows.length }, null, 2));
        }
      } else {
        // Single request mode
        if (targetLimit) {
          apiParams.limit = targetLimit;
        }
        
        const { data } = await client.get('/flows', { params: apiParams });
        
        if (options.stats) {
          const stats = computeStats(data.results || []);
          console.log(JSON.stringify(stats, null, 2));
        } else {
          console.log(JSON.stringify(data, null, 2));
        }
      }
    } catch (err) {
      console.error(JSON.stringify({ error: "Fetch failed", details: err.response?.data || err.message }));
    }
  }
};

function computeStats(flows) {
  const stats = {
    total_flows: flows.length,
    total_download: 0,
    total_upload: 0,
    total_bytes: 0,
    blocked_count: 0,
    regular_count: 0,
    unique_devices: new Set(),
    unique_domains: new Set(),
    unique_regions: new Set(),
    protocols: {},
    categories: {}
  };
  
  for (const flow of flows) {
    stats.total_download += flow.download || 0;
    stats.total_upload += flow.upload || 0;
    stats.total_bytes += (flow.download || 0) + (flow.upload || 0);
    
    if (flow.block) {
      stats.blocked_count++;
    } else {
      stats.regular_count++;
    }
    
    if (flow.device?.name) stats.unique_devices.add(flow.device.name);
    if (flow.device?.ip) stats.unique_devices.add(flow.device.ip);
    if (flow.destination?.name) stats.unique_domains.add(flow.destination.name);
    if (flow.region) stats.unique_regions.add(flow.region);
    
    const proto = flow.protocol || 'unknown';
    stats.protocols[proto] = (stats.protocols[proto] || 0) + 1;
    
    const cat = flow.category || '(none)';
    stats.categories[cat] = (stats.categories[cat] || 0) + 1;
  }
  
  stats.unique_devices = Array.from(stats.unique_devices);
  stats.unique_domains = Array.from(stats.unique_domains);
  stats.unique_regions = Array.from(stats.unique_regions);
  
  return stats;
}

module.exports = Flows;