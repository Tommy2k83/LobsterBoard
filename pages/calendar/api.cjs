const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const https = require('https');
const http = require('http');
const os = require('os');

module.exports = function(ctx) {
  function readConfig() {
    try { return ctx.readData('config.json'); } catch { return { sources: [] }; }
  }
  function writeConfig(data) { ctx.writeData('config.json', data); }

  // --- URL validation (SSRF protection) ---
  function isUrlSafe(urlStr) {
    try {
      const u = new URL(urlStr);
      if (u.protocol !== 'https:') return false;
      const host = u.hostname.toLowerCase();
      // Block localhost, private IPs, link-local, cloud metadata
      if (host === 'localhost' || host === '::1') return false;
      if (/^127\./.test(host)) return false;
      if (/^10\./.test(host)) return false;
      if (/^172\.(1[6-9]|2\d|3[01])\./.test(host)) return false;
      if (/^192\.168\./.test(host)) return false;
      if (/^169\.254\./.test(host)) return false;
      if (/^0\./.test(host) || host === '0.0.0.0') return false;
      if (host.startsWith('fc') || host.startsWith('fd') || host.startsWith('fe80')) return false;
      return true;
    } catch { return false; }
  }

  function validateSource(body) {
    const errors = [];
    if (body.type && !['ical', 'cron'].includes(body.type)) errors.push('type must be "ical" or "cron"');
    if (body.color && !/^#[0-9a-f]{6}$/i.test(body.color)) errors.push('color must be hex format #rrggbb');
    if (body.name && body.name.length > 100) errors.push('name must be 100 chars or less');
    if (body.url && body.type !== 'cron' && !isUrlSafe(body.url)) errors.push('url must be a valid https:// URL (no private/local addresses)');
    return errors;
  }

  // --- iCal cache (5 min, max 20 feeds) ---
  const icalCache = {};
  const MAX_CACHE = 20;
  function fetchIcalRaw(url) {
    if (!isUrlSafe(url)) return Promise.reject(new Error('URL blocked by security policy'));
    return new Promise((resolve, reject) => {
      function doFetch(u, redirects) {
        if (redirects > 3) return reject(new Error('Too many redirects'));
        if (!isUrlSafe(u)) return reject(new Error('Redirect blocked by security policy'));
        const mod = u.startsWith('https') ? https : http;
        const req = mod.get(u, { headers: { 'User-Agent': 'LobsterBoard/1.0' }, timeout: 15000 }, res => {
          if ([301,302,307,308].includes(res.statusCode) && res.headers.location) {
            res.resume(); return doFetch(res.headers.location, redirects+1);
          }
          let body = '';
          res.on('data', c => { body += c; if (body.length > 5e6) res.destroy(); });
          res.on('end', () => resolve(body));
        });
        req.on('error', reject);
        req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
      }
      doFetch(url, 0);
    });
  }

  function parseIcalDate(s) {
    if (!s) return null;
    if (s.length === 8) return new Date(s.slice(0,4)+'-'+s.slice(4,6)+'-'+s.slice(6,8)+'T00:00:00');
    const d = s.replace(/Z$/,'');
    return new Date(d.slice(0,4)+'-'+d.slice(4,6)+'-'+d.slice(6,8)+'T'+d.slice(9,11)+':'+d.slice(11,13)+':'+d.slice(13,15)+(s.endsWith('Z')?'Z':''));
  }

  function parseIcalEvents(text, rangeStart, rangeEnd) {
    const events = [];
    const unfolded = text.replace(/\r?\n[ \t]/g, '');
    const blocks = unfolded.split('BEGIN:VEVENT');
    const MAX_EVENTS_PER_FEED = 2000;
    for (let i = 1; i < blocks.length && events.length < MAX_EVENTS_PER_FEED; i++) {
      const block = blocks[i].split('END:VEVENT')[0];
      if (!block) continue;
      const get = (key) => { const m = block.match(new RegExp('^' + key + '(?:;[^:]*)?:(.*)$', 'm')); return m ? m[1].trim() : ''; };
      const summary = get('SUMMARY').replace(/\\,/g,',').replace(/\\n/g,' ');
      const description = get('DESCRIPTION').replace(/\\,/g,',').replace(/\\n/g,'\n');
      const location = get('LOCATION').replace(/\\,/g,',');
      const dtstart = get('DTSTART');
      const dtend = get('DTEND');
      const rrule = get('RRULE');
      const uid = get('UID') || `ev-${i}`;
      if (!dtstart) continue;
      const allDay = dtstart.length === 8;
      const start = parseIcalDate(dtstart);
      const end = parseIcalDate(dtend);
      if (!start || isNaN(start.getTime())) continue;
      const duration = end ? end.getTime() - start.getTime() : (allDay ? 86400000 : 3600000);

      if (rrule) {
        const rr = parseRRule(rrule);
        const occurrences = expandRRule(rr, start, rangeStart, rangeEnd);
        for (const occ of occurrences) {
          events.push({ uid, summary: summary||'Untitled', start: occ.toISOString(), end: new Date(occ.getTime()+duration).toISOString(), allDay, description, location });
        }
      } else {
        const evEnd = end ? end : new Date(start.getTime() + duration);
        if (evEnd >= rangeStart && start <= rangeEnd) {
          events.push({ uid, summary: summary||'Untitled', start: start.toISOString(), end: evEnd.toISOString(), allDay, description, location });
        }
      }
    }
    return events;
  }

  function parseRRule(str) {
    const r = {};
    str.split(';').forEach(p => { const [k,v] = p.split('='); r[k] = v; });
    return r;
  }

  function expandRRule(rr, start, rangeStart, rangeEnd) {
    const freq = rr.FREQ;
    const count = rr.COUNT ? parseInt(rr.COUNT) : 1000;
    const until = rr.UNTIL ? parseIcalDate(rr.UNTIL) : rangeEnd;
    const interval = parseInt(rr.INTERVAL || '1');
    const limit = Math.min(count, 500);
    const results = [];
    let cur = new Date(start);
    for (let i = 0; i < limit && cur <= until && cur <= rangeEnd; i++) {
      if (cur >= rangeStart) results.push(new Date(cur));
      if (freq === 'DAILY') cur.setDate(cur.getDate() + interval);
      else if (freq === 'WEEKLY') cur.setDate(cur.getDate() + 7 * interval);
      else if (freq === 'MONTHLY') cur.setMonth(cur.getMonth() + interval);
      else if (freq === 'YEARLY') cur.setFullYear(cur.getFullYear() + interval);
      else break;
    }
    return results;
  }

  async function getIcalEvents(source, rangeStart, rangeEnd) {
    const cacheKey = source.url;
    const cached = icalCache[cacheKey];
    let raw;
    if (cached && Date.now() - cached.ts < 300000) {
      raw = cached.data;
    } else {
      try {
              raw = await fetchIcalRaw(source.url);
              // Evict oldest if cache is full
              const keys = Object.keys(icalCache);
              if (keys.length >= MAX_CACHE) { delete icalCache[keys[0]]; }
              icalCache[cacheKey] = { ts: Date.now(), data: raw };
            }
      catch { return []; }
    }
    return parseIcalEvents(raw, rangeStart, rangeEnd).map(ev => ({
      id: `ical-${source.id}-${ev.uid}-${ev.start}`,
      title: ev.summary, start: ev.start, end: ev.end, allDay: ev.allDay,
      color: source.color || '#58a6ff', source: source.name,
      description: ev.description || '', location: ev.location || ''
    }));
  }

  // --- Cron parser ---
  function parseCronField(field, min, max) {
    const values = new Set();
    for (const part of field.split(',')) {
      if (part === '*') { for (let i = min; i <= max; i++) values.add(i); }
      else if (part.includes('/')) {
        const [range, stepStr] = part.split('/');
        const step = parseInt(stepStr);
        let start = min, end = max;
        if (range !== '*') { const [a,b] = range.split('-'); start = parseInt(a); end = b !== undefined ? parseInt(b) : max; }
        for (let i = start; i <= end; i += step) values.add(i);
      } else if (part.includes('-')) {
        const [a,b] = part.split('-');
        for (let i = parseInt(a); i <= parseInt(b); i++) values.add(i);
      } else { values.add(parseInt(part)); }
    }
    return values;
  }

  function getCronOccurrences(expr, tz, rangeStart, rangeEnd) {
    const parts = expr.trim().split(/\s+/);
    if (parts.length < 5) return [];
    const mins = parseCronField(parts[0], 0, 59);
    const hours = parseCronField(parts[1], 0, 23);
    const doms = parseCronField(parts[2], 1, 31);
    const mons = parseCronField(parts[3], 1, 12);
    const dows = parseCronField(parts[4], 0, 6);
    const domWild = parts[2] === '*';
    const dowWild = parts[4] === '*';

    const results = [];
    const cur = new Date(rangeStart);
    cur.setMinutes(0); cur.setSeconds(0); cur.setMilliseconds(0);
    // iterate day by day
    const endMs = rangeEnd.getTime();
    while (cur.getTime() <= endMs && results.length < 500) {
      const m = cur.getMonth() + 1;
      const d = cur.getDate();
      const dow = cur.getDay();
      if (mons.has(m)) {
        const domMatch = doms.has(d);
        const dowMatch = dows.has(dow);
        // Standard cron: if both dom and dow are restricted, OR them; if one is *, use the other
        const dayOk = (domWild && dowWild) || (domWild ? dowMatch : (dowWild ? domMatch : (domMatch || dowMatch)));
        if (dayOk) {
          for (const h of [...hours].sort((a,b)=>a-b)) {
            for (const mn of [...mins].sort((a,b)=>a-b)) {
              const t = new Date(cur);
              t.setHours(h, mn, 0, 0);
              if (t >= rangeStart && t <= rangeEnd) results.push(t.toISOString());
            }
          }
        }
      }
      cur.setDate(cur.getDate() + 1);
    }
    return results;
  }

  function getCronEvents(rangeStart, rangeEnd) {
    const cronFile = path.join(os.homedir(), '.openclaw', 'cron', 'jobs.json');
    let jobs = [];
    try {
      const data = JSON.parse(fs.readFileSync(cronFile, 'utf8'));
      jobs = data.jobs || [];
    } catch { return []; }

    const events = [];
    for (const job of jobs) {
      if (!job.enabled || !job.schedule || job.schedule.kind !== 'cron') continue;
      const occurrences = getCronOccurrences(job.schedule.expr, job.schedule.tz, rangeStart, rangeEnd);
      for (const occ of occurrences) {
        events.push({
          id: `cron-${job.id}-${occ}`,
          title: `⏰ ${job.name}`,
          start: occ,
          end: new Date(new Date(occ).getTime() + 900000).toISOString(), // 15 min duration
          allDay: false,
          color: '#f0883e',
          source: 'Cron Jobs',
          description: job.payload?.message?.slice(0, 200) || ''
        });
      }
    }
    return events;
  }

  return {
    routes: {
      'GET /sources': () => {
        const config = readConfig();
        return config.sources || [];
      },

      'POST /sources': (req, res, { body }) => {
        const errors = validateSource(body);
        if (errors.length) { res.statusCode = 400; return { error: errors.join('; ') }; }
        const config = readConfig();
        if (!config.sources) config.sources = [];
        const source = {
          id: crypto.randomUUID(),
          type: body.type || 'ical',
          name: (body.name || 'Untitled').slice(0, 100),
          url: body.url || '',
          color: body.color || '#58a6ff',
          enabled: body.enabled !== false
        };
        config.sources.push(source);
        writeConfig(config);
        res.statusCode = 201;
        return source;
      },

      'PATCH /sources/:id': (req, res, { body, params }) => {
        const errors = validateSource(body);
        if (errors.length) { res.statusCode = 400; return { error: errors.join('; ') }; }
        const config = readConfig();
        const idx = (config.sources||[]).findIndex(s => s.id === params.id);
        if (idx === -1) { res.statusCode = 404; return { error: 'Not found' }; }
        const allowed = ['name','url','color','enabled','type'];
        allowed.forEach(k => { if (body[k] !== undefined) config.sources[idx][k] = body[k]; });
        writeConfig(config);
        return config.sources[idx];
      },

      'DELETE /sources/:id': (req, res, { params }) => {
        const config = readConfig();
        const idx = (config.sources||[]).findIndex(s => s.id === params.id);
        if (idx === -1) { res.statusCode = 404; return { error: 'Not found' }; }
        config.sources.splice(idx, 1);
        writeConfig(config);
        return { ok: true };
      },

      'GET /events': async (req, res, { query }) => {
        const rangeStart = new Date(query.start || new Date());
        const rangeEnd = new Date(query.end || new Date(Date.now() + 30*86400000));
        const config = readConfig();
        const allEvents = [];

        // Cron events always included
        allEvents.push(...getCronEvents(rangeStart, rangeEnd));

        // iCal sources
        const icalSources = (config.sources || []).filter(s => s.enabled && s.type === 'ical' && s.url);
        const results = await Promise.allSettled(icalSources.map(s => getIcalEvents(s, rangeStart, rangeEnd)));
        results.forEach(r => { if (r.status === 'fulfilled') allEvents.push(...r.value); });

        allEvents.sort((a,b) => new Date(a.start) - new Date(b.start));
        return allEvents;
      },

      'GET /cron-events': (req, res, { query }) => {
        const rangeStart = new Date(query.start || new Date());
        const rangeEnd = new Date(query.end || new Date(Date.now() + 30*86400000));
        return getCronEvents(rangeStart, rangeEnd);
      }
    }
  };
};
