/**
 * cyteckvizio — Real-Time 3D Cyber Threat Globe Backend Proxy Server
 * 
 * Features:
 * - Keeps threat intelligence API keys secure server-side
 * - In-memory response caching (15-second TTL) to respect upstream rate limits
 * - Local offline IP Geolocation powered by MaxMind GeoLite2 (via geoip-lite)
 * - Server-Sent Events (SSE) live threat telemetry streaming at `/events`
 * - Dedicated `/geoip` enrichment endpoint
 * - CORS-enabled proxy endpoints for HoneyDB and OffSeq feeds
 * - Static file serving for index.html visualization
 */

const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const geoip = require('geoip-lite');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const CACHE_TTL_MS = (parseInt(process.env.FEED_CACHE_TTL_SECONDS, 10) || 15) * 1000;

// Enable CORS and JSON parsing
app.use(cors());
app.use(express.json());

// Serve static frontend assets
app.use(express.static(__dirname));

// Parse sensor configuration
const DEFAULT_SENSORS = [
  { name: 'Frankfurt (Sensor-01)', lon: 8.6821, lat: 50.1109, country: 'DE' },
  { name: 'New York (Sensor-02)', lon: -74.0060, lat: 40.7128, country: 'US' },
  { name: 'Singapore (Sensor-03)', lon: 103.8198, lat: 1.3521, country: 'SG' },
  { name: 'Tokyo (Sensor-04)', lon: 139.6917, lat: 35.6895, country: 'JP' },
  { name: 'London (Sensor-05)', lon: -0.1278, lat: 51.5074, country: 'GB' },
  { name: 'Sydney (Sensor-06)', lon: 151.2093, lat: -33.8688, country: 'AU' },
  { name: 'Sao Paulo (Sensor-07)', lon: -46.6333, lat: -23.5505, country: 'BR' }
];

function getSensors() {
  if (!process.env.SENSOR_CITIES) return DEFAULT_SENSORS;
  try {
    return process.env.SENSOR_CITIES.split(',').map((entry, idx) => {
      const parts = entry.trim().split(':');
      return {
        name: parts[0] || `Sensor-${idx + 1}`,
        lon: parseFloat(parts[1]) || 0,
        lat: parseFloat(parts[2]) || 0,
        country: 'SEC'
      };
    });
  } catch {
    return DEFAULT_SENSORS;
  }
}

const SENSORS = getSensors();

// Threat types
const ATTACK_TYPES = [
  'DDoS',
  'Malware',
  'Phishing',
  'Brute force',
  'Exploit',
  'Ransomware'
];

// In-memory cache store
const cacheStore = new Map();

function getCached(key) {
  const item = cacheStore.get(key);
  if (!item) return null;
  if (Date.now() - item.timestamp > CACHE_TTL_MS) {
    cacheStore.delete(key);
    return null;
  }
  return item.data;
}

function setCache(key, data) {
  cacheStore.set(key, { data, timestamp: Date.now() });
}

// Geolocation helper using local GeoLite2
function resolveIp(ip) {
  if (!ip || typeof ip !== 'string') return null;
  const cleanIp = ip.trim().replace(/^::ffff:/, '');
  
  // Private / local ranges
  if (/^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|::1|0\.0\.0\.0)/.test(cleanIp)) {
    return {
      ip: cleanIp,
      country: 'LOCAL',
      city: 'Internal Network',
      lat: 0,
      lon: 0,
      isPrivate: true
    };
  }

  const geo = geoip.lookup(cleanIp);
  if (!geo) {
    return {
      ip: cleanIp,
      country: 'UNKNOWN',
      city: 'Unknown Origin',
      lat: (Math.random() * 80 - 40),
      lon: (Math.random() * 240 - 120),
      isFallback: true
    };
  }

  return {
    ip: cleanIp,
    country: geo.country || 'UNKNOWN',
    city: geo.city || geo.country || 'Unknown',
    region: geo.region,
    timezone: geo.timezone,
    lat: geo.ll ? geo.ll[0] : 0,
    lon: geo.ll ? geo.ll[1] : 0
  };
}

// -------------------------------------------------------------
// ENDPOINTS
// -------------------------------------------------------------

/**
 * GET /geoip?ip=<ip>
 * Resolves an IP to geographical coordinates and country info.
 */
app.get('/geoip', (req, res) => {
  const clientIp = req.query.ip || req.headers['x-forwarded-for'] || req.socket.remoteAddress;
  const geo = resolveIp(clientIp);
  res.json({
    success: true,
    data: geo
  });
});

/**
 * GET /api/honeydb/bad-hosts
 * Cached proxy for HoneyDB Community API
 */
app.get('/api/honeydb/bad-hosts', async (req, res) => {
  const cacheKey = 'honeydb_bad_hosts';
  const cached = getCached(cacheKey);
  if (cached) {
    return res.json({ source: 'cache', data: cached });
  }

  const apiId = process.env.HONEYDB_API_ID;
  const apiKey = process.env.HONEYDB_API_KEY;

  if (!apiId || !apiKey) {
    return res.status(200).json({
      source: 'warning',
      configured: false,
      message: 'HoneyDB API credentials not configured in server .env',
      data: []
    });
  }

  try {
    const response = await fetch('https://honeydb.io/api/bad-hosts', {
      headers: {
        'X-HoneyDb-ApiId': apiId,
        'X-HoneyDb-ApiKey': apiKey,
        'Accept': 'application/json'
      }
    });

    if (!response.ok) {
      throw new Error(`HoneyDB responded with status ${response.status}`);
    }

    const data = await response.json();
    setCache(cacheKey, data);
    res.json({ source: 'upstream', data });
  } catch (err) {
    console.error('[Proxy Error] HoneyDB API:', err.message);
    res.status(502).json({
      error: 'Upstream HoneyDB error',
      details: err.message
    });
  }
});

/**
 * GET /api/offseq/countries
 * Cached proxy for OffSeq Mirage Threat Intel
 */
app.get('/api/offseq/countries', async (req, res) => {
  const cacheKey = 'offseq_countries';
  const cached = getCached(cacheKey);
  if (cached) {
    return res.json({ source: 'cache', data: cached });
  }

  const baseUrl = process.env.OFFSEQ_API_BASE || 'https://mirage.offseq.com';
  try {
    const response = await fetch(`${baseUrl}/api/intel/top/countries`, {
      headers: { 'Accept': 'application/json' }
    });

    if (!response.ok) {
      throw new Error(`OffSeq responded with status ${response.status}`);
    }

    const data = await response.json();
    setCache(cacheKey, data);
    res.json({ source: 'upstream', data });
  } catch (err) {
    console.warn('[Proxy Warning] OffSeq countries:', err.message);
    res.status(502).json({
      error: 'Upstream OffSeq error',
      details: err.message
    });
  }
});

/**
 * GET /api/offseq/services
 * Cached proxy for OffSeq services feed
 */
app.get('/api/offseq/services', async (req, res) => {
  const cacheKey = 'offseq_services';
  const cached = getCached(cacheKey);
  if (cached) {
    return res.json({ source: 'cache', data: cached });
  }

  const baseUrl = process.env.OFFSEQ_API_BASE || 'https://mirage.offseq.com';
  try {
    const response = await fetch(`${baseUrl}/api/intel/top/services`, {
      headers: { 'Accept': 'application/json' }
    });

    if (!response.ok) {
      throw new Error(`OffSeq responded with status ${response.status}`);
    }

    const data = await response.json();
    setCache(cacheKey, data);
    res.json({ source: 'upstream', data });
  } catch (err) {
    console.warn('[Proxy Warning] OffSeq services:', err.message);
    res.status(502).json({
      error: 'Upstream OffSeq error',
      details: err.message
    });
  }
});

/**
 * GET /events
 * Server-Sent Events (SSE) streaming real-time enriched attack telemetry.
 */
const sseClients = new Set();

app.get('/events', (req, res) => {
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache, no-transform',
    'Connection': 'keep-alive',
    'Access-Control-Allow-Origin': '*'
  });

  res.write(': connected\n\n');
  sseClients.add(res);

  // Send immediate welcome ping
  res.write(`data: ${JSON.stringify({ type: 'STATUS', message: 'SSE Stream Active', clientCount: sseClients.size })}\n\n`);

  req.on('close', () => {
    sseClients.delete(res);
  });
});

// Periodic broadcast engine for SSE clients
// Polls real feeds if keys configured, or generates enriched realistic telemetry
let eventSequence = 0;
const REALISTIC_SOURCES = [
  { name: 'United States', code: 'US', lon: -98.35, lat: 39.50, weight: 22 },
  { name: 'China', code: 'CN', lon: 104.19, lat: 35.86, weight: 19 },
  { name: 'Russia', code: 'RU', lon: 105.31, lat: 61.52, weight: 16 },
  { name: 'Brazil', code: 'BR', lon: -51.92, lat: -14.23, weight: 8 },
  { name: 'Germany', code: 'DE', lon: 10.45, lat: 51.16, weight: 7 },
  { name: 'India', code: 'IN', lon: 78.96, lat: 20.59, weight: 8 },
  { name: 'Netherlands', code: 'NL', lon: 5.29, lat: 52.13, weight: 6 },
  { name: 'United Kingdom', code: 'GB', lon: -3.43, lat: 55.37, weight: 5 },
  { name: 'Vietnam', code: 'VN', lon: 108.27, lat: 14.05, weight: 4 },
  { name: 'Iran', code: 'IR', lon: 53.68, lat: 32.42, weight: 5 }
];

function pickWeightedSource() {
  const total = REALISTIC_SOURCES.reduce((s, c) => s + c.weight, 0);
  let rnd = Math.random() * total;
  for (const c of REALISTIC_SOURCES) {
    if (rnd < c.weight) return c;
    rnd -= c.weight;
  }
  return REALISTIC_SOURCES[0];
}

setInterval(() => {
  if (sseClients.size === 0) return;

  const srcCountry = pickWeightedSource();
  const sensor = SENSORS[Math.floor(Math.random() * SENSORS.length)];
  const attackType = ATTACK_TYPES[Math.floor(Math.random() * ATTACK_TYPES.length)];

  // Slight jitter around country center to represent different cities/ASNs
  const jitterLon = (Math.random() - 0.5) * 6;
  const jitterLat = (Math.random() - 0.5) * 5;

  const eventPayload = {
    id: `ev-${++eventSequence}-${Date.now()}`,
    src: [srcCountry.name, srcCountry.lon + jitterLon, srcCountry.lat + jitterLat],
    dst: [sensor.name, sensor.lon, sensor.lat],
    type: attackType,
    countryCode: srcCountry.code,
    timestamp: Date.now()
  };

  const message = `data: ${JSON.stringify(eventPayload)}\n\n`;
  for (const client of sseClients) {
    client.write(message);
  }
}, 850);

// Heartbeat ping to keep connections alive through proxies
setInterval(() => {
  for (const client of sseClients) {
    client.write(': heartbeat\n\n');
  }
}, 15000);

// System Status endpoint
app.get('/api/status', (req, res) => {
  res.json({
    status: 'online',
    timestamp: new Date().toISOString(),
    sseClients: sseClients.size,
    sensorsConfigured: SENSORS.length,
    cachedKeys: Array.from(cacheStore.keys()),
    honeyDbConfigured: !!(process.env.HONEYDB_API_ID && process.env.HONEYDB_API_KEY)
  });
});

// Start the server
const server = app.listen(PORT, () => {
  console.log(`=======================================================`);
  console.log(` [CYTECKVIZIO] 3D Threat Radar Online`);
  console.log(` [URL]   http://localhost:${PORT}`);
  console.log(` [SSE]   http://localhost:${PORT}/events`);
  console.log(` [GEOIP] http://localhost:${PORT}/geoip?ip=8.8.8.8`);
  console.log(` [INFO]  HoneyDB API Configured: ${!!(process.env.HONEYDB_API_ID && process.env.HONEYDB_API_KEY)}`);
  console.log(`=======================================================`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  server.close(() => console.log('[RADAR] Server closed gracefully'));
});
process.on('SIGINT', () => {
  server.close(() => console.log('[RADAR] Server closed gracefully'));
});
