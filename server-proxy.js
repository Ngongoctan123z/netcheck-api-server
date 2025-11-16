const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const net = require('net');
const axios = require('axios');
const { HttpsProxyAgent } = require('https-proxy-agent');
const { SocksProxyAgent } = require('socks-proxy-agent');
const fetch = (...args) => import('node-fetch').then(({ default: fetch }) => fetch(...args));

const app = express();
const PORT = process.env.PORT || 4000;
const DEFAULT_TIMEOUT_MS = 20000;
const MAX_TIMEOUT_MS = 30000;
const TEST_URL = 'https://httpbin.org/get';

// ✅ CORS: Cho phép gọi từ frontend local và Render
app.use(cors({
  origin: function (origin, callback) {
    const allowedOrigins = [
      'http://localhost:3000',
      'https://netcheck-crtu.onrender.com'
    ];
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  }
}));

app.use(express.json({ limit: '100kb' }));
app.use('/api/', rateLimit({
  windowMs: 60 * 1000,
  max: 200,
  message: { error: 'Too many requests, please slow down.' }
}));

function parseProxyString(str) {
  const trimmed = str?.trim();
  if (!trimmed || !trimmed.includes('@')) return null;
  const [authPart, hostPart] = trimmed.split('@');
  const [user, pass] = authPart.split(':');
  const [ip, portStr] = hostPart.split(':');
  const port = parseInt(portStr, 10);
  if (!user || !pass || !ip || Number.isNaN(port) || port < 1 || port > 65535) return null;
  return { ip, port, user, pass };
}

function tcpPortCheck(host, port, timeoutMs) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    const start = Date.now();
    let done = false;
    const finish = (alive, message) => {
      if (done) return;
      done = true;
      socket.destroy();
      resolve({ alive, latency: Date.now() - start, message });
    };
    socket.setTimeout(timeoutMs);
    socket.on('connect', () => finish(true, 'TCP connect OK'));
    socket.on('timeout', () => finish(false, 'TCP timeout'));
    socket.on('error', err => finish(false, 'TCP error: ' + err.message));
    try {
      socket.connect(port, host);
    } catch (err) {
      finish(false, 'TCP connect error: ' + err.message);
    }
  });
}

function createProxyAgent({ ip, port, user, pass, type }) {
  const encoded = `${encodeURIComponent(user)}:${encodeURIComponent(pass)}@${ip}:${port}`;
  if (type === 'http' || type === 'https') return new HttpsProxyAgent(`http://${encoded}`);
  if (type === 'socks4' || type === 'socks5') return new SocksProxyAgent(`${type}://${encoded}`);
  throw new Error('Unsupported proxy type: ' + type);
}

async function httpProxyCheck(parsed, type, timeoutMs, maxTries = 2) {
  let lastError = null;
  let totalLatency = 0;
  for (let attempt = 1; attempt <= maxTries; attempt++) {
    const startTime = Date.now();
    try {
      const agent = createProxyAgent({ ...parsed, type });
      const response = await axios.get(TEST_URL, {
        httpAgent: agent,
        httpsAgent: agent,
        timeout: timeoutMs,
        proxy: false,
        validateStatus: () => true
      });
      const elapsed = Date.now() - startTime;
      totalLatency += elapsed;
      if (response.status >= 200 && response.status < 400) {
        return {
          alive: true,
          latency: totalLatency,
          statusCode: response.status,
          error: null,
          tries: attempt
        };
      }
      lastError = 'HTTP status ' + response.status;
    } catch (err) {
      totalLatency += Date.now() - startTime;
      lastError = err.message || 'Proxy connection failed';
    }
  }
  return {
    alive: false,
    latency: totalLatency,
    statusCode: null,
    error: lastError,
    tries: maxTries
  };
}

app.post('/api/check-proxy-strong', async (req, res) => {
  try {
    const { proxy, type, timeoutMs: rawTimeout } = req.body || {};
    const allowedTypes = ['http', 'https', 'socks4', 'socks5'];
    if (!proxy || typeof proxy !== 'string') {
      return res.status(400).json({ error: 'Missing or invalid proxy' });
    }
    if (!allowedTypes.includes(type)) {
      return res.status(400).json({ error: 'Invalid proxy type. Supported: http, https, socks4, socks5' });
    }
    const timeoutMs = Math.min(Math.max(parseInt(rawTimeout, 10) || DEFAULT_TIMEOUT_MS, 1000), MAX_TIMEOUT_MS);
    const parsed = parseProxyString(proxy);
    if (!parsed) {
      return res.status(400).json({ error: 'Required format: user:pass@ip:port' });
    }
    const tcp = await tcpPortCheck(parsed.ip, parsed.port, timeoutMs);
    if (!tcp.alive) {
      return res.json({
        proxy,
        type,
        parsed: { ip: parsed.ip, port: parsed.port, hasAuth: true },
        timeoutMs,
        tcp,
        http: null,
        alive: false
      });
    }
    const http = await httpProxyCheck(parsed, type, timeoutMs);
    return res.json({
      proxy,
      type,
      parsed: { ip: parsed.ip, port: parsed.port, hasAuth: true },
      timeoutMs,
      tcp,
      http,
      alive: http.alive
    });
  } catch (err) {
    console.error('Error /api/check-proxy-strong:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/ip-info', async (req, res) => {
  try {
    const response = await fetch('https://ip-api.com/json/');
    if (!response.ok) return res.status(500).json({ error: 'Failed to fetch IP info' });
    const data = await response.json();
    res.json(data);
  } catch (err) {
    console.error('Error fetching IP info:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.listen(PORT, () => {
  console.log(`✅ Strong proxy checker running on port ${PORT}`);
});
