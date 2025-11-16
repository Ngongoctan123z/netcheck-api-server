const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const net = require('net');
const axios = require('axios');
const { HttpsProxyAgent } = require('https-proxy-agent');
const { SocksProxyAgent } = require('socks-proxy-agent');

const fetch = (...args) => import('node-fetch').then(({ default: fetch }) => fetch(...args));

const app = express();

// Middleware CORS (giải quyết lỗi frontend gọi cross domain)
app.use(cors());
app.use(express.json({ limit: '100kb' }));

// Giới hạn tốc độ request để chống spam
const globalLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 200,
  message: { error: 'Too many requests, please slow down.' }
});
app.use('/api/', globalLimiter);

const DEFAULT_TIMEOUT_MS = 20000;
const MAX_TIMEOUT_MS = 30000;
const TEST_URL = 'https://httpbin.org/get';

// --- Helper function parse proxy ---
function parseProxyString(str) {
  const trimmed = (str || '').trim();
  if (!trimmed) return null;
  const atIndex = trimmed.indexOf('@');
  if (atIndex === -1) return null;

  const authPart = trimmed.slice(0, atIndex);
  const hostPart = trimmed.slice(atIndex + 1);

  const authSplit = authPart.split(':');
  if (authSplit.length !== 2) return null;
  const user = authSplit[0];
  const pass = authSplit[1];
  if (!user || !pass) return null;

  const hostSplit = hostPart.split(':');
  if (hostSplit.length !== 2) return null;

  const ip = hostSplit[0];
  const port = parseInt(hostSplit[1], 10);
  if (!ip || Number.isNaN(port) || port < 1 || port > 65535) return null;

  return { ip, port, user, pass };
}

// --- Check proxy TCP port ---
function tcpPortCheck(host, port, timeoutMs) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let done = false;
    const start = Date.now();

    const finish = (alive, message) => {
      if (done) return;
      done = true;
      socket.destroy();
      resolve({ alive, latency: Date.now() - start, message });
    };

    socket.setTimeout(timeoutMs);
    socket.on('connect', () => finish(true, 'TCP connect OK'));
    socket.on('timeout', () => finish(false, 'TCP timeout'));
    socket.on('error', (err) => finish(false, 'TCP error: ' + err.message));

    try {
      socket.connect(port, host);
    } catch (err) {
      finish(false, 'TCP connect error: ' + err.message);
    }
  });
}

// --- Tạo proxy agent tương ứng loại proxy ---
function createProxyAgent({ ip, port, user, pass, type }) {
  if (type === 'http' || type === 'https') {
    const proxyUrl = `http://${encodeURIComponent(user)}:${encodeURIComponent(pass)}@${ip}:${port}`;
    return new HttpsProxyAgent(proxyUrl);
  }
  if (type === 'socks4' || type === 'socks5') {
    const socksUrl = `${type}://${encodeURIComponent(user)}:${encodeURIComponent(pass)}@${ip}:${port}`;
    return new SocksProxyAgent(socksUrl);
  }
  throw new Error('Unsupported proxy type: ' + type);
}

// --- Check proxy HTTP (qua agent) ---
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
        return { alive: true, latency: totalLatency, statusCode: response.status, error: null, tries: attempt };
      }
      lastError = 'HTTP status ' + response.status;
    } catch (err) {
      const elapsed = Date.now() - startTime;
      totalLatency += elapsed;
      lastError = err.message || 'Proxy connection failed';
    }
  }
  return { alive: false, latency: totalLatency, statusCode: null, error: lastError, tries: maxTries };
}

// --- API: kiểm tra proxy mạnh ---
app.post('/api/check-proxy-strong', async (req, res) => {
  try {
    const { proxy, type } = req.body || {};
    let { timeoutMs } = req.body || {};

    if (!proxy || typeof proxy !== 'string') {
      return res.status(400).json({ error: 'Missing or invalid proxy' });
    }
    const allowedTypes = ['http', 'https', 'socks4', 'socks5'];
    if (!type || !allowedTypes.includes(type)) {
      return res.status(400).json({ error: 'Invalid proxy type. Supported: http, https, socks4, socks5' });
    }

    timeoutMs = parseInt(timeoutMs, 10);
    if (Number.isNaN(timeoutMs) || timeoutMs < 1000 || timeoutMs > MAX_TIMEOUT_MS) {
      timeoutMs = DEFAULT_TIMEOUT_MS;
    }

    const parsed = parseProxyString(proxy);
    if (!parsed) {
      return res.status(400).json({ error: 'Required format: user:pass@ip:port' });
    }
    const { ip, port, user, pass } = parsed;

    const tcp = await tcpPortCheck(ip, port, timeoutMs);
    if (!tcp.alive) {
      return res.json({ proxy, type, parsed: { ip, port, hasAuth: true }, timeoutMs, tcp, http: null, alive: false });
    }

    const http = await httpProxyCheck({ ip, port, user, pass }, type, timeoutMs);
    const alive = http.alive;

    return res.json({ proxy, type, parsed: { ip, port, hasAuth: true }, timeoutMs, tcp, http, alive });
  } catch (err) {
    console.error('Error /api/check-proxy-strong:', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

// --- API: lấy info IP ---
app.get('/ip-info', async (req, res) => {
  try {
    const response = await fetch('http://ip-api.com/json/');
    if (!response.ok) return res.status(500).json({ error: 'Failed to fetch IP info' });
    const data = await response.json();
    res.json(data);
  } catch (err) {
    console.error('Error fetching IP info:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`Strong proxy checker running on port ${PORT}`);
});
