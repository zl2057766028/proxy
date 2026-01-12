#!/usr/bin/env node

/**
 * ✅ 适配 Hugging Face Spaces（Docker）“Starting…”问题的完整 index.js
 * 关键改动：
 *  1) 必须监听 process.env.PORT（HF 默认 7860）并绑定 0.0.0.0
 *  2) 解析 WS 首包全部加边界检查，避免 Node 20+ Buffer 越界崩溃导致无限重启
 *  3) 哪吒下载/外部请求增加超时与兜底，避免启动阶段卡死
 *  4) AUTO_ACCESS 做字符串布尔解析，避免环境变量 "false" 被当成 true
 */

const os = require('os');
const http = require('http');
const fs = require('fs');
const axios = require('axios');
const net = require('net');
const path = require('path');
const crypto = require('crypto');
const { Buffer } = require('buffer');
const { exec, execSync } = require('child_process');
const { WebSocket, createWebSocketStream } = require('ws');

// ======== ENV ========
const UUID = process.env.UUID || '5efabea4-f6d4-91fd-b8f0-17e004c89c60';
const NEZHA_SERVER = process.env.NEZHA_SERVER || '';
const NEZHA_PORT = process.env.NEZHA_PORT || '';
const NEZHA_KEY = process.env.NEZHA_KEY || '';
const DOMAIN = process.env.DOMAIN || 'hugproxy.zlzl.de5.net';

// HF Spaces 环境变量常为字符串： "true"/"false"
const AUTO_ACCESS = (() => {
  const v = process.env.AUTO_ACCESS;
  if (v === undefined || v === null) return false;
  if (typeof v === 'boolean') return v;
  const s = String(v).trim().toLowerCase();
  return s === 'true' || s === '1' || s === 'yes' || s === 'y' || s === 'on';
})();

const WSPATH = process.env.WSPATH || UUID.slice(0, 8);
const SUB_PATH = process.env.SUB_PATH || 'sub';
const NAME = process.env.NAME || '';

// ✅ HF 默认 PORT=7860；仍然以 env 为准
const PORT = Number(process.env.PORT || 7860);

// ======== STATE ========
let uuid = UUID.replace(/-/g, '');
let CurrentDomain = DOMAIN;
let Tls = 'tls';
let CurrentPort = 443;
let ISP = '';

const DNS_SERVERS = ['8.8.4.4', '1.1.1.1'];
const BLOCKED_DOMAINS = [
  'speedtest.net',
  'fast.com',
  'speedtest.cn',
  'speed.cloudflare.com',
  'speedof.me',
  'testmy.net',
  'bandwidth.place',
  'speed.io',
  'librespeed.org',
  'speedcheck.org',
];

// ======== HELPERS ========
function isBlockedDomain(host) {
  if (!host) return false;
  const hostLower = host.toLowerCase();
  return BLOCKED_DOMAINS.some(blocked => hostLower === blocked || hostLower.endsWith('.' + blocked));
}

async function getisp() {
  try {
    const res = await axios.get('https://api.ip.sb/geoip', {
      headers: { 'User-Agent': 'Mozilla/5.0' },
      timeout: 3000,
    });
    const data = res.data;
    ISP = `${data.country_code}-${data.isp}`.replace(/ /g, '_');
  } catch (e) {
    try {
      const res2 = await axios.get('http://ip-api.com/json', {
        headers: { 'User-Agent': 'Mozilla/5.0' },
        timeout: 3000,
      });
      const data2 = res2.data;
      ISP = `${data2.countryCode}-${data2.org}`.replace(/ /g, '_');
    } catch (e2) {
      ISP = 'Unknown';
    }
  }
}

async function getip() {
  // 若 DOMAIN 未配置或还是占位符，则用公网 IPv4，并禁用 tls（直接端口）
  if (!DOMAIN || DOMAIN === 'your-domain.com') {
    try {
      const res = await axios.get('https://api-ipv4.ip.sb/ip', { timeout: 5000 });
      const ip = String(res.data).trim();
      CurrentDomain = ip;
      Tls = 'none';
      CurrentPort = PORT; // 直接用本服务端口
    } catch (e) {
      console.error('Failed to get IP:', e.message);
      CurrentDomain = 'change-your-domain.com';
      Tls = 'tls';
      CurrentPort = 443;
    }
  } else {
    CurrentDomain = DOMAIN;
    Tls = 'tls';
    CurrentPort = 443;
  }
}

// Custom DNS resolve (via DoH)
function resolveHost(host) {
  return new Promise((resolve, reject) => {
    // ipv4 literal
    if (/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(host)) {
      resolve(host);
      return;
    }

    let attempts = 0;
    function tryNextDNS() {
      if (attempts >= DNS_SERVERS.length) {
        reject(new Error(`Failed to resolve ${host} with all DNS servers`));
        return;
      }
      attempts++;

      const dnsQuery = `https://dns.google/resolve?name=${encodeURIComponent(host)}&type=A`;
      axios
        .get(dnsQuery, {
          timeout: 5000,
          headers: { Accept: 'application/dns-json' },
        })
        .then(response => {
          const data = response.data;
          if (data.Status === 0 && data.Answer && data.Answer.length > 0) {
            const ip = data.Answer.find(record => record.type === 1);
            if (ip) {
              resolve(ip.data);
              return;
            }
          }
          tryNextDNS();
        })
        .catch(() => tryNextDNS());
    }

    tryNextDNS();
  });
}

// ======== HTTP SERVER ========
const httpServer = http.createServer(async (req, res) => {
  try {
    if (req.url === '/') {
      const filePath = path.join(__dirname, 'index.html');
      fs.readFile(filePath, 'utf8', (err, content) => {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        if (err) {
          res.end('Hello world!');
          return;
        }
        res.end(content);
      });
      return;
    }

    if (req.url === `/${SUB_PATH}`) {
      await getisp();
      await getip();

      const namePart = NAME ? `${NAME}-${ISP}` : ISP;
      const tlsParam = Tls === 'tls' ? 'tls' : 'none';
      const ssTlsParam = Tls === 'tls' ? 'tls;' : '';

      const vlsURL = `vless://${UUID}@${CurrentDomain}:${CurrentPort}?encryption=none&security=${tlsParam}&sni=${CurrentDomain}&fp=chrome&type=ws&host=${CurrentDomain}&path=%2F${WSPATH}#${namePart}`;
      const troURL = `trojan://${UUID}@${CurrentDomain}:${CurrentPort}?security=${tlsParam}&sni=${CurrentDomain}&fp=chrome&type=ws&host=${CurrentDomain}&path=%2F${WSPATH}#${namePart}`;
      const ssMethodPassword = Buffer.from(`none:${UUID}`).toString('base64');
      const ssURL = `ss://${ssMethodPassword}@${CurrentDomain}:${CurrentPort}?plugin=v2ray-plugin;mode%3Dwebsocket;host%3D${CurrentDomain};path%3D%2F${WSPATH};${ssTlsParam}sni%3D${CurrentDomain};skip-cert-verify%3Dtrue;mux%3D0#${namePart}`;

      const subscription = `${vlsURL}\n${troURL}\n${ssURL}`;
      const base64Content = Buffer.from(subscription).toString('base64');

      res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end(base64Content + '\n');
      return;
    }

    res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('Not Found\n');
  } catch (e) {
    res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('Internal Server Error\n');
  }
});

// ======== WS PROTOCOL PARSERS (SAFE) ========

// VLESS 处理（加长度检查，避免 Buffer 越界）
function handleVlsConnection(ws, msg) {
  try {
    if (!Buffer.isBuffer(msg)) msg = Buffer.from(msg);

    // 最少要有：version(1) + uuid(16) + optLen(1) + cmd(1) + port(2) + atyp(1) = 22
    if (msg.length < 22) return false;

    const VERSION = msg[0];
    const id = msg.slice(1, 17);
    if (id.length !== 16) return false;
    if (!id.every((v, i) => v == parseInt(uuid.substr(i * 2, 2), 16))) return false;

    const optLen = msg.readUInt8(17);
    let i = 19 + optLen; // 17: optLen, 18: cmd, 19..: opt
    if (i < 0 || i >= msg.length) return false;

    // port(2) + atyp(1)
    if (i + 3 > msg.length) return false;

    const port = msg.readUInt16BE(i);
    i += 2;

    const ATYP = msg.readUInt8(i);
    i += 1;

    let host = '';
    if (ATYP === 1) {
      if (i + 4 > msg.length) return false;
      host = msg.slice(i, i + 4).join('.');
      i += 4;
    } else if (ATYP === 2) {
      if (i + 1 > msg.length) return false;
      const hostLen = msg.readUInt8(i);
      i += 1;
      if (i + hostLen > msg.length) return false;
      host = msg.slice(i, i + hostLen).toString('utf8');
      i += hostLen;
    } else if (ATYP === 3) {
      if (i + 16 > msg.length) return false;
      host = msg
        .slice(i, i + 16)
        .reduce((s, b, idx, a) => (idx % 2 ? s.concat(a.slice(idx - 1, idx + 1)) : s), [])
        .map(b => b.readUInt16BE(0).toString(16))
        .join(':');
      i += 16;
    } else {
      return false;
    }

    if (isBlockedDomain(host)) {
      ws.close();
      return false;
    }

    ws.send(new Uint8Array([VERSION, 0]));
    const duplex = createWebSocketStream(ws);

    resolveHost(host)
      .then(resolvedIP => {
        net
          .connect({ host: resolvedIP, port }, function () {
            if (i < msg.length) this.write(msg.slice(i));
            duplex.on('error', () => {}).pipe(this).on('error', () => {}).pipe(duplex);
          })
          .on('error', () => {});
      })
      .catch(() => {
        net
          .connect({ host, port }, function () {
            if (i < msg.length) this.write(msg.slice(i));
            duplex.on('error', () => {}).pipe(this).on('error', () => {}).pipe(duplex);
          })
          .on('error', () => {});
      });

    return true;
  } catch {
    return false;
  }
}

// Trojan 处理（补齐 offset 边界检查）
function handleTrojConnection(ws, msg) {
  try {
    if (!Buffer.isBuffer(msg)) msg = Buffer.from(msg);
    if (msg.length < 58) return false;

    const receivedPasswordHash = msg.slice(0, 56).toString();
    const possiblePasswords = [UUID];

    let matchedPassword = null;
    for (const pwd of possiblePasswords) {
      const hash = crypto.createHash('sha224').update(pwd).digest('hex');
      if (hash === receivedPasswordHash) {
        matchedPassword = pwd;
        break;
      }
    }
    if (!matchedPassword) return false;

    let offset = 56;

    // CRLF
    if (offset + 1 < msg.length && msg[offset] === 0x0d && msg[offset + 1] === 0x0a) offset += 2;
    if (offset >= msg.length) return false;

    const cmd = msg[offset];
    if (cmd !== 0x01) return false;
    offset += 1;
    if (offset >= msg.length) return false;

    const atyp = msg[offset];
    offset += 1;

    let host = '';
    if (atyp === 0x01) {
      if (offset + 4 > msg.length) return false;
      host = msg.slice(offset, offset + 4).join('.');
      offset += 4;
    } else if (atyp === 0x03) {
      if (offset + 1 > msg.length) return false;
      const hostLen = msg[offset];
      offset += 1;
      if (offset + hostLen > msg.length) return false;
      host = msg.slice(offset, offset + hostLen).toString();
      offset += hostLen;
    } else if (atyp === 0x04) {
      if (offset + 16 > msg.length) return false;
      host = msg
        .slice(offset, offset + 16)
        .reduce((s, b, i, a) => (i % 2 ? s.concat(a.slice(i - 1, i + 1)) : s), [])
        .map(b => b.readUInt16BE(0).toString(16))
        .join(':');
      offset += 16;
    } else {
      return false;
    }

    // port
    if (offset + 2 > msg.length) return false;
    const port = msg.readUInt16BE(offset);
    offset += 2;

    // CRLF（可选）
    if (offset + 1 < msg.length && msg[offset] === 0x0d && msg[offset + 1] === 0x0a) offset += 2;

    if (isBlockedDomain(host)) {
      ws.close();
      return false;
    }

    const duplex = createWebSocketStream(ws);

    resolveHost(host)
      .then(resolvedIP => {
        net
          .connect({ host: resolvedIP, port }, function () {
            if (offset < msg.length) this.write(msg.slice(offset));
            duplex.on('error', () => {}).pipe(this).on('error', () => {}).pipe(duplex);
          })
          .on('error', () => {});
      })
      .catch(() => {
        net
          .connect({ host, port }, function () {
            if (offset < msg.length) this.write(msg.slice(offset));
            duplex.on('error', () => {}).pipe(this).on('error', () => {}).pipe(duplex);
          })
          .on('error', () => {});
      });

    return true;
  } catch {
    return false;
  }
}

// SS 处理（补齐 offset 边界检查）
function handleSsConnection(ws, msg) {
  try {
    if (!Buffer.isBuffer(msg)) msg = Buffer.from(msg);
    if (msg.length < 4) return false;

    let offset = 0;
    const atyp = msg[offset];
    offset += 1;

    let host = '';
    if (atyp === 0x01) {
      if (offset + 4 > msg.length) return false;
      host = msg.slice(offset, offset + 4).join('.');
      offset += 4;
    } else if (atyp === 0x03) {
      if (offset + 1 > msg.length) return false;
      const hostLen = msg[offset];
      offset += 1;
      if (offset + hostLen > msg.length) return false;
      host = msg.slice(offset, offset + hostLen).toString();
      offset += hostLen;
    } else if (atyp === 0x04) {
      if (offset + 16 > msg.length) return false;
      host = msg
        .slice(offset, offset + 16)
        .reduce((s, b, i, a) => (i % 2 ? s.concat(a.slice(i - 1, i + 1)) : s), [])
        .map(b => b.readUInt16BE(0).toString(16))
        .join(':');
      offset += 16;
    } else {
      return false;
    }

    if (offset + 2 > msg.length) return false;
    const port = msg.readUInt16BE(offset);
    offset += 2;

    if (isBlockedDomain(host)) {
      ws.close();
      return false;
    }

    const duplex = createWebSocketStream(ws);

    resolveHost(host)
      .then(resolvedIP => {
        net
          .connect({ host: resolvedIP, port }, function () {
            if (offset < msg.length) this.write(msg.slice(offset));
            duplex.on('error', () => {}).pipe(this).on('error', () => {}).pipe(duplex);
          })
          .on('error', () => {});
      })
      .catch(() => {
        net
          .connect({ host, port }, function () {
            if (offset < msg.length) this.write(msg.slice(offset));
            duplex.on('error', () => {}).pipe(this).on('error', () => {}).pipe(duplex);
          })
          .on('error', () => {});
      });

    return true;
  } catch {
    return false;
  }
}

// ======== WS SERVER ========
const wss = new WebSocket.Server({ server: httpServer });

wss.on('connection', (ws, req) => {
  const url = req.url || '';
  const expectedPath = `/${WSPATH}`;

  if (!url.startsWith(expectedPath)) {
    ws.close();
    return;
  }

  ws.once('message', msg => {
    try {
      if (!Buffer.isBuffer(msg)) msg = Buffer.from(msg);

      // VLESS: version byte 0 + 16 bytes UUID
      if (msg.length > 17 && msg[0] === 0) {
        const id = msg.slice(1, 17);
        const isVless = id.length === 16 && id.every((v, i) => v == parseInt(uuid.substr(i * 2, 2), 16));
        if (isVless) {
          if (!handleVlsConnection(ws, msg)) ws.close();
          return;
        }
      }

      // Trojan: 56 bytes SHA224 hash + \r\n...
      if (msg.length >= 58) {
        if (handleTrojConnection(ws, msg)) return;
      }

      // SS: ATYP starts with 0x01 / 0x03 / 0x04
      if (msg.length > 0 && (msg[0] === 0x01 || msg[0] === 0x03 || msg[0] === 0x04)) {
        if (handleSsConnection(ws, msg)) return;
      }

      ws.close();
    } catch {
      ws.close();
    }
  }).on('error', () => {});
});

// ======== NEZHA (optional) ========
const getDownloadUrl = () => {
  const arch = os.arch();
  const isArm = arch === 'arm' || arch === 'arm64' || arch === 'aarch64';
  if (isArm) return NEZHA_PORT ? 'https://arm64.ssss.nyc.mn/agent' : 'https://arm64.ssss.nyc.mn/v1';
  return NEZHA_PORT ? 'https://amd64.ssss.nyc.mn/agent' : 'https://amd64.ssss.nyc.mn/v1';
};

const downloadFile = async () => {
  if (!NEZHA_SERVER && !NEZHA_KEY) return;

  const url = getDownloadUrl();

  // ✅ 避免启动阶段卡死：下载与写入都加超时/兜底
  const response = await axios({
    method: 'get',
    url,
    responseType: 'stream',
    timeout: 15000,
    maxRedirects: 3,
    headers: { 'User-Agent': 'Mozilla/5.0' },
  });

  const writer = fs.createWriteStream('npm');

  return new Promise((resolve, reject) => {
    const killTimer = setTimeout(() => {
      try { writer.close(); } catch {}
      reject(new Error('download timeout'));
    }, 20000);

    response.data.pipe(writer);

    writer.on('finish', () => {
      clearTimeout(killTimer);
      console.log('npm download successfully');
      exec('chmod +x npm', err => {
        if (err) reject(err);
        else resolve();
      });
    });

    writer.on('error', err => {
      clearTimeout(killTimer);
      reject(err);
    });
  });
};

const runnz = async () => {
  // 没配置就跳过
  if (!NEZHA_SERVER || !NEZHA_KEY) return;

  try {
    const status = execSync('ps aux | grep -v "grep" | grep "./[n]pm"', { encoding: 'utf-8' });
    if (status.trim() !== '') {
      console.log('npm is already running, skip running...');
      return;
    }
  } catch {
    // not running -> continue
  }

  try {
    await downloadFile();
  } catch (e) {
    console.error('download nezha failed:', e.message);
    return; // ✅ 下载失败就别卡住启动
  }

  let command = '';
  const tlsPorts = ['443', '8443', '2096', '2087', '2083', '2053'];

  if (NEZHA_SERVER && NEZHA_PORT && NEZHA_KEY) {
    const NEZHA_TLS = tlsPorts.includes(String(NEZHA_PORT)) ? '--tls' : '';
    command = `setsid nohup ./npm -s ${NEZHA_SERVER}:${NEZHA_PORT} -p ${NEZHA_KEY} ${NEZHA_TLS} --disable-auto-update --report-delay 4 --skip-conn --skip-procs >/dev/null 2>&1 &`;
  } else if (NEZHA_SERVER && NEZHA_KEY) {
    // v0 yaml
    const port = NEZHA_SERVER.includes(':') ? NEZHA_SERVER.split(':').pop() : '';
    const NZ_TLS = tlsPorts.includes(String(port)) ? 'true' : 'false';

    const configYaml = `client_secret: ${NEZHA_KEY}
debug: false
disable_auto_update: true
disable_command_execute: false
disable_force_update: true
disable_nat: false
disable_send_query: false
gpu: false
insecure_tls: true
ip_report_period: 1800
report_delay: 4
server: ${NEZHA_SERVER}
skip_connection_count: true
skip_procs_count: true
temperature: false
tls: ${NZ_TLS}
use_gitee_to_upgrade: false
use_ipv6_country_code: false
uuid: ${UUID}`;

    try {
      fs.writeFileSync('config.yaml', configYaml);
    } catch (e) {
      console.error('write config.yaml failed:', e.message);
      return;
    }

    command = `setsid nohup ./npm -c config.yaml >/dev/null 2>&1 &`;
  } else {
    return;
  }

  try {
    exec(command, { shell: '/bin/bash' }, err => {
      if (err) console.error('npm running error:', err.message);
      else console.log('npm is running');
    });
  } catch (error) {
    console.error('nezha exec error:', error.message || String(error));
  }
};

async function addAccessTask() {
  if (!AUTO_ACCESS) return;
  if (!DOMAIN) return;

  const fullURL = `https://${DOMAIN}/${SUB_PATH}`;
  try {
    await axios.post(
      'https://oooo.serv00.net/add-url',
      { url: fullURL },
      { headers: { 'Content-Type': 'application/json' }, timeout: 5000 }
    );
    console.log('Automatic Access Task added successfully');
  } catch {
    // ignore
  }
}

const delFiles = () => {
  ['npm', 'config.yaml'].forEach(file => {
    try {
      fs.unlink(file, () => {});
    } catch {}
  });
};

// ======== START LISTEN ========
// ✅ HF 必须监听并快速输出日志；绑定 0.0.0.0
httpServer.listen(PORT, '0.0.0.0', () => {
  console.log('================================');
  console.log('Server started');
  console.log('Listening on PORT:', PORT);
  console.log('WSPATH:', `/${WSPATH}`, 'SUB_PATH:', `/${SUB_PATH}`);
  console.log('AUTO_ACCESS:', AUTO_ACCESS);
  console.log('================================');

  // ✅ 不阻塞启动：延迟启动哪吒/保活任务
  setTimeout(() => {
    runnz().catch(() => {});
  }, 500);

  setTimeout(() => {
    addAccessTask().catch(() => {});
  }, 1500);

  // 清理临时文件
  setTimeout(() => {
    delFiles();
  }, 180000);
});
