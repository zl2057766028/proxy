#!/usr/bin/env node

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

const UUID = process.env.UUID || '5efabea4-f6d4-91fd-b8f0-17e004c89c60'; // 运行哪吒v1,在不同的平台需要改UUID,否则会被覆盖
const NEZHA_SERVER = process.env.NEZHA_SERVER || '';       // 哪吒v1填写形式：nz.abc.com:8008   哪吒v0填写形式：nz.abc.com
const NEZHA_PORT = process.env.NEZHA_PORT || '';           // 哪吒v1没有此变量，v0的agent端口为{443,8443,2096,2087,2083,2053}其中之一时开启tls
const NEZHA_KEY = process.env.NEZHA_KEY || '';             // v1的NZ_CLIENT_SECRET或v0的agent端口
const DOMAIN = process.env.DOMAIN || 'hugproxy.zlzl.de5.net';    // 填写项目域名或已反代的域名，不带前缀，建议填已反代的域名
const AUTO_ACCESS = process.env.AUTO_ACCESS || false;      // 是否开启自动访问保活,false为关闭,true为开启,需同时填写DOMAIN变量
const WSPATH = process.env.WSPATH || UUID.slice(0, 8);     // 节点路径，默认获取uuid前8位
const SUB_PATH = process.env.SUB_PATH || 'sub';            // 获取节点的订阅路径
const NAME = process.env.NAME || '';                       // 节点名称
const PORT = process.env.PORT || 7860;                     // http和ws服务端口

let uuid = UUID.replace(/-/g, ""), CurrentDomain = DOMAIN, Tls = 'tls', CurrentPort = 443, ISP = '';
const DNS_SERVERS = ['8.8.4.4', '1.1.1.1'];
const BLOCKED_DOMAINS = [
  'speedtest.net', 'fast.com', 'speedtest.cn', 'speed.cloudflare.com', 'speedof.me',
  'testmy.net', 'bandwidth.place', 'speed.io', 'librespeed.org', 'speedcheck.org'
];

// block speedtest domains
function isBlockedDomain(host) {
  if (!host) return false;
  const hostLower = host.toLowerCase();
  return BLOCKED_DOMAINS.some(blocked => hostLower === blocked || hostLower.endsWith('.' + blocked));
}

async function getisp() {
  try {
    const res = await axios.get('https://api.ip.sb/geoip', { headers: { 'User-Agent': 'Mozilla/5.0', timeout: 3000 } });
    const data = res.data;
    ISP = `${data.country_code}-${data.isp}`.replace(/ /g, '_');
  } catch (e) {
    try {
      const res2 = await axios.get('http://ip-api.com/json', { headers: { 'User-Agent': 'Mozilla/5.0', timeout: 3000 } });
      const data2 = res2.data;
      ISP = `${data2.countryCode}-${data2.org}`.replace(/ /g, '_');
    } catch (e2) {
      ISP = 'Unknown';
    }
  }
}

async function getip() {
  if (!DOMAIN || DOMAIN === 'your-domain.com') {
    try {
      const res = await axios.get('https://api-ipv4.ip.sb/ip', { timeout: 5000 });
      const ip = res.data.trim();
      CurrentDomain = ip; Tls = 'none'; CurrentPort = PORT;
    } catch (e) {
      console.error('Failed to get IP', e.message);
      CurrentDomain = 'cahnge-your-domain.com'; Tls = 'tls'; CurrentPort = 443;
    }
  } else {
    CurrentDomain = DOMAIN; Tls = 'tls'; CurrentPort = 443;
  }
}

// http route
const httpServer = http.createServer(async (req, res) => {
  if (req.url === '/') {
    const filePath = path.join(__dirname, 'index.html');
    fs.readFile(filePath, 'utf8', (err, content) => {
      if (err) {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end('Hello world!');
        return;
      }
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(content);
    });
    return;
  } else if (req.url === `/${SUB_PATH}`) {
    await getisp(); await getip();
    const namePart = NAME ? `${NAME}-${ISP}` : ISP;
    const tlsParam = Tls === 'tls' ? 'tls' : 'none';
    const ssTlsParam = Tls === 'tls' ? 'tls;' : '';
    const vlsURL = `vless://${UUID}@${CurrentDomain}:${CurrentPort}?encryption=none&security=${tlsParam}&sni=${CurrentDomain}&fp=chrome&type=ws&host=${CurrentDomain}&path=%2F${WSPATH}#${namePart}`;
    const troURL = `trojan://${UUID}@${CurrentDomain}:${CurrentPort}?security=${tlsParam}&sni=${CurrentDomain}&fp=chrome&type=ws&host=${CurrentDomain}&path=%2F${WSPATH}#${namePart}`;
    const ssMethodPassword = Buffer.from(`none:${UUID}`).toString('base64');
    const ssURL = `ss://${ssMethodPassword}@${CurrentDomain}:${CurrentPort}?plugin=v2ray-plugin;mode%3Dwebsocket;host%3D${CurrentDomain};path%3D%2F${WSPATH};${ssTlsParam}sni%3D${CurrentDomain};skip-cert-verify%3Dtrue;mux%3D0#${namePart}`;
    const subscription = vlsURL + '\n' + troURL + '\n' + ssURL;
    const base64Content = Buffer.from(subscription).toString('base64');

    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end(base64Content + '\n');
  } else {
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('Not Found\n');
  }
});

// Custom DNS
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
      axios.get(dnsQuery, {
        timeout: 5000,
        headers: { 'Accept': 'application/dns-json' }
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

/**
 * ==========================
 *  WS 协议解析（安全版）
 *  解决 Node20+ Buffer 越界
 * ==========================
 */

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

    // port(2) + atyp(1) 至少要够
    if (i + 3 > msg.length) return false;

    const port = msg.readUInt16BE(i);
    i += 2;

    const ATYP = msg.readUInt8(i);
    i += 1;

    let host = '';
    if (ATYP === 1) { // IPv4
      if (i + 4 > msg.length) return false;
      host = msg.slice(i, i + 4).join('.');
      i += 4;
    } else if (ATYP === 2) { // Domain
      if (i + 1 > msg.length) return false;
      const hostLen = msg.readUInt8(i);
      i += 1;
      if (i + hostLen > msg.length) return false;
      host = msg.slice(i, i + hostLen).toString('utf8');
      i += hostLen;
    } else if (ATYP === 3) { // IPv6
      if (i + 16 > msg.length) return false;
      host = msg.slice(i, i + 16)
        .reduce((s, b, idx, a) => (idx % 2 ? s.concat(a.slice(idx - 1, idx + 1)) : s), [])
        .map(b => b.readUInt16BE(0).toString(16)).join(':');
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
        net.connect({ host: resolvedIP, port }, function () {
          if (i < msg.length) this.write(msg.slice(i));
          duplex.on('error', () => { }).pipe(this).on('error', () => { }).pipe(duplex);
        }).on('error', () => { });
      })
      .catch(() => {
        net.connect({ host, port }, function () {
          if (i < msg.length) this.write(msg.slice(i));
          duplex.on('error', () => { }).pipe(this).on('error', () => { }).pipe(duplex);
        }).on('error', () => { });
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
      if (hash === receivedPasswordHash) { matchedPassword = pwd; break; }
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
      host = msg.slice(offset, offset + 16)
        .reduce((s, b, i, a) => (i % 2 ? s.concat(a.slice(i - 1, i + 1)) : s), [])
        .map(b => b.readUInt16BE(0).toString(16)).join(':');
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
        net.connect({ host: resolvedIP, port }, function () {
          if (offset < msg.length) this.write(msg.slice(offset));
          duplex.on('error', () => { }).pipe(this).on('error', () => { }).pipe(duplex);
        }).on('error', () => { });
      })
      .catch(() => {
        net.connect({ host, port }, function () {
          if (offset < msg.length) this.write(msg.slice(offset));
          duplex.on('error', () => { }).pipe(this).on('error', () => { }).pipe(duplex);
        }).on('error', () => { });
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
      host = msg.slice(offset, offset + 16)
        .reduce((s, b, i, a) => (i % 2 ? s.concat(a.slice(i - 1, i + 1)) : s), [])
        .map(b => b.readUInt16BE(0).toString(16)).join(':');
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
        net.connect({ host: resolvedIP, port }, function () {
          if (offset < msg.length) this.write(msg.slice(offset));
          duplex.on('error', () => { }).pipe(this).on('error', () => { }).pipe(duplex);
        }).on('error', () => { });
      })
      .catch(() => {
        net.connect({ host, port }, function () {
          if (offset < msg.length) this.write(msg.slice(offset));
          duplex.on('error', () => { }).pipe(this).on('error', () => { }).pipe(duplex);
        }).on('error', () => { });
      });

    return true;
  } catch {
    return false;
  }
}

// Ws handler
const wss = new WebSocket.Server({ server: httpServer });
wss.on('connection', (ws, req) => {
  const url = req.url || '';

  const expectedPath = `/${WSPATH}`;
  if (!url.startsWith(expectedPath)) {
    ws.close();
    return;
  }

  ws.once('message', msg => {
    if (!Buffer.isBuffer(msg)) msg = Buffer.from(msg);

    // VLESS (version byte 0 + 16 bytes UUID)
    if (msg.length > 17 && msg[0] === 0) {
      const id = msg.slice(1, 17);
      const isVless = id.length === 16 && id.every((v, i) => v == parseInt(uuid.substr(i * 2, 2), 16));
      if (isVless) {
        if (!handleVlsConnection(ws, msg)) ws.close();
        return;
      }
    }

    // Trojan (56 bytes SHA224 hash)
    if (msg.length >= 58) {
      if (handleTrojConnection(ws, msg)) return;
    }

    // SS (ATYP开头: 0x01, 0x03, 0x04)
    if (msg.length > 0 && (msg[0] === 0x01 || msg[0] === 0x03 || msg[0] === 0x04)) {
      if (handleSsConnection(ws, msg)) return;
    }

    ws.close();
  }).on('error', () => { });
});

const getDownloadUrl = () => {
  const arch = os.arch();
  if (arch === 'arm' || arch === 'arm64' || arch === 'aarch64') {
    if (!NEZHA_PORT) return 'https://arm64.ssss.nyc.mn/v1';
    return 'https://arm64.ssss.nyc.mn/agent';
  } else {
    if (!NEZHA_PORT) return 'https://amd64.ssss.nyc.mn/v1';
    return 'https://amd64.ssss.nyc.mn/agent';
  }
};

const downloadFile = async () => {
  if (!NEZHA_SERVER && !NEZHA_KEY) return;

  try {
    const url = getDownloadUrl();
    const response = await axios({
      method: 'get',
      url: url,
      responseType: 'stream'
    });

    const writer = fs.createWriteStream('npm');
    response.data.pipe(writer);

    return new Promise((resolve, reject) => {
      writer.on('finish', () => {
        console.log('npm download successfully');
        exec('chmod +x npm', (err) => {
          if (err) reject(err);
          resolve();
        });
      });
      writer.on('error', reject);
    });
  } catch (err) {
    throw err;
  }
};

const runnz = async () => {
  try {
    const status = execSync('ps aux | grep -v "grep" | grep "./[n]pm"', { encoding: 'utf-8' });
    if (status.trim() !== '') {
      console.log('npm is already running, skip running...');
      return;
    }
  } catch (e) {
    // 进程不存在时继续运行nezha
  }

  await downloadFile();
  let command = '';
  let tlsPorts = ['443', '8443', '2096', '2087', '2083', '2053'];

  if (NEZHA_SERVER && NEZHA_PORT && NEZHA_KEY) {
    const NEZHA_TLS = tlsPorts.includes(String(NEZHA_PORT)) ? '--tls' : '';
    command = `setsid nohup ./npm -s ${NEZHA_SERVER}:${NEZHA_PORT} -p ${NEZHA_KEY} ${NEZHA_TLS} --disable-auto-update --report-delay 4 --skip-conn --skip-procs >/dev/null 2>&1 &`;
  } else if (NEZHA_SERVER && NEZHA_KEY) {
    if (!NEZHA_PORT) {
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

      fs.writeFileSync('config.yaml', configYaml);
    }
    command = `setsid nohup ./npm -c config.yaml >/dev/null 2>&1 &`;
  } else {
    return;
  }

  try {
    exec(command, { shell: '/bin/bash' }, (err) => {
      if (err) console.error('npm running error:', err);
      else console.log('npm is running');
    });
  } catch (error) {
    console.error(`error: ${error}`);
  }
};

async function addAccessTask() {
  if (!AUTO_ACCESS) return;
  if (!DOMAIN) return;

  const fullURL = `https://${DOMAIN}/${SUB_PATH}`;
  try {
    await axios.post("https://oooo.serv00.net/add-url", { url: fullURL }, {
      headers: { 'Content-Type': 'application/json' }
    });
    console.log('Automatic Access Task added successfully');
  } catch (error) {
    // ignore
  }
}

const delFiles = () => {
  ['npm', 'config.yaml'].forEach(file => fs.unlink(file, () => { }));
};

httpServer.listen(PORT, () => {
  runnz();
  setTimeout(() => {
    delFiles();
  }, 180000);
  addAccessTask();
  console.log(`Server is running on port ${PORT}`);
});
