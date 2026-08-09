import { connect } from "cloudflare:sockets";

/**
 * Galaxy-Tunnel Cloudflare Worker (Android V2Ray & Speedtest Compatibility Enhanced)
 * Features: Multi-UUID VLESS, Multi-Password TROJAN, SOCKS5 Outbound Relay,
 * Android Health Check Fix (204 Ping), Speedtest.net Support, Multi-DoH DNS
 */

// ============================================
// CONFIGURATION & DEFAULTS
// ============================================
var ALLOWED_UUIDS = ["d3b07384-d113-42a6-a719-30cf56f235d1","8f3d12a9-7c45-421b-8e12-990142fa91b0","1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d"];
var ALLOWED_TROJAN_PASSWORDS = ["galaxy_pass_secure_2026","admin_pass_secondary_99"];
var PROXY_IP_POOL = ["104.16.85.20:443","104.17.123.45:443","104.21.234.45:443","172.64.155.1:443","172.65.250.1:443","[2606:4700:4700::1111]:443","[2606:4700:4700::1001]:443","cdn.xn--b6gac.eu.org:443","cdn-all.xn--b6gac.eu.org:443","cdn-b100.xn--b6gac.eu.org:443","workers.cloudflare.com:443"];
var SOCKS5_SERVERS = [{"enabled":true,"server":"127.0.0.1","port":1080,"username":"proxyuser","password":"proxypassword"}];
var DOH_PROVIDERS = ["https://2mms0p4zud.cloudflare-gateway.com/dns-query","https://dns.google/dns-query","https://dns.quad9.net/dns-query","https://cloudflare-dns.com/dns-query","https://1.1.1.1/dns-query","https://dns.alidns.com/dns-query","https://doh.pub/dns-query"];
var SNI_DOMAINS = ["www.visa.com","www.visakorea.com","africa.visa.com","www.visa.com.sg","www.visa.com.hk","icook.hk","ip.sb","japan.com","malaysia.com","www.gov.se"];

var GITHUB_PROXY_URL = "https://raw.githubusercontent.com/proxzero/galaxy-subdomain/refs/heads/main/PROXYIP.txt";
var MAX_RETRY_ATTEMPTS = 3;
var ENABLE_SOCKS5 = true;
var ENABLE_SMART_ROUTING = true;

// Dynamic Routing Rules Table
var ROUTING_RULES = [
  { type: "domain", pattern: "speedtest.net", action: "direct" },
  { type: "keyword", pattern: "ookla", action: "direct" },
  { type: "keyword", pattern: "generate_204", action: "direct" },
  { type: "keyword", pattern: "gstatic", action: "direct" },
  { type: "keyword", pattern: "cp.cloudflare.com", action: "direct" },
  { type: "keyword", pattern: "torrent", action: "block" }
];

// ============================================
// UTILITY FUNCTIONS
// ============================================
function isValidUUID(uuid) {
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  return uuidRegex.test(uuid ? uuid.trim() : "");
}

// SHA224 Implementation for Trojan Password Verification
function sha224(str) {
  function rightRotate(value, amount) {
    return (value >>> amount) | (value << (32 - amount));
  }
  const mathPow = Math.pow;
  const maxWord = mathPow(2, 32);
  let result = '';
  const words = [];
  const asciiBitLength = str.length * 8;
  let hash = [
    0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
    0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4
  ];
  const k = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ];
  let s = str;
  s += '\x80';
  while (s.length % 64 - 56) s += '\x00';
  for (let i = 0; i < s.length; i++) {
    const j = s.charCodeAt(i);
    if (j >> 8) return null;
    words[i >> 2] |= j << ((3 - i) % 4) * 8;
  }
  words[words.length] = ((asciiBitLength / maxWord) | 0);
  words[words.length] = (asciiBitLength);
  for (let j = 0; j < words.length;) {
    const w = words.slice(j, j += 16);
    const oldHash = hash.slice(0);
    for (let i = 0; i < 64; i++) {
      if (i >= 16) {
        const w15 = w[i - 15], w2 = w[i - 2];
        w[i] = (
          w[i - 16] +
          (rightRotate(w15, 7) ^ rightRotate(w15, 18) ^ (w15 >>> 3)) +
          w[i - 7] +
          (rightRotate(w2, 17) ^ rightRotate(w2, 19) ^ (w2 >>> 10))
        ) | 0;
      }
      const a = hash[0], e = hash[4];
      const temp1 = (
        hash[7] +
        (rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25)) +
        ((e & hash[5]) ^ (~e & hash[6])) +
        k[i] +
        w[i]
      );
      const temp2 = (
        (rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22)) +
        ((a & hash[1]) ^ (a & hash[2]) ^ (hash[1] & hash[2]))
      );
      hash = [(temp1 + temp2) | 0].concat(hash);
      hash[4] = (hash[4] + temp1) | 0;
      hash.pop();
    }
    for (let i = 0; i < 8; i++) {
      hash[i] = (hash[i] + oldHash[i]) | 0;
    }
  }
  for (let i = 0; i < 7; i++) {
    const hex = hash[i];
    result += ((hex >> 28) & 0xf).toString(16) +
      ((hex >> 24) & 0xf).toString(16) +
      ((hex >> 20) & 0xf).toString(16) +
      ((hex >> 16) & 0xf).toString(16) +
      ((hex >> 12) & 0xf).toString(16) +
      ((hex >> 8) & 0xf).toString(16) +
      ((hex >> 4) & 0xf).toString(16) +
      (hex & 0xf).toString(16);
  }
  return result;
}

function parseProxyList(input) {
  if (!input) return [];
  if (Array.isArray(input)) return input;
  return input.split(/,|\n/)
    .map(s => s.trim())
    .filter(s => s.length > 0 && !s.startsWith('#'))
    .map(s => s.replace(/^\[|\]$/g, ''));
}

function getRandomItem(arr) {
  if (!arr || arr.length === 0) return null;
  return arr[Math.floor(Math.random() * arr.length)];
}

// Parse "ip:port" or "[ipv6]:port" with multi-port support (e.g. 80, 8080, 443, 2052, 2082)
function parseIpPort(entry, defaultPort = 443) {
  if (!entry) return { hostname: "", port: defaultPort };
  let str = entry.trim();
  let port = defaultPort;

  if (str.startsWith('[')) {
    const closeIdx = str.indexOf(']');
    if (closeIdx !== -1) {
      const hostname = str.substring(1, closeIdx);
      const remainder = str.substring(closeIdx + 1);
      if (remainder.startsWith(':')) {
        port = parseInt(remainder.substring(1), 10) || defaultPort;
      }
      return { hostname, port };
    }
  }

  const parts = str.split(':');
  if (parts.length === 2 && !isNaN(parseInt(parts[1], 10))) {
    return { hostname: parts[0], port: parseInt(parts[1], 10) };
  }
  return { hostname: str.replace(/^\[|\]$/g, ''), port: defaultPort };
}

async function fetchDynamicProxyList(url) {
  if (!url || url.includes("YOUR_USERNAME")) return [];
  try {
    const response = await fetch(url, { cf: { cacheTtl: 300, cacheEverything: true } });
    if (response.ok) {
      const text = await response.text();
      return parseProxyList(text);
    }
  } catch (err) {
    console.error("GitHub Dynamic ProxyIP Fetch Error:", err);
  }
  return [];
}

async function getActiveProxyPool(env) {
  let staticList = [...PROXY_IP_POOL];
  if (env && (env.PROXYIP || env.proxyip)) {
    const envProxy = parseProxyList(env.PROXYIP || env.proxyip);
    if (envProxy.length > 0) staticList = envProxy;
  }
  const githubUrl = (env && env.PROXY_LIST_URL) ? env.PROXY_LIST_URL : GITHUB_PROXY_URL;
  const dynamicList = await fetchDynamicProxyList(githubUrl);
  return [...staticList, ...dynamicList];
}

function determineRoutingAction(addressRemote, portRemote) {
  if (!ENABLE_SMART_ROUTING) return "proxy";

  const host = addressRemote.toLowerCase();

  // Special Android Connectivity Test & Speedtest.net handling
  if (
    host.includes("speedtest") ||
    host.includes("ookla") ||
    host.includes("generate_204") ||
    host.includes("gstatic.com") ||
    host.includes("cp.cloudflare.com")
  ) {
    return "direct";
  }

  for (const rule of ROUTING_RULES) {
    if (rule.type === "domain" && host === rule.pattern.toLowerCase()) return rule.action;
    if (rule.type === "keyword" && host.includes(rule.pattern.toLowerCase())) return rule.action;
  }

  if (host.endsWith(".local") || host === "localhost" || host === "127.0.0.1") return "direct";
  return "proxy";
}

// ============================================
// SOCKS5 OUTBOUND HANDSHAKE ENGINE
// ============================================
async function connectViaSocks5(socksConfig, targetAddress, targetPort) {
  const { server, port: socksPort, username, password } = socksConfig;
  const socket = connect({ hostname: server, port: socksPort });
  const writer = socket.writable.getWriter();
  const reader = socket.readable.getReader();

  const hasAuth = !!(username && password);
  const authMethods = hasAuth ? new Uint8Array([0x05, 0x02, 0x00, 0x02]) : new Uint8Array([0x05, 0x01, 0x00]);
  await writer.write(authMethods);

  let res = await reader.read();
  if (!res.value || res.value[0] !== 0x05) throw new Error("Invalid SOCKS5 server response");
  const chosenMethod = res.value[1];

  if (chosenMethod === 0x02) {
    const userBytes = new TextEncoder().encode(username);
    const passBytes = new TextEncoder().encode(password);
    const authBuf = new Uint8Array(3 + userBytes.length + passBytes.length);
    authBuf[0] = 0x01;
    authBuf[1] = userBytes.length;
    authBuf.set(userBytes, 2);
    authBuf[2 + userBytes.length] = passBytes.length;
    authBuf.set(passBytes, 3 + userBytes.length);

    await writer.write(authBuf);
    res = await reader.read();
    if (!res.value || res.value[1] !== 0x00) throw new Error("SOCKS5 Authentication failed");
  } else if (chosenMethod !== 0x00) {
    throw new Error("SOCKS5 No acceptable authentication method");
  }

  let addressBuffer;
  const isIPv4 = /^\d+\.\d+\.\d+\.\d+$/.test(targetAddress);
  if (isIPv4) {
    const ipParts = targetAddress.split('.').map(Number);
    addressBuffer = new Uint8Array([0x01, ...ipParts]);
  } else {
    const domainBytes = new TextEncoder().encode(targetAddress);
    addressBuffer = new Uint8Array([0x03, domainBytes.length, ...domainBytes]);
  }

  const portBuf = new Uint8Array([(targetPort >> 8) & 0xff, targetPort & 0xff]);
  const reqBuf = new Uint8Array(3 + addressBuffer.length + 2);
  reqBuf[0] = 0x05;
  reqBuf[1] = 0x01;
  reqBuf[2] = 0x00;
  reqBuf.set(addressBuffer, 3);
  reqBuf.set(portBuf, 3 + addressBuffer.length);

  await writer.write(reqBuf);
  res = await reader.read();

  if (!res.value || res.value[1] !== 0x00) {
    throw new Error("SOCKS5 Connection request failed with code: " + (res.value ? res.value[1] : 'unknown'));
  }

  writer.releaseLock();
  reader.releaseLock();
  return socket;
}

// ============================================
// MAIN WORKER FETCH HANDLER
// ============================================
export default {
  async fetch(request, env, ctx) {
    try {
      const envUuids = env.UUID ? parseProxyList(env.UUID) : ALLOWED_UUIDS;
      const envTrojans = env.TROJAN_PASS ? parseProxyList(env.TROJAN_PASS) : ALLOWED_TROJAN_PASSWORDS;

      const upgradeHeader = request.headers.get("Upgrade");
      if (upgradeHeader === "websocket") {
        return await proxyOverWSHandler(request, envUuids, envTrojans, env);
      }

      const url = new URL(request.url);

      if (url.pathname === "/health" || url.pathname === "/api/health") {
        const pool = await getActiveProxyPool(env);
        return new Response(JSON.stringify({
          status: "healthy",
          timestamp: new Date().toISOString(),
          activeUUIDsCount: envUuids.filter(isValidUUID).length,
          trojanAuthActive: envTrojans.length > 0,
          proxyPoolSize: pool.length,
          socks5Enabled: ENABLE_SOCKS5,
          smartRoutingEnabled: ENABLE_SMART_ROUTING,
          dohProvidersCount: DOH_PROVIDERS.length
        }), { status: 200, headers: { "Content-Type": "application/json" } });
      }

      return new Response(getGalaxyPage(envUuids, envTrojans), {
        status: 200,
        headers: { "Content-Type": "text/html; charset=utf-8" }
      });
    } catch (err) {
      return new Response("Internal Worker Error: " + err.message, { status: 500 });
    }
  }
};

// ============================================
// WEBSOCKET PROXY HANDLER (ANDROID & SPEEDTEST READY)
// ============================================
async function proxyOverWSHandler(request, uuidsPool, trojanPool, env) {
  const webSocketPair = new WebSocketPair();
  const [client, webSocket] = Object.values(webSocketPair);
  webSocket.accept();

  let address = "";
  let portWithRandomLog = "";
  const log = (info, event) => console.log(`[${address}:${portWithRandomLog}] ${info}`, event || "");

  const earlyDataHeader = request.headers.get("sec-websocket-protocol") || "";
  const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);

  let remoteSocketWrapper = { value: null };
  let udpStreamWrite = null;
  let isDns = false;

  readableWebSocketStream.pipeTo(new WritableStream({
    async write(chunk, controller) {
      if (isDns && udpStreamWrite) return udpStreamWrite(chunk);
      if (remoteSocketWrapper.value) {
        const writer = remoteSocketWrapper.value.writable.getWriter();
        await writer.write(chunk);
        writer.releaseLock();
        return;
      }

      const firstByte = new Uint8Array(chunk.slice(0, 1))[0];
      let result = null;
      let protocolType = "unknown";

      if (firstByte === 0x00 && uuidsPool.length > 0) {
        try {
          result = processVlessHeader(chunk, uuidsPool);
          if (!result.hasError) protocolType = "vless";
        } catch (e) {
          result = { hasError: true, message: e.message };
        }
      }

      if ((!result || result.hasError) && trojanPool.length > 0) {
        result = processTrojanHeader(chunk, trojanPool);
        if (result && !result.hasError) protocolType = "trojan";
      }

      if (!result || result.hasError) {
        throw new Error(result ? result.message : "Authentication failed or invalid protocol header");
      }

      const { addressRemote = "", portRemote = 443, rawDataIndex, responseHeader, isUDP } = result;

      address = addressRemote;
      portWithRandomLog = `${portRemote} ${isUDP ? "udp" : "tcp"} [${protocolType}]`;

      // DNS (UDP Port 53) via DoH
      if (isUDP && portRemote === 53) {
        isDns = true;
        const rawClientData = chunk.slice(rawDataIndex);
        const { write } = await handleUDPOutBound(webSocket, responseHeader, log);
        udpStreamWrite = write;
        udpStreamWrite(rawClientData);
        return;
      }

      // Non-53 UDP Traffic (QUIC / STUN / Voice / Speedtest UDP)
      if (isUDP && portRemote !== 53) {
        log(`Non-53 UDP packet to ${addressRemote}:${portRemote}. Routing via SOCKS5 or TCP Fallback.`);
        if (ENABLE_SOCKS5 && SOCKS5_SERVERS.length > 0) {
          // Send response header immediately for Android VPN client delay check
          if (responseHeader && responseHeader.byteLength > 0) {
            webSocket.send(responseHeader);
          }
          handleTCPOutBound(remoteSocketWrapper, addressRemote, portRemote, chunk.slice(rawDataIndex), webSocket, new Uint8Array(0), log, env, true);
          return;
        } else {
          // Gracefully notify client and fallback to TCP
          if (responseHeader && responseHeader.byteLength > 0) {
            webSocket.send(responseHeader);
          }
          log("UDP Non-53 fallback to TCP for web/speedtest compatibility");
        }
      }

      const rawClientData = chunk.slice(rawDataIndex);
      handleTCPOutBound(remoteSocketWrapper, addressRemote, portRemote, rawClientData, webSocket, responseHeader, log, env, false);
    },
    close() { log("WebSocket stream closed"); },
    abort(reason) { log("WebSocket stream aborted", JSON.stringify(reason)); }
  })).catch((err) => log("WebSocket pipeTo error", err));

  return new Response(null, { status: 101, webSocket: client });
}

// ============================================
// OUTBOUND TCP CONNECTION WITH MULTI-RETRY & SPEEDTEST SUPPORT
// ============================================
async function handleTCPOutBound(remoteSocket, addressRemote, portRemote, rawClientData, webSocket, responseHeader, log, env, forceSocks = false) {
  const routingAction = determineRoutingAction(addressRemote, portRemote);
  log(`Routing action for ${addressRemote}:${portRemote} -> ${routingAction}`);

  if (routingAction === "block") {
    log(`Access blocked by routing rules for ${addressRemote}`);
    safeCloseWebSocket(webSocket);
    return;
  }

  async function connectAndWrite(targetHost, targetPort, useSocks = false) {
    let tcpSocket;
    const { hostname, port } = parseIpPort(targetHost, targetPort);

    if ((useSocks || forceSocks) && SOCKS5_SERVERS.length > 0) {
      const activeSocks = SOCKS5_SERVERS.find(s => s.enabled) || SOCKS5_SERVERS[0];
      log(`Relaying via SOCKS5 Outbound: ${activeSocks.server}:${activeSocks.port}`);
      tcpSocket = await connectViaSocks5(activeSocks, addressRemote, portRemote);
    } else {
      log(`Direct Socket Connect to ${hostname}:${port}`);
      tcpSocket = connect({ hostname, port });
    }

    remoteSocket.value = tcpSocket;
    const writer = tcpSocket.writable.getWriter();
    await writer.write(rawClientData);
    writer.releaseLock();
    return tcpSocket;
  }

  async function retrySequence() {
    const pool = await getActiveProxyPool(env);
    let attempts = 0;

    while (attempts < MAX_RETRY_ATTEMPTS) {
      attempts++;
      const activeProxy = getRandomItem(pool);
      const target = activeProxy || addressRemote;
      log(`Failover Retry Attempt ${attempts}/${MAX_RETRY_ATTEMPTS} via ProxyIP: ${target}`);

      try {
        const tcpSocket = await connectAndWrite(target, portRemote, ENABLE_SOCKS5 && (attempts === MAX_RETRY_ATTEMPTS));
        tcpSocket.closed.catch(err => console.log("Socket closed", err)).finally(() => safeCloseWebSocket(webSocket));
        remoteSocketToWS(tcpSocket, webSocket, null, log);
        return;
      } catch (err) {
        log(`Attempt ${attempts} failed: ${err.message}`);
      }
    }
    safeCloseWebSocket(webSocket);
  }

  try {
    const initialTarget = (routingAction === "direct") ? addressRemote : (getRandomItem(await getActiveProxyPool(env)) || addressRemote);
    const tcpSocket = await connectAndWrite(initialTarget, portRemote, ENABLE_SOCKS5 && routingAction === "socks5");
    remoteSocketToWS(tcpSocket, webSocket, responseHeader, retrySequence, log);
  } catch (err) {
    log("Initial connect failed, starting retry sequence", err.message);
    await retrySequence();
  }
}

// ============================================
// HEADER PARSERS (MULTI-AUTH & ANDROID DELAY FIX)
// ============================================
function processVlessHeader(vlessBuffer, validUuidsPool) {
  if (vlessBuffer.byteLength < 24) return { hasError: true, message: "Invalid VLESS header size" };

  const version = new Uint8Array(vlessBuffer.slice(0, 1));
  const slicedBuffer = new Uint8Array(vlessBuffer.slice(1, 17));
  const slicedBufferString = stringify(slicedBuffer);

  const isValidUser = validUuidsPool.some(uuid => isValidUUID(uuid) && slicedBufferString.toLowerCase() === uuid.trim().toLowerCase());
  if (!isValidUser) return { hasError: true, message: "VLESS Authentication failed: invalid UUID" };

  const optLength = new Uint8Array(vlessBuffer.slice(17, 18))[0];
  const command = new Uint8Array(vlessBuffer.slice(18 + optLength, 18 + optLength + 1))[0];

  let isUDP = command === 2;
  if (command !== 1 && command !== 2) return { hasError: true, message: `Unsupported VLESS command: ${command}` };

  const portIndex = 18 + optLength + 1;
  const portBuffer = vlessBuffer.slice(portIndex, portIndex + 2);
  const portRemote = new DataView(portBuffer).getUint16(0);

  let addressIndex = portIndex + 2;
  const addressType = new Uint8Array(vlessBuffer.slice(addressIndex, addressIndex + 1))[0];

  let addressLength = 0;
  let addressValueIndex = addressIndex + 1;
  let addressValue = "";

  switch (addressType) {
    case 1:
      addressLength = 4;
      addressValue = new Uint8Array(vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength)).join(".");
      break;
    case 2:
      addressLength = new Uint8Array(vlessBuffer.slice(addressValueIndex, addressValueIndex + 1))[0];
      addressValueIndex += 1;
      addressValue = new TextDecoder().decode(vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
      break;
    case 3:
      addressLength = 16;
      const dataView = new DataView(vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
      const ipv6 = [];
      for (let i = 0; i < 8; i++) ipv6.push(dataView.getUint16(i * 2).toString(16));
      addressValue = ipv6.join(":");
      break;
    default:
      return { hasError: true, message: `Invalid VLESS address type: ${addressType}` };
  }

  return {
    hasError: false,
    addressRemote: addressValue,
    portRemote,
    rawDataIndex: addressValueIndex + addressLength,
    responseHeader: new Uint8Array([version[0], 0]),
    isUDP
  };
}

function processTrojanHeader(trojanBuffer, validPasswordsPool) {
  if (trojanBuffer.byteLength < 58) return { hasError: true, message: "Invalid TROJAN header size" };

  const bytes = new Uint8Array(trojanBuffer);
  const dataView = new DataView(trojanBuffer);

  if (bytes[56] !== 0x0d || bytes[57] !== 0x0a) return { hasError: true, message: "Missing CRLF in TROJAN header" };

  const receivedHash = new TextDecoder().decode(bytes.slice(0, 56)).toLowerCase();
  const isValidTrojan = validPasswordsPool.some(pass => pass && sha224(pass).toLowerCase() === receivedHash);

  if (!isValidTrojan) return { hasError: true, message: "TROJAN Authentication failed: password mismatch" };

  const command = bytes[58];
  const addressType = bytes[59];
  let addressValue, addressLength, addressValueIndex;

  switch (addressType) {
    case 0x01:
      addressLength = 4;
      addressValueIndex = 60;
      addressValue = Array.from(bytes.slice(addressValueIndex, addressValueIndex + addressLength)).join(".");
      break;
    case 0x03:
      addressLength = bytes[60];
      addressValueIndex = 61;
      addressValue = new TextDecoder().decode(bytes.slice(addressValueIndex, addressValueIndex + addressLength));
      break;
    case 0x04:
      addressLength = 16;
      addressValueIndex = 60;
      addressValue = Array.from({ length: 8 }, (_, i) => dataView.getUint16(addressValueIndex + i * 2).toString(16)).join(":");
      break;
    default:
      return { hasError: true, message: `Invalid TROJAN address type: ${addressType}` };
  }

  const portIndex = addressValueIndex + addressLength;
  const portRemote = dataView.getUint16(portIndex);

  return {
    hasError: false,
    addressRemote: addressValue,
    portRemote,
    rawDataIndex: portIndex + 4,
    responseHeader: new Uint8Array(0),
    isUDP: command === 0x03
  };
}

function makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
  return new ReadableStream({
    start(controller) {
      webSocketServer.addEventListener("message", (e) => controller.enqueue(e.data));
      webSocketServer.addEventListener("close", () => { safeCloseWebSocket(webSocketServer); controller.close(); });
      webSocketServer.addEventListener("error", (err) => controller.error(err));
      if (earlyDataHeader) {
        try {
          const dec = atob(earlyDataHeader.replace(/-/g, "+").replace(/_/g, "/"));
          const buf = Uint8Array.from(dec, c => c.charCodeAt(0)).buffer;
          controller.enqueue(buf);
        } catch (e) {}
      }
    }
  });
}

async function remoteSocketToWS(remoteSocket, webSocket, responseHeader, retry, log) {
  let header = responseHeader;
  let hasIncomingData = false;

  await remoteSocket.readable.pipeTo(new WritableStream({
    async write(chunk) {
      hasIncomingData = true;
      if (webSocket.readyState !== 1) return;
      if (header && header.byteLength > 0) {
        webSocket.send(await new Blob([header, chunk]).arrayBuffer());
        header = null;
      } else {
        webSocket.send(chunk);
      }
    }
  })).catch(() => safeCloseWebSocket(webSocket));

  if (!hasIncomingData && retry) retry();
}

async function handleUDPOutBound(webSocket, responseHeader, log) {
  let isHeaderSent = false;
  const transformStream = new TransformStream({
    transform(chunk, controller) {
      for (let index = 0; index < chunk.byteLength;) {
        const lengthBuffer = chunk.slice(index, index + 2);
        const udpPacketLength = new DataView(lengthBuffer).getUint16(0);
        const udpData = new Uint8Array(chunk.slice(index + 2, index + 2 + udpPacketLength));
        index += 2 + udpPacketLength;
        controller.enqueue(udpData);
      }
    }
  });

  transformStream.readable.pipeTo(new WritableStream({
    async write(chunk) {
      for (const url of DOH_PROVIDERS) {
        try {
          const resp = await fetch(url, { method: "POST", headers: { "content-type": "application/dns-message" }, body: chunk });
          const result = await resp.arrayBuffer();
          const size = result.byteLength;
          const sizeBuf = new Uint8Array([size >> 8 & 255, size & 255]);

          if (webSocket.readyState === 1) {
            if (isHeaderSent) webSocket.send(await new Blob([sizeBuf, result]).arrayBuffer());
            else {
              webSocket.send(await new Blob([responseHeader, sizeBuf, result]).arrayBuffer());
              isHeaderSent = true;
            }
            return;
          }
        } catch (e) {}
      }
    }
  }));

  const writer = transformStream.writable.getWriter();
  return { write: (chunk) => writer.write(chunk) };
}

function safeCloseWebSocket(socket) {
  try { if (socket.readyState === 1 || socket.readyState === 2) socket.close(); } catch (e) {}
}

var byteToHex = [];
for (let i = 0; i < 256; ++i) byteToHex.push((i + 256).toString(16).slice(1));

function stringify(arr, offset = 0) {
  return (
    byteToHex[arr[offset + 0]] + byteToHex[arr[offset + 1]] + byteToHex[arr[offset + 2]] + byteToHex[arr[offset + 3]] + "-" +
    byteToHex[arr[offset + 4]] + byteToHex[arr[offset + 5]] + "-" +
    byteToHex[arr[offset + 6]] + byteToHex[arr[offset + 7]] + "-" +
    byteToHex[arr[offset + 8]] + byteToHex[arr[offset + 9]] + "-" +
    byteToHex[arr[offset + 10]] + byteToHex[arr[offset + 11]] + byteToHex[arr[offset + 12]] + byteToHex[arr[offset + 13]] + byteToHex[arr[offset + 14]] + byteToHex[arr[offset + 15]]
  ).toLowerCase();
}

function getGalaxyPage(uuidsPool, trojanPool) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Edge API Gateway Status</title>
  <style>
    body { background-color: #090d16; color: #f3f4f6; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 0; padding: 0; display: flex; min-height: 100vh; align-items: center; justify-content: center; }
    .container { background: #111827; border: 1px solid #1f2937; border-radius: 12px; padding: 2.5rem; max-width: 500px; width: 90%; text-align: center; }
    .status-badge { display: inline-flex; align-items: center; gap: 0.5rem; background: rgba(16, 185, 129, 0.1); border: 1px solid rgba(16, 185, 129, 0.3); color: #10b981; padding: 0.35rem 0.85rem; border-radius: 9999px; font-size: 0.85rem; font-weight: 600; margin-bottom: 1.25rem; }
    .dot { width: 8px; height: 8px; background-color: #10b981; border-radius: 50%; display: inline-block; }
    h1 { font-size: 1.5rem; font-weight: 700; margin: 0 0 0.5rem 0; color: #f3f4f6; }
    p { color: #9ca3af; font-size: 0.9rem; line-height: 1.5; margin: 0 0 1.5rem 0; }
    .metrics { background: rgba(0,0,0,0.2); border: 1px solid #1f2937; border-radius: 8px; padding: 1rem; text-align: left; font-family: monospace; font-size: 0.8rem; color: #d1d5db; }
    .metric-row { display: flex; justify-content: space-between; padding: 0.35rem 0; border-bottom: 1px dashed #1f2937; }
    .metric-row:last-child { border-bottom: none; }
    .footer { margin-top: 1.5rem; font-size: 0.75rem; color: #6b7280; }
  </style>
</head>
<body>
  <div class="container">
    <div class="status-badge"><span class="dot"></span> All Systems Operational</div>
    <h1>Edge Compute Gateway</h1>
    <p>High-performance edge microservice routing and request dispatch layer.</p>
    <div class="metrics">
      <div class="metric-row"><span>Service Health:</span> <span style="color:#10b981;">100% Online</span></div>
      <div class="metric-row"><span>Protocol Handling:</span> <span>HTTP/2, HTTP/3, WSS</span></div>
      <div class="metric-row"><span>Node Response:</span> <span>0.24 ms</span></div>
      <div class="metric-row"><span>Gateway Auth:</span> <span style="color:#60a5fa;">Enforced</span></div>
    </div>
    <div class="footer">Cloudflare Workers Gateway Microservice Platform</div>
  </div>
</body>
</html>`;
}
