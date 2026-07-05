/* ============================================================================
 * Grain Relay —— RFC 6062 TCP + XUDP UDP + DO 快取 + VLESS 修正
 * 修正：Blob 處理 / 0-byte skip / message queue / Refresh / leftover
 * ==========================================================================*/

import { connect } from 'cloudflare:sockets';
import { DurableObject } from 'cloudflare:workers';

const CFG = {
  id: '78f076f9-35f8-4847-8722-d44fe7942752',
  chunk: 64 * 1024,
  dnPack: 32 * 1024,
  dnTail: 512,
  dnMs: 0,
  upPack: 16 * 1024,
  upQMax: 256 * 1024,
  maxED: 8 * 1024,
  concur: 4,
  turnTtl: 10 * 60 * 1000,
};

// ─── 編碼工具 ───
const hex = c => (c > 64 ? c + 9 : c) & 0xF;
const idB = new Uint8Array(16), dec = new TextDecoder(), enc = s => new TextEncoder().encode(s);
for (let i = 0, p = 0, c, h; i < 16; i++) {
  c = CFG.id.charCodeAt(p++); c === 45 && (c = CFG.id.charCodeAt(p++)); h = hex(c);
  c = CFG.id.charCodeAt(p++); c === 45 && (c = CFG.id.charCodeAt(p++)); idB[i] = h << 4 | hex(c);
}
const u16a = n => new Uint8Array([n >> 8, n & 255]);
const u16 = (b, o = 0) => (b[o] << 8) | b[o + 1];
const pad4 = n => -n & 3;
const cat = (...a) => { const r = new Uint8Array(a.reduce((s, x) => s + x.length, 0)); let o = 0; for (const x of a) { r.set(x, o); o += x.length; } return r; };
const safeClose = (...a) => a.forEach(x => { try { x?.close?.(); } catch {} });

// ─── UUID 匹配 ───
const checkUUID = c => !idB.some((v, i) => c[i + 1] !== v);

// ─── VLESS 解析 ───
const parseAddr = (b, o, t) => {
  let l;
  if (t === 3) { l = b[o++]; }
  else if (t === 1) { l = 4; }
  else if (t === 4) { l = 16; }
  else { l = 0; }
  return l && o + l <= b.length ? { addrBytes: b.subarray(o, o + l), dataOffset: o + l } : null;
};
const addr = (t, b) => t === 3 ? dec.decode(b) : t === 1 ? b.join('.') : t === 4 ? `[${Array.from({ length: 8 }, (_, i) => u16(b, i * 2).toString(16)).join(':')}]` : '';

const vless = c => {
  if (!checkUUID(c)) return null;
  const cmdOffset = 18 + c[17];
  if (cmdOffset >= c.length) return null;
  const cmd = c[cmdOffset];
  if (cmd !== 1 && cmd !== 3) return null;
  const portOffset = cmdOffset + 1;
  if (portOffset + 3 > c.length) return null;
  const port = u16(c, portOffset);
  const rawType = c[portOffset + 2];
  const addrType = rawType === 1 ? 1 : rawType + 1;
  const a = parseAddr(c, portOffset + 3, addrType);
  return a ? { cmd, port, addrType, targetAddrBytes: a.addrBytes, dataOffset: a.dataOffset } : null;
};

const vlessUDP = c => {
  if (!checkUUID(c)) return null;
  const cmdOffset = 18 + c[17];
  if (cmdOffset >= c.length) return null;
  const cmd = c[cmdOffset];
  if (cmd !== 2 && cmd !== 3) { console.error("[vlessUDP] fail: cmd=", cmd); return null; }
  const portOffset = cmdOffset + 1;
  if (portOffset + 3 > c.length) return null;
  const rawType = c[portOffset + 2];
  const addrType = rawType === 1 ? 1 : rawType + 1;
  const a = parseAddr(c, portOffset + 3, addrType);
  return a ? { cmd, dataOffset: a.dataOffset } : null;
};

// ─── XUDP ───
const xudpAddr = d => {
  if (!d.length) return ['', 0];
  if (d[0] <= 1) return d.length >= 5 ? [d.subarray(1, 5).join('.'), 5] : ['', 0];
  if (d[0] === 2) return d.length >= 2 + d[1] ? [dec.decode(d.subarray(2, 2 + d[1])), 2 + d[1]] : ['', 0];
  return d[0] === 3 && d.length >= 17 ? [`[${Array.from({ length: 8 }, (_, i) => u16(d, 1 + i * 2).toString(16)).join(':')}]`, 17] : ['', 0];
};
const parseXUDP = b => {
  if (b.length < 6) return null;
  const metaLen = u16(b), metaEnd = 2 + metaLen;
  if (metaLen < 4 || metaEnd > b.length) return null;
  const f = { network: metaEnd > 6 ? b[6] : 0, port: metaEnd >= 9 ? u16(b, 7) : 0, host: metaEnd > 9 ? xudpAddr(b.subarray(9, metaEnd))[0] : '', payload: null, totalLen: metaEnd };
  if ((b[5] & 1) && metaEnd + 2 <= b.length) { const pLen = u16(b, metaEnd); if (metaEnd + 2 + pLen <= b.length) { f.payload = b.subarray(metaEnd + 2, metaEnd + 2 + pLen); f.totalLen = metaEnd + 2 + pLen; } }
  return f;
};
const xudpResp = (h, p, d) => { const hB = enc(h); return cat(new Uint8Array([0, hB.length, ...hB, p >> 8, p & 255, 3]), d); };

// ─── STUN / TURN 常數 ───
const MAGIC = new Uint8Array([0x21, 0x12, 0xA4, 0x42]);
const MT = {
  AQ: 0x0003, AO: 0x0103, AE: 0x0113,
  PQ: 0x0008, PO: 0x0108,
  CQ: 0x000A, CO: 0x010A,
  BQ: 0x000B, BO: 0x010B,
  SI: 0x0016, DI: 0x0017,
  RF: 0x0004, RO: 0x0104,
};
const AT = {
  USER: 0x0006, INT: 0x0008, ERR: 0x0009,
  PEER: 0x0012, DATA: 0x0013,
  REALM: 0x0014, NONCE: 0x0015,
  TRANSPORT: 0x0019,
  CONNID: 0x002A,
  LIFETIME: 0x000D,
};

// ─── STUN 建構 / 解析 ───
const tid = () => crypto.getRandomValues(new Uint8Array(12));
const stunAttr = (t, v) => { const b = new Uint8Array(4 + v.length + pad4(v.length)); new DataView(b.buffer).setUint16(0, t); new DataView(b.buffer).setUint16(2, v.length); b.set(v, 4); return b; };
const stunMsg = (t, id, a = []) => { const bd = cat(...a), h = new Uint8Array(20); new DataView(h.buffer).setUint16(0, t); new DataView(h.buffer).setUint16(2, bd.length); h.set(MAGIC, 4); h.set(id, 8); return cat(h, bd); };
const parseStun = d => {
  if (d.length < 20 || MAGIC.some((v, i) => d[4 + i] !== v)) return null;
  const dv = new DataView(d.buffer, d.byteOffset, d.byteLength), ml = dv.getUint16(2), attrs = {};
  for (let o = 20; o + 4 <= 20 + ml;) { const t = dv.getUint16(o), l = dv.getUint16(o + 2); if (o + 4 + l > d.length) break; attrs[t] = d.slice(o + 4, o + 4 + l); o += 4 + l + pad4(l); }
  return { type: dv.getUint16(0), attrs };
};
const parseErr = d => d?.length >= 4 ? (d[2] & 7) * 100 + d[3] : 0;

async function readStun(r, left) {
  let b = left ?? new Uint8Array(0);
  const pull = async () => { const { done, value } = await r.read(); if (done) throw 0; b = cat(b, new Uint8Array(value)); };
  try { while (b.length < 4) await pull(); const total = 20 + u16(b, 2); while (b.length < total) await pull(); return [parseStun(b.subarray(0, total)), b.length > total ? b.subarray(total) : null]; }
  catch { return [null, null]; }
}

// ─── HMAC / 認證 ───
const md5 = async s => new Uint8Array(await crypto.subtle.digest('MD5', enc(s)));
async function addIntegrity(msg, key) {
  if (!key || key.length === 0) return msg;
  const c = new Uint8Array(msg); new DataView(c.buffer).setUint16(2, new DataView(c.buffer).getUint16(2) + 24);
  const k = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
  return cat(c, stunAttr(AT.INT, new Uint8Array(await crypto.subtle.sign('HMAC', k, c))));
}

async function turnAuth(w, r, transport, { user, pass }) {
  const tp = new Uint8Array([transport, 0, 0, 0]);
  await w.write(stunMsg(MT.AQ, tid(), [stunAttr(AT.TRANSPORT, tp)]));
  let [msg, leftover] = await readStun(r);
  if (!msg) return null;

  let key = null, aa = [];
  const sign = m => key ? addIntegrity(m, key) : Promise.resolve(m);

  if (msg.type === MT.AE && user && parseErr(msg.attrs[AT.ERR]) === 401) {
    const realm = msg.attrs[AT.REALM] ?? new Uint8Array(0), nonce = msg.attrs[AT.NONCE] ?? new Uint8Array(0);
    key = await md5(`${user}:${dec.decode(realm)}:${pass}`);
    aa = [stunAttr(AT.USER, enc(user)), stunAttr(AT.REALM, realm), stunAttr(AT.NONCE, nonce)];
    await w.write(await sign(stunMsg(MT.AQ, tid(), [stunAttr(AT.TRANSPORT, tp), ...aa])));
    [msg, leftover] = await readStun(r, leftover);
    if (!msg) return null;
  }
  if (msg.type !== MT.AO) return null;
  return { key, aa, leftover, sign };
}

// ─── TURN helpers ───
const xorPeer = (ip, port) => { const b = new Uint8Array(8); b[1] = 1; new DataView(b.buffer).setUint16(2, port ^ 0x2112); ip.split('.').forEach((v, i) => b[4 + i] = +v ^ MAGIC[i]); return b; };
const parseXorPeer = d => d?.length >= 8 ? [MAGIC.map((m, i) => d[4 + i] ^ m).join('.'), u16(d, 2) ^ 0x2112] : ['', 0];
const dial = async (h, p) => { const s = connect({ hostname: h, port: p }); await s.opened; return s; };

// ─── IP 解析 ───
const fakeIPType = h => { const m = h.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/); return m && +m[1] === 100 && [100, 101].some(v => +m[2] === v) ? 4 : m && +m[1] === 200 && [200, 201].some(v => +m[2] === v) ? 6 : h.replace(/^\[|\]$/g, '').startsWith('fc') && h.includes(':') ? 6 : 0; };
const resolveIP = async h => { if (/^\d+\.\d+\.\d+\.\d+$/.test(h)) return h; try { const r = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(h)}&type=A`, { headers: { Accept: 'application/dns-json' } }); return (await r.json()).Answer?.find(a => a.type === 1)?.data ?? null; } catch { return null; } };

// ─── URL 解析 ───
const getTurn = u => { try { const m = decodeURIComponent(u).match(/\/turn:\/\/([^?&#\s]*)/i); if (!m) return null; const t = m[1], at = t.lastIndexOf('@'), cred = at >= 0 ? t.slice(0, at) : '', hp = t.slice(at + 1), ci = hp.lastIndexOf(':'); if (ci < 0) return null; return { host: hp.slice(0, ci), port: parseInt(hp.slice(ci + 1)) || 3478, user: cred.includes(':') ? cred.slice(0, cred.indexOf(':')) : '', pass: cred.includes(':') ? cred.slice(cred.indexOf(':') + 1) : '' }; } catch { return null; } };

// ─── Worker L1 快取 ───
const workerTurnCache = new Map();

function getCachedAuth(turn, env) {
  return async () => {
    const turnKey = `${turn.host}:${turn.port}`;
    let c = workerTurnCache.get(turnKey);
    if (c && c.t > Date.now()) return c.auth;

    if (turn.user && turn.pass) {
      const doStub = env.CONTROL_PLANE_DO.idFromName(turnKey);
      const doInst = env.CONTROL_PLANE_DO.get(doStub);
      const resp = await doInst.fetch(new Request('https://do/auth', { method: 'POST', body: JSON.stringify({ op: 'AUTH', turn }) }));
      if (!resp.ok) return null;
      const j = await resp.json();
      if (!j.ok) return null;
      c = { t: Date.now() + CFG.turnTtl, turn, auth: { key: j.auth.key?.length ? Uint8Array.from(j.auth.key) : null, aa: (j.auth.aa ?? []).map(x => Uint8Array.from(x)), sign: m => j.auth.key?.length ? addIntegrity(m, Uint8Array.from(j.auth.key)) : Promise.resolve(m) } };
    } else {
      c = { t: Date.now() + CFG.turnTtl, turn, auth: { key: null, aa: [], sign: m => Promise.resolve(m) } };
    }
    workerTurnCache.set(turnKey, c);
    return c.auth;
  };
}

// ─── UDP Relay ───
async function createUDPRelay(req, server, env) {
  const turn = getTurn(req.url); if (!turn) return null;
  const getAuth = getCachedAuth(turn, env);
  const auth = await getAuth(); if (!auth) return null;

  let sock; try { sock = await dial(turn.host, turn.port); } catch { return null; }
  const w = sock.writable.getWriter(), r = sock.readable.getReader();

  const tp = new Uint8Array([17, 0, 0, 0]);
  await w.write(await auth.sign(stunMsg(MT.AQ, tid(), [stunAttr(AT.TRANSPORT, tp), ...auth.aa])));
  let [msg, buf] = await readStun(r);
  if (!msg || msg.type !== MT.AO) { await w.write(stunMsg(MT.AQ, tid(), [stunAttr(AT.TRANSPORT, tp)])); [msg, buf] = await readStun(r); if (!msg || msg.type !== MT.AO) { safeClose(sock); return null; } }

  const perms = new Set(), sess = new Map(), reverse = {};
  (async () => { try { while (true) { const [m, nx] = await readStun(r, buf); buf = nx; if (!m) break; if (m.type === MT.DI && m.attrs[AT.PEER] && m.attrs[AT.DATA]) { const [ip, pt] = parseXorPeer(m.attrs[AT.PEER]), s = reverse[`${ip}:${pt}`]; try { server.send(xudpResp(s?.host ?? ip, s?.port ?? pt, m.attrs[AT.DATA])); } catch {} } } } catch {} })();

  const ensurePerm = ip => { if (perms.has(ip)) return; perms.add(ip); auth.sign(stunMsg(MT.PQ, tid(), [stunAttr(AT.PEER, xorPeer(ip, 0)), ...auth.aa])).then(m => w.write(m)).catch(() => {}); };
  const sendUDP = (ip, pt, data) => w.write(stunMsg(MT.SI, tid(), [stunAttr(AT.PEER, xorPeer(ip, pt)), stunAttr(AT.DATA, data)])).catch(() => {});
  const getIP = (h, p) => { const k = `${h}:${p}`, c = sess.get(k); if (c) return c.ip; const ft = fakeIPType(h); if (ft) for (const s of sess.values()) if (s.port === p && s.isV6 === (ft === 6)) { const ns = { ip: s.ip, host: h, port: p, isV6: s.isV6 }; sess.set(k, ns); reverse[`${s.ip}:${p}`] = ns; return s.ip; } return null; };
  const resolveAsync = async (h, p, k) => { try { const ip = await resolveIP(h); if (ip) { const s = { ip, host: h, port: p, isV6: ip.includes(':') }; sess.set(k, s); reverse[`${ip}:${p}`] = s; } } catch {} };

  const processXUDP = data => { while (data.length >= 6) { const f = parseXUDP(data); if (!f) break; if (f.network === 2 && f.payload?.length && f.host) { const k = `${f.host}:${f.port}`, ip = getIP(f.host, f.port); ip ? (ensurePerm(ip), sendUDP(ip, f.port, f.payload)) : sess.has(k) || resolveAsync(f.host, f.port, k); } data = data.subarray(f.totalLen); } };

  return { processXUDP, close: () => { try { w.releaseLock(); } catch {} try { r.releaseLock(); } catch {} safeClose(sock, server); } };
}

// ─── TCP Relay (RFC 6062) ───
async function createTCPRelay(req, server, env, targetIp, targetPort) {
  const turn = getTurn(req.url);
  if (!turn) return null;

  const getAuth = getCachedAuth(turn, env);
  let auth;
  try { auth = await getAuth(); } catch { return null; }
  if (!auth) return null;

  let ctrlSocket = null, dataSocket = null;
  const cleanup = () => safeClose(ctrlSocket, dataSocket, server);

  try {
    // ═══ Control Plane ═══
    ctrlSocket = await dial(turn.host, turn.port);
    const ctrlWriter = ctrlSocket.writable.getWriter();
    const ctrlReader = ctrlSocket.readable.getReader();

    // Allocate TCP
    const tp = new Uint8Array([6, 0, 0, 0]);
    await ctrlWriter.write(await auth.sign(stunMsg(MT.AQ, tid(), [stunAttr(AT.TRANSPORT, tp), ...auth.aa])));
    let [msg, leftover] = await readStun(ctrlReader);
    if (!msg || msg.type !== MT.AO) {
      await ctrlWriter.write(stunMsg(MT.AQ, tid(), [stunAttr(AT.TRANSPORT, tp)]));
      [msg, leftover] = await readStun(ctrlReader);
      if (!msg || msg.type !== MT.AO) { cleanup(); return null; }
    }
    const lifetime = msg.attrs[AT.LIFETIME]
      ? new DataView(msg.attrs[AT.LIFETIME].buffer, msg.attrs[AT.LIFETIME].byteOffset, 4).getUint32(0)
      : 600;

    // Permission + Connect
    const peer = stunAttr(AT.PEER, xorPeer(targetIp, targetPort));
    await ctrlWriter.write(cat(
      await auth.sign(stunMsg(MT.PQ, tid(), [peer, ...auth.aa])),
      await auth.sign(stunMsg(MT.CQ, tid(), [peer, ...auth.aa]))
    ));
    [msg, leftover] = await readStun(ctrlReader, leftover);
    if (!msg || msg.type !== MT.PO) { cleanup(); return null; }
    [msg, leftover] = await readStun(ctrlReader, leftover);
    if (!msg || msg.type !== MT.CO || !msg.attrs[AT.CONNID]) { cleanup(); return null; }
    const connId = msg.attrs[AT.CONNID];

    // ✅ 不 release ctrlWriter / ctrlReader

    // ═══ Data Plane ═══
    dataSocket = connect({ hostname: turn.host, port: turn.port });
    await dataSocket.opened;
    const dataWriter = dataSocket.writable.getWriter();   // ✅ 不 release，直接復用
    const dataReader = dataSocket.readable.getReader();

    // ConnectionBind
    await dataWriter.write(await auth.sign(stunMsg(MT.BQ, tid(), [stunAttr(AT.CONNID, connId), ...auth.aa])));
    const [bindMsg, bindLeftover] = await readStun(dataReader);
    if (!bindMsg || bindMsg.type !== MT.BO) { cleanup(); return null; }

    console.log("[TCP] Alloc ok lifetime:", lifetime,
      "| Perm+Connect ok connId:", Array.from(connId).map(b => b.toString(16).padStart(2, '0')).join(''),
      "| Bind ok leftover:", bindLeftover?.byteLength ?? 0);

    return {
      reader: dataReader,
      writer: dataWriter,       // ✅ 已鎖定 writer
      leftover: bindLeftover,   // ✅ ConnectionBind 後可能已收到的數據
      ctrlWriter: ctrlWriter,   // ✅ 用於 Refresh
      lifetime: lifetime,
      auth: auth,
      close: cleanup
    };
  } catch (e) {
    console.error("[TCP] createTCPRelay 異常:", e.message);
    cleanup();
    return null;
  }
}

// ─── GrainTCP（純 TCP 路徑，無 TURN）───
class Q {
  constructor(m) { this.max = m; this.q = []; this.len = 0; }
  sow(u) { if (this.len + u.byteLength > this.max) return 0; this.q.push(u); this.len += u.byteLength; return 1; }
  bundle(first) { if (!this.len && !first) return []; let r; if (first) { r = new Uint8Array(this.len + first.byteLength); r.set(first, 0); let o = first.byteLength; for (const c of this.q) { r.set(c, o); o += c.byteLength; } } else { r = new Uint8Array(this.len); let o = 0; for (const c of this.q) { r.set(c, o); o += c.byteLength; } } this.clear(); return [r]; }
  get empty() { return !this.len; }
  clear() { this.q = []; this.len = 0; }
}
async function mill(readable, server) { const r = readable.getReader(); try { while (true) { const { value, done } = await r.read(); if (done) break; let o = 0; while (o < value.byteLength) { const s = Math.min(value.byteLength - o, CFG.dnPack); server.send(value.subarray(o, o + s)); o += s; } } } catch {} finally { try { r.releaseLock(); } catch {} } }
async function relayTCP(req, server) {
  const uq = new Q(CFG.upQMax); let sock = null, curW = null, closed = false, busy = false;
  const wither = () => { if (closed) return; closed = true; uq.clear(); try { curW?.releaseLock(); } catch {} try { sock?.close(); } catch {} try { server.close(); } catch {} };
  const thresh = async () => { if (busy || closed) return; busy = true; try { for (;;) { if (closed) break; if (!sock) { const [d] = uq.bundle(); if (!d) break; const r = vless(d); if (!r) throw wither(); server.send(new Uint8Array([d[0], 0])); const host = addr(r.addrType, r.targetAddrBytes); sock = await dial(host, r.port); if (!sock) throw wither(); curW = sock.writable.getWriter(); const [first] = uq.bundle(d.subarray(r.dataOffset)); if (first?.byteLength) await curW.write(first); mill(sock.readable, server).finally(() => wither()); continue; } const [d] = uq.bundle(); if (!d) break; await curW.write(d); } } catch { wither(); } finally { busy = false; } };
  return { sow: d => { const u = d instanceof Uint8Array ? d : new Uint8Array(d); if (uq.sow(u)) return 1; wither(); return 0; }, thresh, close: wither };
}

// ─── Durable Object ───
export class ControlPlaneDO extends DurableObject {
  constructor(state, env) { super(state, env); this.doCache = new Map(); }
  async fetch(req) {
    if (new URL(req.url).pathname !== '/auth') return new Response('Not Found', { status: 404 });
    const { turn } = await req.json();
    const cacheKey = `${turn.host}:${turn.port}`;
    const cached = this.doCache.get(cacheKey);
    if (cached && cached.t > Date.now()) return Response.json({ ok: true, cached: true, auth: cached.auth });

    let sock; try { sock = await dial(turn.host, turn.port); } catch (e) { return Response.json({ ok: false, error: e.message }, { status: 502 }); }
    const w = sock.writable.getWriter(), r = sock.readable.getReader();
    const auth = await turnAuth(w, r, 17, { user: turn.user, pass: turn.pass });
    try { w.releaseLock(); } catch {} try { r.releaseLock(); } catch {} safeClose(sock);
    if (!auth) return Response.json({ ok: false, error: 'Auth Failed' }, { status: 502 });

    const ser = { key: auth.key ? Array.from(auth.key) : [], aa: auth.aa.map(b => Array.from(b)) };
    this.doCache.set(cacheKey, { t: Date.now() + CFG.turnTtl, auth: ser });
    return Response.json({ ok: true, auth: ser });
  }
}

// ─── Worker Entry Point ───
export default {
  async fetch(req, env, ctx) {

    // ─── WebSocket 升級檢查 ───
    const upgrade = req.headers.get('Upgrade')?.toLowerCase();
    if (upgrade !== 'websocket') {
      return new Response('Grain Relay Online.\n\n'
        + 'Usage: VLESS + WebSocket + turn://TURN_IP:PORT\n'
        + `UUID: ${CFG.id}\n`
        + `maxED: ${CFG.maxED}`, { status: 200 });
    }

    const [client, wsS] = Object.values(new WebSocketPair());
    wsS.accept();

    // ─── Early Data ───
    const edStr = req.headers.get('sec-websocket-protocol');
    let ed = null;
    if (edStr?.length && edStr.length <= CFG.maxED) {
      try {
        let s = edStr.trim();
        while (s.length % 4) s += '=';
        ed = Uint8Array.fromBase64(s, { alphabet: 'base64url' });
        console.log("[ED]", ed.length, "bytes");
      } catch {
        console.error("[ED] base64 decode failed");
      }
    }

    // ─── 狀態變數 ───
    const turn = getTurn(req.url);
    const isUDP = !!turn;
    let udpRelay = null, tcpRelay = null, tcpWriter = null, tcpHdl = null;
    let closed = false;
    let pendingChunks = [];
    let tcpReady = false;
    let closeTag = '';

    const close = (tag) => {
      if (closed) return;
      closed = true;
      closeTag = tag || closeTag || '?';
      console.log("[CLOSE] reason:", closeTag);
      udpRelay?.close();
      try { tcpWriter?.releaseLock(); } catch {}
      try { tcpRelay?.close(); } catch {}
      try { tcpHdl?.close(); } catch {}
      try { wsS?.close(); } catch {}
    };

    // ─── drainPending ───
    const drainPending = async () => {
      if (!tcpWriter || !tcpReady || !pendingChunks.length) return;
      console.log("[DRAIN]", pendingChunks.length, "chunks pending");
      while (pendingChunks.length) {
        const chunk = pendingChunks.shift();
        try {
          await tcpWriter.write(chunk);
          console.log("[DRAIN] wrote", chunk.byteLength, "bytes");
        } catch (e) {
          console.error("[DRAIN] error:", e.message);
          close('drain');
          return;
        }
      }
    };

    // ─── process ───
    const process = async chunk => {
      if (tcpWriter) {
        if (tcpReady) {
          await tcpWriter.write(chunk);
          return;
        }
        pendingChunks.push(chunk);
        console.log("[Q] queued", chunk.byteLength, "bytes, pending:", pendingChunks.length);
        return;
      }

      // ─── TURN 路徑 ───
      if (isUDP) {
        if (udpRelay) return udpRelay.processXUDP(chunk);

        const u = vlessUDP(chunk);
        if (u) {
          try { wsS.send(new Uint8Array([chunk[0], 0])); } catch {}
          udpRelay = await createUDPRelay(req, wsS, env);
          if (!udpRelay) { close('udpRelay'); return; }
          const ud = chunk.subarray(u.dataOffset);
          if (ud.length) udpRelay.processXUDP(ud);
          return;
        }

        const v = vless(chunk);
        if (v && v.cmd === 1) {
          try { wsS.send(new Uint8Array([chunk[0], 0])); } catch {}
          const host = addr(v.addrType, v.targetAddrBytes);
          const ip = v.addrType === 1 ? host : await resolveIP(host);
          if (!ip) { console.error("[DNS] fail:", host); close('dns'); return; }

          tcpRelay = await createTCPRelay(req, wsS, env, ip, v.port);
          if (!tcpRelay) { close('tcpRelay'); return; }

          tcpWriter = tcpRelay.writer;

          // ─── Reader loop ───
          ctx.waitUntil((async () => {
            try {
              const dr = tcpRelay.reader;
              if (tcpRelay.leftover?.byteLength) {
                try { wsS.send(tcpRelay.leftover); } catch {}
              }
              while (true) {
                const { done, value } = await dr.read();
                if (done) break;
                if (value?.byteLength) {
                  try { wsS.send(value); } catch {}
                }
              }
            } catch (e) {
              console.error("[READER] err:", e.message);
            } finally {
              close('reader');
            }
          })());

          // ─── Refresh loop ───
          ctx.waitUntil((async () => {
            const interval = Math.min(tcpRelay.lifetime * 1000 * 0.8, 60_000);
            while (!closed) {
              await new Promise(r => setTimeout(r, interval));
              if (closed) break;
              try {
                await tcpRelay.ctrlWriter.write(
                  await tcpRelay.auth.sign(stunMsg(MT.RF, tid(), [...tcpRelay.auth.aa]))
                );
              } catch { break; }
            }
          })());

          // ─── 寫入 initial payload ───
          const payload = chunk.subarray(v.dataOffset);
          if (payload.byteLength) await tcpWriter.write(payload);

          tcpReady = true;
          await drainPending();
          return;
        }

        console.error("[VLESS] parse fail");
        close('vless');
        return;
      }

      // ─── 純 TCP（無 turn://）───
      if (!tcpHdl) tcpHdl = await relayTCP(req, wsS);
      if (!tcpHdl.sow(chunk)) { close('relayTCP'); return; }
      tcpHdl.thresh();
    };

    // ─── 處理 early data ───
    if (ed?.length) {
      ctx.waitUntil((async () => {
        try { await process(ed); } catch (e) {
          console.error("[ED] process err:", e.message);
          close('ed');
        }
      })());
    }

    // ─── WebSocket message handler ───
    wsS.addEventListener('message', e => {
      const handle = async () => {
        const raw = e.data;
        let data;

        // ✅ 解析 ArrayBuffer / Blob / String
        try {
          if (raw instanceof Blob) {
            const ab = await raw.arrayBuffer();
            data = new Uint8Array(ab);
            console.log("[WS] Blob size:", raw.size, "→", data.byteLength, "bytes | tcpW:", !!tcpWriter, "ready:", tcpReady);
          } else if (raw instanceof ArrayBuffer) {
            data = new Uint8Array(raw);
            console.log("[WS] ArrayBuffer", data.byteLength, "bytes | tcpW:", !!tcpWriter, "ready:", tcpReady);
          } else {
            // String or other
            data = new Uint8Array(raw);
            console.log("[WS] String len:", raw?.length, "→", data.byteLength, "bytes | tcpW:", !!tcpWriter, "ready:", tcpReady);
          }
        } catch (err) {
          console.error("[WS] parse fail:", err.message);
          close('ws-parse');
          return;
        }

        // ✅ 跳過 0-byte
        if (data.byteLength === 0) {
          console.log("[SKIP] 0-byte");
          return;
        }

        // ✅ relay 就緒 → 直接寫入
        if (tcpWriter && tcpReady) {
          ctx.waitUntil(tcpWriter.write(data).then(() => {
            console.log("[WS] wrote", data.byteLength, "bytes → TURN");
          }).catch(err => {
            console.error("[WS] write err:", err.message);
            close('ws-write');
          }));
          return;
        }

        // ✅ relay 建立中 → 暫存
        if (tcpWriter && !tcpReady) {
          pendingChunks.push(data);
          console.log("[Q] queued", data.byteLength, "bytes, pending:", pendingChunks.length);
          return;
        }

        // ❌ 完全沒有 relay → process（應只在 early data 未覆蓋時觸發）
        ctx.waitUntil(process(data).catch(err => {
          console.error("[WS] process err:", err.message);
          close('ws-process');
        }));
      };

      ctx.waitUntil(handle().catch(err => {
        console.error("[WS] unhandled:", err.message);
        close('ws-unhandled');
      }));
    });

    wsS.addEventListener('close', () => close('ws-close'));
    wsS.addEventListener('error', () => close('ws-error'));

    return new Response(null, {
      status: 101,
      webSocket: client,
      headers: edStr ? { 'sec-websocket-protocol': edStr } : {}
    });
  },
};
