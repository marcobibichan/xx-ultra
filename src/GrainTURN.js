// =============================================================================
// xx-ultra — XHTTP XMUX 完全體 Worker (Cloudflare Workers)
// UUID: 78f076f9-35f8-4847-8722-d44fe7942752  路徑: /bibichan
// 全 TURN 出口: TCP RFC 6062 + UDP ChannelData 盲轉
// ControlPlaneDO: 僅 auth handshake → 休眠
// =============================================================================

import { connect } from 'cloudflare:sockets';

const CFG = {
  UUID: '78f076f9-35f8-4847-8722-d44fe7942752',
  PATH: '/bibichan',
  CHUNK: 64 * 1024,
  DN_PACK: 64 * 1024,
  DN_TAIL: 512,
  DN_MS: 8,
  CONCUR: 6,
  MAX_SESSIONS: 128,
  SESSION_IDLE_MS: 30_000,
  MUX_METALEN_MAX: 512,
};

// ─── UUID ───────────────────────────────────────────────────────────────────
const hex = c => (c > 64 ? c + 9 : c) & 0xF;
const uuidB = new Uint8Array(16);
{
  const s = CFG.UUID.replaceAll('-', '');
  for (let i = 0; i < 16; i++) uuidB[i] = (hex(s.charCodeAt(i * 2)) << 4) | hex(s.charCodeAt(i * 2 + 1));
}
const [U0, U1, U2, U3, U4, U5, U6, U7, U8, U9, U10, U11, U12, U13, U14, U15] = uuidB;
const matchUUID = c =>
  c.length >= 17 &&
  c[1] === U0 && c[2] === U1 && c[3] === U2 && c[4] === U3 &&
  c[5] === U4 && c[6] === U5 && c[7] === U6 && c[8] === U7 &&
  c[9] === U8 && c[10] === U9 && c[11] === U10 && c[12] === U11 &&
  c[13] === U12 && c[14] === U13 && c[15] === U14 && c[16] === U15;

// ─── 地址編解碼 ─────────────────────────────────────────────────────────────
const ATYPE_IPV4 = 0x01, ATYPE_DOMAIN = 0x02, ATYPE_IPV6 = 0x03;
const td = new TextDecoder(), te = new TextEncoder();

const readAddr = (b, o) => {
  if (o + 1 > b.length) return null;
  const t = b[o++];
  if (t === ATYPE_IPV4) {
    if (o + 4 > b.length) return null;
    return { addr: `${b[o]}.${b[o+1]}.${b[o+2]}.${b[o+3]}`, end: o + 4 };
  }
  if (t === ATYPE_DOMAIN) {
    if (o >= b.length) return null;
    const len = b[o++];
    if (o + len > b.length) return null;
    return { addr: td.decode(b.subarray(o, o + len)), end: o + len };
  }
  if (t === ATYPE_IPV6) {
    if (o + 16 > b.length) return null;
    const parts = [];
    for (let i = 0; i < 8; i++) parts.push(((b[o + i * 2] << 8) | b[o + i * 2 + 1]).toString(16));
    return { addr: `[${parts.join(':')}]`, end: o + 16 };
  }
  return null;
};

const readAddrBody = (b, o, atype) => {
  if (atype === ATYPE_IPV4) {
    if (o + 4 > b.length) return null;
    return { addr: `${b[o]}.${b[o+1]}.${b[o+2]}.${b[o+3]}`, end: o + 4 };
  }
  if (atype === ATYPE_DOMAIN) {
    if (o >= b.length) return null;
    const len = b[o++];
    if (o + len > b.length) return null;
    return { addr: td.decode(b.subarray(o, o + len)), end: o + len };
  }
  if (atype === ATYPE_IPV6) {
    if (o + 16 > b.length) return null;
    const parts = [];
    for (let i = 0; i < 8; i++) parts.push(((b[o + i * 2] << 8) | b[o + i * 2 + 1]).toString(16));
    return { addr: `[${parts.join(':')}]`, end: o + 16 };
  }
  return null;
};

const writeAddr = (host) => {
  const ipv4 = host.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (ipv4) return new Uint8Array([ATYPE_IPV4, ...ipv4.slice(1).map(Number)]);
  if (host.startsWith('[') && host.endsWith(']')) {
    const h = host.slice(1, -1), parts = h.split(':');
    if (parts.length === 8) {
      const b = new Uint8Array(17); b[0] = ATYPE_IPV6;
      parts.forEach((p, i) => { const v = parseInt(p, 16) || 0; b[1 + i * 2] = v >> 8; b[2 + i * 2] = v & 0xFF; });
      return b;
    }
  }
  const d = te.encode(host);
  return new Uint8Array([ATYPE_DOMAIN, d.length, ...d]);
};

// ─── VLESS Header ───────────────────────────────────────────────────────────
const parseVLESS = (c) => {
  if (c.length < 22 || !matchUUID(c)) return null;
  const addInfoLen = c[17];
  let o = 19 + addInfoLen;
  if (o + 3 > c.length) return null;
  const cmd = c[o - 1];
  const port = (c[o] << 8) | c[o + 1];
  const atype = c[o + 2];

  if (cmd === 0x03) {
    return { cmd, port: 0, atype: 0, addr: '', dataOffset: o };
  }
  if (cmd === 0x02) {
    const a = readAddrBody(c, o + 3, atype);
    const addrEnd = a ? a.end : o + 3;
    return { cmd, port, atype, addr: a ? a.addr : '', dataOffset: addrEnd };
  }

  const a = readAddrBody(c, o + 3, atype);
  return a ? { cmd, port, atype, addr: a.addr, dataOffset: a.end } : null;
};

// ─── XMUX Frame 解析 ────────────────────────────────────────────────────────
const SESS_NEW = 0x01, SESS_KEEP = 0x02, SESS_END = 0x03, SESS_KEEPALIVE = 0x04;
const OPT_DATA = 0x01, OPT_ERR = 0x02;
const NET_TCP = 0x01, NET_UDP = 0x02;

const parseXMUXFrame = (b, o) => {
  if (o + 2 > b.length) return null;
  const metaLen = (b[o] << 8) | b[o + 1];
  if (metaLen < 4 || metaLen > CFG.MUX_METALEN_MAX) return null;
  const metaEnd = o + 2 + metaLen;
  if (metaEnd > b.length) return null;

  const sid = (b[o + 2] << 8) | b[o + 3];
  const status = b[o + 4];
  const option = b[o + 5];

  // ★ 驗證 status (1-4) 和 option (0-2)
  if (status < 1 || status > 4) return null;
  if (option > 2) return null;

  let target = null;
  let metaCursor = o + 6;

  if (status === SESS_NEW) {
    if (metaCursor >= metaEnd) return null;
    const netType = b[metaCursor++];
    if (metaCursor + 2 > metaEnd) return null;
    const port = (b[metaCursor] << 8) | b[metaCursor + 1];
    metaCursor += 2;
    const a = readAddr(b, metaCursor);
    if (!a || a.end > metaEnd) return null;
    target = { net: netType, host: a.addr, port };
    metaCursor = a.end;
  } else if (status === SESS_KEEP && metaLen > 4 && b[o + 6] === NET_UDP) {
    metaCursor = o + 7;
    if (metaCursor + 2 > metaEnd) return null;
    const port = (b[metaCursor] << 8) | b[metaCursor + 1];
    metaCursor += 2;
    const a = readAddr(b, metaCursor);
    if (!a || a.end > metaEnd) return null;
    target = { net: NET_UDP, host: a.addr, port };
    metaCursor = a.end;
  }

  if (metaEnd + 2 > b.length) return null;
  const dataLen = (b[metaEnd] << 8) | b[metaEnd + 1];
  const dataStart = metaEnd + 2;
  if (dataStart + dataLen > b.length) return null;

  return {
    sid, status, option, target,
    data: dataLen > 0 ? b.subarray(dataStart, dataStart + dataLen) : null,
    frameEnd: dataStart + dataLen,
  };
};

const buildXMUXKeepFrame = (sid, data) => {
  const metaLen = 4;
  const dLen = data.byteLength;
  const frame = new Uint8Array(2 + metaLen + 2 + dLen);
  const dv = new DataView(frame.buffer);
  dv.setUint16(0, metaLen);
  dv.setUint16(2, sid);
  frame[4] = SESS_KEEP;
  frame[5] = OPT_DATA;
  dv.setUint16(6, dLen);
  frame.set(data, 8);
  return frame;
};

// ─── 通用輔助 ───────────────────────────────────────────────────────────────
const u16 = (b, o = 0) => (b[o] << 8) | b[o + 1];
const pad4 = n => -n & 3;
const cat = (...a) => { const r = new Uint8Array(a.reduce((s, x) => s + x.length, 0)); a.reduce((o, x) => (r.set(x, o), o + x.length), 0); return r; };
const toU8 = (v) => {
  if (v instanceof Uint8Array) return v;
  if (ArrayBuffer.isView(v)) return new Uint8Array(v.buffer, v.byteOffset, v.byteLength);
  if (v instanceof ArrayBuffer) return new Uint8Array(v);
  return new Uint8Array(0);
};

const dial = async (host, port) => {
  const s = connect({ hostname: host, port });
  await s.opened;
  return s;
};

const resolveIP = async h =>
  /^\d+\.\d+\.\d+\.\d+$/.test(h) ? h :
  (await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(h)}&type=A`, {
    headers: { Accept: 'application/dns-json' }
  }).then(r => r.json()).catch(() => ({}))).Answer?.find(a => a.type === 1)?.data ?? null;

const vlessResp = new Uint8Array([0, 0]);

// ─── GrainTCP ────────────────────────────────────────────────────────────────
const mkGrainTCP = (cap = CFG.DN_PACK, tail = CFG.DN_TAIL, low = Math.max(4096, tail << 3)) => {
  let pb = new Uint8Array(cap), p = 0, tp = 0, mq = 0, gen = 0, qk = 0, qr = 0;
  let writer = null;

  const reap = () => {
    tp && clearTimeout(tp); tp = 0; mq = 0;
    if (!p || !writer) return;
    try { writer.write(pb.subarray(0, p).slice()); } catch {}
    pb = new Uint8Array(cap); p = 0; qr = 0;
  };

  const ripen = () => {
    if (tp || mq) return;
    mq = 1; qk = gen;
    queueMicrotask(() => {
      mq = 0;
      if (!p || tp || !writer) return;
      if (cap - p < tail) return reap();
      tp = setTimeout(() => {
        tp = 0;
        if (!p || !writer) return;
        if (cap - p < tail) return reap();
        if (qr < 2 && (gen !== qk || p < low)) { qr++; qk = gen; return ripen(); }
        reap();
      }, Math.max(CFG.DN_MS, 1));
    });
  };

  return {
    setWriter(w) { writer = w; },
    send(u) {
      if (!u?.byteLength) return;
      let o = 0, n = u.byteLength;
      while (o < n) {
        if (!p && n - o >= cap) {
          const m = Math.min(cap, n - o);
          writer?.write(o || m !== n ? u.subarray(o, o + m) : u);
          o += m; continue;
        }
        const m = Math.min(cap - p, n - o);
        pb.set(u.subarray(o, o + m), p); p += m; o += m; gen++;
        if (p === cap || cap - p < tail) reap(); else ripen();
      }
    },
    reap,
    close() { reap(); writer = null; },
  };
};

// ─── STUN / TURN ────────────────────────────────────────────────────────────
const MAGIC = new Uint8Array([0x21, 0x12, 0xA4, 0x42]);
const MT = { AQ: 0x003, AO: 0x103, AE: 0x113, PQ: 0x008, PO: 0x108, CQ: 0x00A, CO: 0x10A, BQ: 0x00B, BO: 0x10B, SI: 0x016, DI: 0x017 };
const AT = { USER: 0x006, MI: 0x008, ERR: 0x009, PEER: 0x012, DATA: 0x013, REALM: 0x014, NONCE: 0x015, TRANSPORT: 0x019, CONNID: 0x02A };

const tid = () => crypto.getRandomValues(new Uint8Array(12));
const stunAttr = (t, v) => { const b = new Uint8Array(4 + v.length + pad4(v.length)), d = new DataView(b.buffer); d.setUint16(0, t); d.setUint16(2, v.length); b.set(v, 4); return b; };
const stunMsg = (t, id, a) => { const bd = cat(...a), h = new Uint8Array(20), d = new DataView(h.buffer); d.setUint16(0, t); d.setUint16(2, bd.length); h.set(MAGIC, 4); h.set(id, 8); return cat(h, bd); };
const xorPeer = (ip, port) => { const b = new Uint8Array(8); b[1] = 1; new DataView(b.buffer).setUint16(2, port ^ 0x2112); ip.split('.').forEach((v, i) => b[4 + i] = +v ^ MAGIC[i]); return b; };

const parseStun = d => {
  if (d.length < 20 || MAGIC.some((v, i) => d[4 + i] !== v)) return null;
  const dv = new DataView(d.buffer, d.byteOffset, d.byteLength), ml = dv.getUint16(2), attrs = {};
  for (let o = 20; o + 4 <= 20 + ml;) {
    const t = dv.getUint16(o), l = dv.getUint16(o + 2);
    if (o + 4 + l > d.length) break;
    attrs[t] = d.slice(o + 4, o + 4 + l); o += 4 + l + pad4(l);
  }
  return { type: dv.getUint16(0), attrs };
};

const parseErr = d => d?.length >= 4 ? (d[2] & 7) * 100 + d[3] : 0;
const parseXorPeer = d => d?.length >= 8 ? [MAGIC.map((m, i) => d[4 + i] ^ m).join('.'), u16(d, 2) ^ 0x2112] : ['', 0];

const addIntegrity = async (m, key) => {
  if (!key) return m;
  const c = new Uint8Array(m), d = new DataView(c.buffer);
  d.setUint16(2, d.getUint16(2) + 24);
  const k = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
  return cat(c, stunAttr(AT.MI, new Uint8Array(await crypto.subtle.sign('HMAC', k, c))));
};

const md5 = async s => new Uint8Array(await crypto.subtle.digest('MD5', te.encode(s)));

const readStun = async (rd, buf) => {
  let b = buf ?? new Uint8Array(0);
  const pull = async () => { const { done, value } = await rd.read(); if (done) throw 0; b = cat(b, new Uint8Array(value)); };
  try {
    while (b.length < 20) await pull();
    const n = 20 + u16(b, 2);
    while (b.length < n) await pull();
    return [parseStun(b.subarray(0, n)), b.length > n ? b.subarray(n) : null];
  } catch { return [null, null]; }
};

// ─── TURN 認證 ─────────────────────────────────────────────────────────────
const turnAuthHandshake = async (w, r, transport, { user, pass }) => {
  const tp = new Uint8Array([transport, 0, 0, 0]);
  await w.write(stunMsg(MT.AQ, tid(), [stunAttr(AT.TRANSPORT, tp)]));
  let [msg, ex] = await readStun(r); if (!msg) return null;
  let key = null, aa = [];
  const sign = m => addIntegrity(m, key);

  if (msg.type === MT.AE && parseErr(msg.attrs[AT.ERR]) === 401) {
    const realm = td.decode(msg.attrs[AT.REALM] ?? new Uint8Array(0));
    const nonce = msg.attrs[AT.NONCE] ?? new Uint8Array(0);
    if (user && pass) key = await md5(`$bibichan:${realm}:${pass}`);
    aa = [
      stunAttr(AT.USER, te.encode(user || '')),
      stunAttr(AT.REALM, te.encode(realm)),
      stunAttr(AT.NONCE, nonce),
    ];
    await w.write(await sign(stunMsg(MT.AQ, tid(), [stunAttr(AT.TRANSPORT, tp), ...aa])));
    [msg, ex] = await readStun(r, ex); if (!msg) return null;
  }
  return msg.type === MT.AO ? { key, aa, ex, sign } : null;
};

// ─── ControlPlaneDO ────────────────────────────────────────────────────────
export class ControlPlaneDO {
  constructor(state, env) {
    this.state = state;
    this.env = env;
    this.doCache = new Map();
    (async () => {
      try { for (const [k] of await this.state.storage.list()) { const v = await this.state.storage.get(k); if (v?.expiry > Date.now()) this.doCache.set(k, v); } } catch {}
    })().catch(() => {});
  }

  async fetch(request) {
    const url = new URL(request.url);
    if (url.pathname !== '/turnAuth') return new Response('Not Found', { status: 404 });

    const { host, port, user, pass, transport } = await request.json();
    const cacheKey = `${host}:${port}:$bibichan:${transport}`;
    const cached = this.doCache.get(cacheKey);
    if (cached && cached.expiry > Date.now()) {
      return new Response(JSON.stringify(cached.state), { headers: { 'Content-Type': 'application/json' } });
    }

    try {
      const sock = await dial(host, port);
      const w = sock.writable.getWriter(), r = sock.readable.getReader();
      const auth = await turnAuthHandshake(w, r, transport, { user, pass });
      w.releaseLock(); r.releaseLock();
      try { sock.close(); } catch {}

      if (auth) {
        const state = {
          key: auth.key ? Array.from(auth.key) : null,
          aa: auth.aa.map(a => Array.from(a)),
        };
        const entry = { state, expiry: Date.now() + 600_000 };
        this.doCache.set(cacheKey, entry);
        try { await this.state.storage.put(cacheKey, entry); } catch {}
        return new Response(JSON.stringify(state), { headers: { 'Content-Type': 'application/json' } });
      }
      return new Response(JSON.stringify({ error: 'auth failed' }), { status: 401 });
    } catch (e) {
      return new Response(JSON.stringify({ error: e.message }), { status: 500 });
    }
  }
}

// ─── Worker L1 Cache ────────────────────────────────────────────────────────
const workerTurnCache = new Map();

const getTurnAuthState = async (env, turnCfg, transport) => {
  if (!turnCfg?.host) return null;
  const { host, port, user, pass } = turnCfg;
  const cacheKey = `${host}:${port}:$bibichan:${transport}`;

  const l1 = workerTurnCache.get(cacheKey);
  if (l1 && l1.expiry > Date.now()) return l1.state;

  if (env.CONTROL_PLANE_DO) {
    try {
      const stub = env.CONTROL_PLANE_DO.get(env.CONTROL_PLANE_DO.idFromName('turn'));
      const res = await stub.fetch(new Request('https://do/turnAuth', {
        method: 'POST', body: JSON.stringify({ host, port, user, pass, transport }),
      }));
      if (res.ok) {
        const state = await res.json();
        if (!state.error) { workerTurnCache.set(cacheKey, { state, expiry: Date.now() + 600_000 }); return state; }
      }
    } catch {}
  }

  try {
    const sock = await dial(host, port);
    const w = sock.writable.getWriter(), r = sock.readable.getReader();
    const auth = await turnAuthHandshake(w, r, transport, { user, pass });
    w.releaseLock(); r.releaseLock();
    try { sock.close(); } catch {}
    if (auth) {
      const state = { key: auth.key ? Array.from(auth.key) : null, aa: auth.aa.map(a => Array.from(a)) };
      workerTurnCache.set(cacheKey, { state, expiry: Date.now() + 600_000 });
      return state;
    }
  } catch {}
  return null;
};

// ─── TURN UDP Pool ─────────────────────────────────────────────────────────
const createTURNUDPPool = async (turnCfg, env) => {
  const { host, port, user, pass } = turnCfg;
  const authState = await getTurnAuthState(env, turnCfg, 17);
  if (!authState) { return null; }

  const key = authState.key ? new Uint8Array(authState.key) : null;
  const aa = authState.aa.map(a => new Uint8Array(a));
  const sign = (m) => addIntegrity(m, key);

  let ctrl = null, cw = null, cr = null;
  try {
    ctrl = await dial(host, port);
    cw = ctrl.writable.getWriter();
    cr = ctrl.readable.getReader();

    await cw.write(await sign(stunMsg(MT.AQ, tid(), [
      stunAttr(AT.TRANSPORT, new Uint8Array([17, 0, 0, 0])), ...aa
    ])));
    const [udpAlloc, udpEx] = await readStun(cr);
    if (!udpAlloc || udpAlloc.type !== MT.AO) {
      cw.releaseLock(); cr.releaseLock();
      try { ctrl.close(); } catch {}
      return null;
    }

    let closed = false;
    let ctrlBuf = udpEx;
    let onUDPData = null;
    const perms = new Set();
    const permQueue = [];

    const close = () => {
      if (closed) return;
      closed = true;
      try { cw.releaseLock(); } catch {}
      try { cr.releaseLock(); } catch {}
      try { ctrl?.close(); } catch {}
    };

    (async () => {
      try {
        while (!closed) {
          const [msg, nx] = await readStun(cr, ctrlBuf);
          ctrlBuf = nx;
          if (!msg) { break; }
          if (msg.type === MT.DI && msg.attrs[AT.PEER] && msg.attrs[AT.DATA] && onUDPData) {
            const [ip, pt] = parseXorPeer(msg.attrs[AT.PEER]);
            onUDPData(ip, pt, msg.attrs[AT.DATA]);
          } else if (msg.type === MT.PO) {
            const r = permQueue.shift();
            if (r) r.resolve();
          } else if (msg.type === MT.AE && msg.attrs[AT.ERR]) {
            const errCode = parseErr(msg.attrs[AT.ERR]);
            const r = permQueue.shift();
            if (r) r.reject(new Error(`TURN error ${errCode}`));
          }
        }
      } catch (e) {}
    })().catch(() => {});

    const udpSend = (targetIp, targetPort, data) => {
      if (closed) { return; }
      cw.write(stunMsg(MT.SI, tid(), [
        stunAttr(AT.PEER, xorPeer(targetIp, targetPort)),
        stunAttr(AT.DATA, data),
      ])).catch(() => {});
    };

    const ensurePerm = async (ip) => {
      if (perms.has(ip)) { return; }
      perms.add(ip);
      let resolve, reject;
      const p = new Promise((res, rej) => { resolve = res; reject = rej; });
      permQueue.push({ resolve, reject });
      const m = await sign(stunMsg(MT.PQ, tid(), [stunAttr(AT.PEER, xorPeer(ip, 0)), ...aa]));
      try {
        await cw.write(m);
        await p;
      } catch (e) {
        perms.delete(ip);
      }
    };

    const setUDPHandler = (handler) => { onUDPData = handler; };

    return { udpSend, ensurePerm, setUDPHandler, close };
  } catch (e) {
    try { cw?.releaseLock(); } catch {}
    try { cr?.releaseLock(); } catch {}
    try { ctrl?.close(); } catch {}
    return null;
  }
};

// ─── TURN TCP Session Factory ──────────────────────────────────────────────
const createTURNTCPConnection = async (turnCfg, env, targetIp, targetPort) => {
  const { host, port, user, pass } = turnCfg;
  
  const authState = await getTurnAuthState(env, turnCfg, 6);
  if (!authState) {  return null; }

  const key = authState.key ? new Uint8Array(authState.key) : null;
  const aa = authState.aa.map(a => new Uint8Array(a));
  const sign = (m) => addIntegrity(m, key);

  let ctrl = null, dataSock = null;
  let cw = null, cr = null, dr = null;
  try {
    
    ctrl = await dial(host, port);
    cw = ctrl.writable.getWriter();
    cr = ctrl.readable.getReader();

    await cw.write(await sign(stunMsg(MT.AQ, tid(), [
      stunAttr(AT.TRANSPORT, new Uint8Array([6, 0, 0, 0])), ...aa
    ])));
    const [allocResp, allocEx] = await readStun(cr);
    if (!allocResp || allocResp.type !== MT.AO) {
      
      cw.releaseLock(); cr.releaseLock();
      try { ctrl.close(); } catch {}
      return null;
    }

    const peer = stunAttr(AT.PEER, xorPeer(targetIp, targetPort));
    
    await cw.write(cat(
      await sign(stunMsg(MT.PQ, tid(), [peer, ...aa])),
      await sign(stunMsg(MT.CQ, tid(), [peer, ...aa]))
    ));

    let [msg, buf] = await readStun(cr, allocEx);
    if (!msg || msg.type !== MT.PO) {
      
      cw.releaseLock(); cr.releaseLock();
      try { ctrl.close(); } catch {}
      return null;
    }

    [msg, buf] = await readStun(cr, buf);
    if (!msg || msg.type !== MT.CO || !msg.attrs[AT.CONNID]) {
      
      cw.releaseLock(); cr.releaseLock();
      try { ctrl.close(); } catch {}
      return null;
    }
    const connId = msg.attrs[AT.CONNID];

    dataSock = connect({ hostname: host, port });
    await dataSock.opened;
    const dw = dataSock.writable.getWriter();
    dr = dataSock.readable.getReader();

    await dw.write(await sign(stunMsg(MT.BQ, tid(), [
      stunAttr(AT.CONNID, connId), ...aa
    ])));

    const [bindResp, bindExtra] = await readStun(dr);
    if (!bindResp || bindResp.type !== MT.BO) {
      
      dw.releaseLock(); dr.releaseLock();
      try { dataSock.close(); } catch {}
      cw.releaseLock(); cr.releaseLock();
      try { ctrl.close(); } catch {}
      return null;
    }

    cw.releaseLock(); cr.releaseLock();
    cw = null; cr = null;

    dw.releaseLock();
    const grain = mkGrainTCP();
    const writer = dataSock.writable.getWriter();
    grain.setWriter(writer);

    const readable = new ReadableStream({
      start: c => bindExtra?.length && c.enqueue(bindExtra),
      pull: c => dr.read().then(({ done, value }) =>
        done ? c.close() : c.enqueue(new Uint8Array(value))
      ),
      cancel: () => {
        try { dr.releaseLock(); } catch {}
        try { dataSock.close(); } catch {}
      },
    });

    return {
      readable, writable: dataSock.writable, grain,
      close: () => {
        
        try { grain.close(); } catch {}
        try { writer.releaseLock(); } catch {}
        try { dr.releaseLock(); } catch {}
        try { dataSock.close(); } catch {}
        try { ctrl?.close(); } catch {}
      },
    };
  } catch (e) {
    
    try { cw?.releaseLock(); } catch {}
    try { cr?.releaseLock(); } catch {}
    try { dr?.releaseLock(); } catch {}
    try { dataSock?.close(); } catch {}
    try { ctrl?.close(); } catch {}
    return null;
  }
};

// ─── XUDP 輔助 ──────────────────────────────────────────────────────────────
const parseXUDP = d => {
  if (d.length < 6) return null;
  const metaLen = u16(d), metaEnd = 2 + metaLen;
  if (metaLen < 4 || metaEnd > d.length) return null;

  const status = d[4];
  const option = d[5];
  const network = metaEnd > 6 ? d[6] : 0;
  const port = metaEnd >= 9 ? u16(d, 7) : 0;
  const addrStart = 9;

  let host = '';
  let addrEnd = addrStart;
  if (metaEnd > addrStart) {
    const a = xudpAddr(d.subarray(addrStart, metaEnd));
    host = a[0];
    addrEnd = addrStart + a[1];
  }

  let globalID = null;
  if (status === SESS_NEW && addrEnd + 8 <= metaEnd) {
    globalID = d.subarray(addrEnd, addrEnd + 8);
  }

  let payload = null;
  let totalLen = metaEnd;
  if (option & OPT_DATA) {
    if (metaEnd + 2 > d.length) return null;
    const pLen = u16(d, metaEnd);
    if (metaEnd + 2 + pLen > d.length) return null;
    payload = d.subarray(metaEnd + 2, metaEnd + 2 + pLen);
    totalLen = metaEnd + 2 + pLen;
  }

  return { status, option, network, host, port, globalID, payload, totalLen };
};

const xudpAddr = d => {
  if (!d.length) return ['', 0];
  if (d[0] <= 1) return d.length >= 5 ? [d.subarray(1, 5).join('.'), 5] : ['', 0];
  if (d[0] === 2) return d.length >= 2 + d[1] ? [td.decode(d.subarray(2, 2 + d[1])), 2 + d[1]] : ['', 0];
  return d[0] === 3 && d.length >= 17 ? [`[${Array.from({ length: 8 }, (_, i) => u16(d, 1 + i * 2).toString(16)).join(':')}]`, 17] : ['', 0];
};

const xudpResp = (host, port, payload) => {
  const a = writeAddr(host), ml = 7 + a.length;
  const buf = new Uint8Array(2 + ml + 2 + payload.length);
  [buf[0], buf[1], buf[4], buf[5], buf[6], buf[7], buf[8]] = [ml >> 8, ml & 0xFF, 2, 1, 2, port >> 8, port & 0xFF];
  buf.set(a, 9);
  const pOff = 2 + ml;
  [buf[pOff], buf[pOff + 1]] = [payload.length >> 8, payload.length & 0xFF];
  buf.set(payload, pOff + 2);
  return buf;
};

// ─── TURN 配置解析 ──────────────────────────────────────────────────────────
const parseTurnHeader = (v) => {
  if (!v) return null;
  const m = v.trim().match(/^(?:turn:\/\/)?([^:]+):(\d+)(?::([^:]*):(.*))?$/);
  return m ? { host: m[1], port: +m[2], user: m[3] || '', pass: m[4] || '' } : null;
};

// ─── XMUX Session Manager ───────────────────────────────────────────────────
const createSessionManager = (controller, turnCfg, env, udpPool, isStreamOne) => {
  const sessions = new Map();
  const udpMap = new Map();
  let closed = false;

  const downWrite = (sid, data) => {
    if (closed) return;
    try {
      if (isStreamOne && sid === 0) {
        controller.enqueue(data);
      } else {
        controller.enqueue(buildXMUXKeepFrame(sid, data));
      }
    } catch {}
  };

  const closeAll = () => {
    if (closed) return;
    closed = true;
    for (const [, s] of sessions) {
      try { s.grain?.close(); } catch {}
      try { s.writer?.releaseLock(); } catch {}
      try { s.sock?.close(); } catch {}
    }
    sessions.clear();
    udpMap.clear();
    try { controller.close(); } catch {}
  };

  const closeSession = (sid) => {
    const s = sessions.get(sid);
    if (!s) return;
    try { s.grain?.close(); } catch {}
    try { s.writer?.releaseLock(); } catch {}
    try { s.sock?.close(); } catch {}
    sessions.delete(sid);
    udpMap.delete(sid);
  };

  const newTCPSession = async (sid, host, port) => {
    closeSession(sid);
    const resolved = await resolveIP(host);
    if (!resolved) { return; }
    const tcpConn = await createTURNTCPConnection(turnCfg, env, resolved, port);
    if (!tcpConn) { return; }

    const grain = tcpConn.grain;
    const sock = {
      readable: tcpConn.readable,
      writable: tcpConn.writable,
      close: tcpConn.close,
    };
    sessions.set(sid, {
      sock, writer: null, grain,
      target: { host, port }, net: NET_TCP, alive: Date.now(),
    });

    const reader = sock.readable.getReader();
    (async () => {
      try {
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          if (!value?.byteLength) continue;
          downWrite(sid, new Uint8Array(value));
        }
      } catch (e) {} finally {
        try { reader.releaseLock(); } catch {}
        closeSession(sid);
      }
    })().catch(() => {});
  };

  const ensureUDPSession = async (sid, host, port) => {
    if (udpMap.has(sid)) {
      return udpMap.get(sid);
    }
    const resolved = await resolveIP(host);
    if (!resolved) return null;
    const s = { host, port, ip: resolved };
    udpMap.set(sid, s);
    await udpPool?.ensurePerm(resolved);
    return s;
  };

  const handleFrame = async (frame) => {
    const { sid, status, option, target, data } = frame;

    switch (status) {
      case SESS_NEW: {
        if (!target) { return; }

        if (target.net === NET_TCP) {
          await newTCPSession(sid, target.host, target.port);
        } else if (target.net === NET_UDP) {
          await ensureUDPSession(sid, target.host, target.port);
          sessions.set(sid, { net: NET_UDP, target, alive: Date.now(), grain: null, writer: null, sock: null });
        }
        if (data && (option & OPT_DATA)) {
          const s = sessions.get(sid);
          if (s?.grain) {
            s.grain.send(data);
          } else if (s?.net === NET_UDP && udpPool) {
            const us = udpMap.get(sid);
            if (us) {
              let xd = data;
              while (xd.length >= 6) {
                const f = parseXUDP(xd);
                if (!f) break;
                if (f.payload?.length && f.host) {
                  const sendIP = us.ip || await resolveIP(f.host);
                  if (sendIP) { await udpPool.ensurePerm(sendIP); udpPool.udpSend(sendIP, f.port, f.payload); }
                }
                xd = xd.subarray(f.totalLen);
              }
            }
          }
        }
        break;
      }
      case SESS_KEEP: {
        const s = sessions.get(sid);
        if (!s) { return; }
        s.alive = Date.now();
        if (data && (option & OPT_DATA)) {
          if (s.net === NET_TCP && s.grain) {
            s.grain.send(data);
          } else if (s.net === NET_UDP && udpPool) {
            const us = udpMap.get(sid);
            if (us) {
              let xd = data;
              while (xd.length >= 6) {
                const f = parseXUDP(xd);
                if (!f) break;
                if (f.payload?.length && f.host) {
                  const sendIP = us.ip || await resolveIP(f.host);
                  if (sendIP) { await udpPool.ensurePerm(sendIP); udpPool.udpSend(sendIP, f.port, f.payload); }
                }
                xd = xd.subarray(f.totalLen);
              }
            }
          }
        }
        if (target && target.net === NET_UDP && s.net === NET_UDP) {
          s.target = target;
          await ensureUDPSession(sid, target.host, target.port);
        }
        break;
      }
      case SESS_END:
        closeSession(sid);
        break;
      case SESS_KEEPALIVE: {
        const s = sessions.get(sid);
        if (s) s.alive = Date.now();
        break;
      }
    }
  };

  const idleCheck = () => {
    const now = Date.now();
    for (const [sid, s] of sessions) {
      if (now - s.alive > CFG.SESSION_IDLE_MS) {
        
        closeSession(sid);
      }
    }
  };
  const idleTimer = setInterval(idleCheck, 15_000);

  return { handleFrame, closeAll, closeSession, sessions, idleTimer, udpMap, downWrite };
};

// ─── 主 Fetch Handler ───────────────────────────────────────────────────────
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const normPath = url.pathname.replace(/\/+$/, '') || '/';

    if (request.method === 'GET' && normPath === '/') {
      return Response.redirect('https://github.com/utopian-society', 302);
    }
    if (request.method === 'GET') {
      return new Response('Not Found', { status: 404 });
    }
    if (request.method !== 'POST' || normPath !== CFG.PATH) {
      return new Response('Not Found', { status: 404 });
    }

    const turnHeader = request.headers.get('X-Turn') || request.headers.get('x-turn');
    const turnCfg = parseTurnHeader(turnHeader);
    if (!turnCfg) {
      return new Response('TURN server required (X-Turn header)', { status: 400 });
    }

    // ── Phase 1: 自適應讀取 VLESS header ──
    const reader = request.body.getReader();
    let cache = new Uint8Array(0);

    while (cache.length < 22) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value) cache = cat(cache, toU8(value));
    }
    if (cache.length < 22) {
      try { reader.releaseLock(); } catch {}
      return new Response('Incomplete header', { status: 400 });
    }
    if (!matchUUID(cache)) {
      try { reader.releaseLock(); } catch {}
      return new Response('UUID mismatch', { status: 403 });
    }

    const addInfoLen = cache[17];
    const cmdOff = 18 + addInfoLen;
    const portOff = cmdOff + 1;
    const addrTypeOff = portOff + 2;
    const addrBodyOff = addrTypeOff + 1;

    while (cache.length <= addrTypeOff) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value) cache = cat(cache, toU8(value));
    }
    if (cache.length <= addrTypeOff) {
      try { reader.releaseLock(); } catch {}
      return new Response('Incomplete header', { status: 400 });
    }

    const atype = cache[addrTypeOff];
    const cmdPreview = cache[cmdOff];

    let needBytes;
    if (cmdPreview === 0x03) {
      needBytes = addrTypeOff;
    } else if (atype === ATYPE_IPV4) {
      needBytes = addrBodyOff + 4;
    } else if (atype === ATYPE_IPV6) {
      needBytes = addrBodyOff + 16;
    } else if (atype === ATYPE_DOMAIN) {
      while (cache.length <= addrBodyOff) {
        const { done, value } = await reader.read();
        if (done) break;
        if (value) cache = cat(cache, toU8(value));
      }
      if (cache.length <= addrBodyOff) {
        try { reader.releaseLock(); } catch {}
        return new Response('Incomplete header', { status: 400 });
      }
      const domainLen = cache[addrBodyOff];
      needBytes = addrBodyOff + 1 + domainLen;
    } else {
      // UDP: atype 可能是 0/4/5/255，全部放行
      
      needBytes = addrBodyOff;
    }

    while (cache.length < needBytes) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value) cache = cat(cache, toU8(value));
    }
    if (cache.length < needBytes) {
      try { reader.releaseLock(); } catch {}
      return new Response('Incomplete address', { status: 400 });
    }

    const vless = parseVLESS(cache);
    if (!vless) {
      try { reader.releaseLock(); } catch {}
      return new Response('Invalid target address', { status: 422 });
    }

    const remaining = cache.subarray(vless.dataOffset);
    const vlessTarget = { cmd: vless.cmd, host: vless.addr, port: vless.port, atype: vless.atype };

    // ── UDP 專用路徑 (cmd=0x02 / cmd=0x03 both XUDP in XMUX stack) ────
    if (vlessTarget.cmd === 0x02 || vlessTarget.cmd === 0x03) {
      let xd = remaining;

      let udpPoolRef = null;

      const responseStream = new ReadableStream({
        start(controller) {
          controller.enqueue(vlessResp);

          ctx.waitUntil((async () => {
            try {
              const pool = await createTURNUDPPool(turnCfg, env);
              if (!pool) { controller.error(new Error('TURN UDP pool init failed')); return; }
              udpPoolRef = pool;

              pool.setUDPHandler((ip, port, data) => {
                try { controller.enqueue(xudpResp(ip, port, data)); } catch {}
              });

              const sendFrame = async (f) => {
                if (f.payload?.length && f.host) {
                  const resolved = await resolveIP(f.host);
                  if (resolved) { await pool.ensurePerm(resolved); pool.udpSend(resolved, f.port, f.payload); }
                }
              };

              let uploadBuffer = new Uint8Array(0);

              const processXUDPChunk = async (chunk) => {
                let c = cat(uploadBuffer, chunk);
                uploadBuffer = new Uint8Array(0);

                while (c.length >= 6) {
                  const f = parseXUDP(c);
                  if (!f) {
                    uploadBuffer = c;
                    return;
                  }
                  await sendFrame(f);
                  c = c.subarray(f.totalLen);
                }
                if (c.length > 0) {
                  uploadBuffer = c;
                }
              };

              await processXUDPChunk(xd);

              for (;;) {
                const { done, value } = await reader.read();
                if (done) break;
                if (value) await processXUDPChunk(toU8(value));
              }
            } catch (e) {  } finally {
              
              try { reader.releaseLock(); } catch {}
              udpPoolRef?.close();
            }
          })().catch(() => {}));
        },
        cancel() {
          
          try { reader.releaseLock(); } catch {}
          udpPoolRef?.close();
        },
      });

      return new Response(responseStream, {
        status: 200,
        headers: {
          'Content-Type': 'application/octet-stream',
          'Cache-Control': 'no-cache, no-store, must-revalidate',
          'X-Accel-Buffering': 'no',
          'Connection': 'keep-alive',
          'User-Agent': 'Go-http-client/2.0',
        },
      });
    }

    // ── TCP / XMUX 路徑 (cmd=0x01) ──────────────────────────────────────
    const isStreamOne = vlessTarget.cmd === 0x01;
    let sm = null;
    let udpPool = null;

    const responseStream = new ReadableStream({
      start(controller) {
        controller.enqueue(vlessResp);

        let uploadBuffer = new Uint8Array(0);

        const processFrames = async (chunk, smRef, vlessTgt) => {
          let c = cat(uploadBuffer, chunk);
          uploadBuffer = new Uint8Array(0);

          while (c.length >= 4) {
            const frame = parseXMUXFrame(c, 0);
            if (!frame) {
              if (vlessTgt && vlessTgt.cmd === 0x01 && c.length > 0) {
                if (!smRef.sessions.has(0)) {
                  await smRef.handleFrame({
                    sid: 0, status: SESS_NEW, option: OPT_DATA,
                    target: { net: NET_TCP, host: vlessTgt.host, port: vlessTgt.port },
                    data: null, frameEnd: 0,
                  });
                }
                const s = smRef.sessions.get(0);
                if (s?.grain) { s.grain.send(c); }
                return;
              }
              uploadBuffer = c;
              return;
            }
            await smRef.handleFrame(frame);
            c = c.subarray(frame.frameEnd);
          }
          if (c.length > 0) {
            uploadBuffer = c;
          }
        };

        ctx.waitUntil((async () => {
          try {
            udpPool = await createTURNUDPPool(turnCfg, env);
            if (!udpPool) {
              controller.error(new Error('TURN UDP pool init failed'));
              return;
            }

            sm = createSessionManager(controller, turnCfg, env, udpPool, isStreamOne);

            udpPool.setUDPHandler((ip, port, data) => {
              for (const [sid, us] of sm.udpMap) {
                if (us.ip === ip && us.port === port) {
                  sm.downWrite(sid, xudpResp(us.host, us.port, data));
                  return;
                }
              }
              sm.downWrite(0, xudpResp(ip, port, data));
            });

            await processFrames(remaining, sm, vlessTarget);

            for (;;) {
              const { done, value } = await reader.read();
              if (done) { break; }
              if (value) {
                const chunk = toU8(value);
                if (chunk.byteLength) await processFrames(chunk, sm, vlessTarget);
              }
            }
          } catch (e) {} finally {
            try { reader.releaseLock(); } catch {}
            sm?.closeAll();
            udpPool?.close();
            clearInterval(sm?.idleTimer);
          }
        })().catch(() => {}));
      },

      cancel() {
        
        try { reader.releaseLock(); } catch {}
        sm?.closeAll();
        udpPool?.close();
        clearInterval(sm?.idleTimer);
      },
    });

    return new Response(responseStream, {
      status: 200,
      headers: {
        'Content-Type': 'application/octet-stream',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'X-Accel-Buffering': 'no',
        'Connection': 'keep-alive',
        'User-Agent': 'Go-http-client/2.0',
      },
    });
  },
};
