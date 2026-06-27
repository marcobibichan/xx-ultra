import { connect } from 'cloudflare:sockets';

const CFG = {
  token: 'af6c7297-0ae9-48d3-bcf6-e34bea0d9e56',
  chunk:   64 * 1024,
  dnPack:  64 * 1024,
  dnTail:   4 * 1024,
  dnMs:           1,
  upPack:  16 * 1024,
  upQMax: 256 * 1024,
  maxED:        8192,
  kaMs:        25000
};

// ===== pre-parse token =====
const hex = c => (c > 64 ? c + 9 : c) & 0xF;
const keyB = new Uint8Array(16);
for (let i = 0, p = 0, c; i < 16; i++) {
  c = CFG.token.charCodeAt(p++); if (c === 45) c = CFG.token.charCodeAt(p++);
  const hi = hex(c);
  c = CFG.token.charCodeAt(p++); if (c === 45) c = CFG.token.charCodeAt(p++);
  keyB[i] = hi << 4 | hex(c);
}
const [K0,K1,K2,K3,K4,K5,K6,K7,K8,K9,K10,K11,K12,K13,K14,K15] = keyB;
const checkKey = c =>
  c[1]===K0&&c[2]===K1&&c[3]===K2&&c[4]===K3&&c[5]===K4&&c[6]===K5&&c[7]===K6&&
  c[8]===K7&&c[9]===K8&&c[10]===K9&&c[11]===K10&&c[12]===K11&&c[13]===K12&&c[14]===K13&&c[15]===K14&&c[16]===K15;

// ===== helpers =====
const dec = new TextDecoder(), enc = s => new TextEncoder().encode(s);
const u16 = (b, o = 0) => (b[o] << 8) | b[o + 1];
const pad4 = n => -n & 3;
const safeClose = (...a) => a.forEach(x => { try { x?.close?.(); } catch {} });

const addr = (t, b) =>
    t === 1 ? `${b[0]}.${b[1]}.${b[2]}.${b[3]}`
  : t === 3 ? dec.decode(b)
  : `[${Array.from({ length: 8 }, (_, i) => u16(b, i * 2).toString(16)).join(':')}]`;

const parseAddr = (b, o, t) => {
  const l = t === 3 ? b[o++] : t === 1 ? 4 : t === 4 ? 16 : 0;
  return l && o + l <= b.length ? { addrBytes: b.subarray(o, o + l), dataOff: o + l } : null;
};

const unpack = c => {
  if (c.length < 24 || !checkKey(c)) return null;
  let o = 19 + c[17], port = u16(c, o), t = c[o + 2]; if (t !== 1) t += 1;
  const a = parseAddr(c, o + 3, t);
  return a ? { addrType: t, ...a, dataOff: a.dataOff, port } : null;
};

// ===== upload queue =====
const mkQ = (cap, qCap = cap, itemsMax = Math.max(1, qCap >> 8)) => {
  let q = [], h = 0, qB = 0, buf = null;
  const trim = () => { h > 32 && h * 2 >= q.length && (q = q.slice(h), h = 0); };
  return {
    get bytes()  { return qB; },
    get size()   { return q.length - h; },
    get empty()  { return h >= q.length; },
    clear()      { q = []; h = 0; qB = 0; },
    add(d) {
      const n = d?.byteLength || 0; if (!n) return 1;
      if (qB + n > qCap || q.length - h >= itemsMax) return 0;
      q.push(d); qB += n; return 1;
    },
    take() {
      if (h >= q.length) return null;
      const d = q[h]; q[h++] = undefined; qB -= d.byteLength; trim();
      return d;
    },
    bundle(d) {
      d ||= this.take();
      if (!d || h >= q.length || d.byteLength >= cap) return [d, 0];
      let n = d.byteLength, e = h;
      while (e < q.length) { const nn = n + q[e].byteLength; if (nn > cap) break; n = nn; e++; }
      if (e === h) return [d, 0];
      const out = buf ||= new Uint8Array(cap);
      out.set(d, 0);
      for (let o = d.byteLength; h < e;) {
        const x = q[h]; q[h++] = undefined; qB -= x.byteLength;
        out.set(x, o); o += x.byteLength;
      }
      trim();
      return [out.subarray(0, n), 1];
    }
  };
};

// ===== download aggregator =====
const mkDn = w => {
  const cap  = CFG.dnPack,
        tail = CFG.dnTail,
        low  = 16 * 1024;
  let pb = new Uint8Array(cap), p = 0, tp = 0, gen = 0, qk = 0, qr = 0, mq = 0;
  const flush = () => {
    if (tp) { clearTimeout(tp); tp = 0; }
    mq = 0;
    if (!p) return;
    try { w.send(pb.subarray(0, p).slice()); } catch {}
    pb = new Uint8Array(cap); p = 0; qr = 0;
  };
  const ripen = () => {
    if (tp || mq) return; mq = 1; qk = gen;
    queueMicrotask(() => {
      mq = 0;
      if (!p || tp) return;
      if (p >= low) return flush();
      tp = setTimeout(() => {
        tp = 0;
        if (!p) return;
        if (p >= low || qr >= 2) return flush();
        qr++;
      }, Math.max(CFG.dnMs, 1));
    });
  };
  return {
    feed(u) {
      let o = 0, n = u?.byteLength || 0; if (!n) return;
      while (o < n) {
        if (!p && n - o >= cap) {
          const m = Math.min(cap, n - o);
          try { w.send(o || m !== n ? u.subarray(o, o + m) : u); } catch {}
          o += m; continue;
        }
        const m = Math.min(cap - p, n - o);
        pb.set(u.subarray(o, o + m), p); p += m; o += m; gen++;
        if (p === cap) { flush(); continue; }
        if (cap - p < tail) { flush(); continue; }
        if (p >= low) { flush(); continue; }
        ripen();
      }
    },
    flush
  };
};

// ===== byob drain =====
const drain = async (rd, dn) => {
  let r;
  try { r = rd.getReader({ mode: 'byob' }); } catch { r = rd.getReader(); }
  const byob = r.mode === 'byob';
  let buf = byob ? new ArrayBuffer(CFG.chunk) : null;
  try {
    for (;;) {
      let v, done;
      if (byob) {
        ({ done, value: v } = await r.read(new Uint8Array(buf, 0, CFG.chunk)));
      } else {
        ({ done, value: v } = await r.read());
      }
      if (done) break;
      if (!v?.byteLength) continue;
      if (v.byteLength >= CFG.chunk) {
        dn.flush();
        try { dn.feed(v); } catch {}
        if (byob) buf = new ArrayBuffer(CFG.chunk);
      } else {
        dn.feed(v.slice ? v.slice() : new Uint8Array(v));
        if (byob) buf = v.buffer;
      }
    }
    dn.flush();
  } catch (e) {
    console.error('[drain] exit:', e?.message ?? '');
  } finally {
    try { dn.flush(); } catch {}
    try { r?.releaseLock(); } catch {}
  }
};

// ===== dns cache =====
const dnsCache = new Map();
const resolve = h =>
  /^\d+\.\d+\.\d+\.\d+$/.test(h) ? Promise.resolve(h)
  : dnsCache.has(h) ? Promise.resolve(dnsCache.get(h))
  : (dnsCache.set(h,
      fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(h)}&type=A`,
            { headers: { Accept: 'application/dns-json' } })
        .then(r => r.json())
        .then(j => j.Answer?.find(a => a.type === 1)?.data ?? null)
        .catch(() => null)
    ),
     dnsCache.get(h));

// ===== direct dial =====
const direct = async (h, p) => {
  const s = connect({ hostname: h, port: p });
  await s.opened;
  return s;
};

// ===== relay URL parse =====
const getRelay = url => {
  const d = decodeURIComponent(url);
  console.log('[getRelay] url:', d);
  const m = d.match(/[?&]relay=([^?&#\s]+)/i);
  if (!m) { console.log('[getRelay] no relay param'); return null; }
  const t = m[1], at = t.lastIndexOf('@');
  const cred = at >= 0 ? t.slice(0, at) : '',
        hostPort = t.slice(at + 1);
  const [host, port] = hostPort.split(':');
  const ci = cred.indexOf(':');
  const result = port ? {
    host,
    port: +port,
    user: ci >= 0 ? cred.slice(0, ci) : '',
    pass: ci >= 0 ? cred.slice(ci + 1) : ''
  } : null;
  console.log('[getRelay] result:', result ? `${result.user}@${result.host}:${result.port}` : 'null');
  return result;
};

// ===== SX protocol (RFC 5389 / 5766 / 6062) =====
const COOKIE = new Uint8Array([0x21, 0x12, 0xA4, 0x42]);
const MT = {
  AQ: 0x003, AO: 0x103, AE: 0x113,
  PQ: 0x008, PO: 0x108,
  CQ: 0x00A, CO: 0x10A,
  BQ: 0x00B, BO: 0x10B,
  SI: 0x016, DI: 0x017
};
const AT = {
  UNAME: 0x006, INTEG: 0x008, ECODE: 0x009,
  PEER:  0x012, DATA:  0x013,
  REALM: 0x014, NONCE: 0x015,
  TRANSP:0x019, CONNID:0x02A
};

const cat = (...a) => {
  const r = new Uint8Array(a.reduce((s, x) => s + x.length, 0));
  a.reduce((o, x) => (r.set(x, o), o + x.length), 0);
  return r;
};

const sxTid = () => crypto.getRandomValues(new Uint8Array(12));

const sxAttr = (t, v) => {
  const b = new Uint8Array(4 + v.length + pad4(v.length));
  new DataView(b.buffer).setUint16(0, t);
  new DataView(b.buffer).setUint16(2, v.length);
  b.set(v, 4);
  return b;
};

const sxMsg = (t, id, a) => {
  const bd = cat(...a);
  const h = new Uint8Array(20);
  new DataView(h.buffer).setUint16(0, t);
  new DataView(h.buffer).setUint16(2, bd.length);
  h.set(COOKIE, 4); h.set(id, 8);
  return cat(h, bd);
};

const xorPeer = (ip, port) => {
  const b = new Uint8Array(8); b[1] = 1;
  new DataView(b.buffer).setUint16(2, port ^ 0x2112);
  ip.split('.').forEach((v, i) => b[4 + i] = +v ^ COOKIE[i]);
  return b;
};

const parseSx = d => {
  if (d.length < 20 || COOKIE.some((v, i) => d[4 + i] !== v)) return null;
  const dv = new DataView(d.buffer, d.byteOffset, d.byteLength);
  const ml = dv.getUint16(2);
  const attrs = {};
  for (let o = 20; o + 4 <= 20 + ml;) {
    const t = dv.getUint16(o), l = dv.getUint16(o + 2);
    if (o + 4 + l > d.length) break;
    attrs[t] = d.subarray(o + 4, o + 4 + l);
    o += 4 + l + pad4(l);
  }
  return { type: dv.getUint16(0), attrs };
};

const errCode = d => (d?.length >= 4 ? (d[2] & 7) * 100 + d[3] : 0);

const readSx = async (rd, buf) => {
  let b = buf ?? new Uint8Array(0);
  const pull = async () => {
    const { done, value } = await rd.read();
    if (done) throw 0;
    b = cat(b, new Uint8Array(value));
  };
  try {
    while (b.length < 20) await pull();
    const n = 20 + u16(b, 2);
    while (b.length < n) await pull();
    return [parseSx(b.subarray(0, n)), b.length > n ? b.subarray(n) : null];
  } catch { return [null, null]; }
};

const hmac = async (m, key) => {
  const c = new Uint8Array(m);
  new DataView(c.buffer).setUint16(2, new DataView(c.buffer).getUint16(2) + 24);
  const k = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
  return cat(c, sxAttr(AT.INTEG, new Uint8Array(await crypto.subtle.sign('HMAC', k, c))));
};

const md5 = async s => new Uint8Array(await crypto.subtle.digest('MD5', enc(s)));

// ===== relay allocate with auth pipeline =====
const relayAuth = async (w, r, transport, rc, pipeline) => {
  const tp = new Uint8Array([transport, 0, 0, 0]);
  await w.write(sxMsg(MT.AQ, sxTid(), [sxAttr(AT.TRANSP, tp)]));
  let [msg, ex] = await readSx(r);
  if (!msg) return null;

  let key = null, aa = [];
  const sign = m => key ? hmac(m, key) : Promise.resolve(m);

  if (msg.type === MT.AE && errCode(msg.attrs[AT.ECODE]) === 401) {
    const realm = dec.decode(msg.attrs[AT.REALM] ?? new Uint8Array(0));
    const nonce = msg.attrs[AT.NONCE] ?? new Uint8Array(0);
    const { user, pass } = rc;
    if (user) {
      key = await md5(`${user}:${realm}:${pass}`);
      aa = [sxAttr(AT.UNAME, enc(user)), sxAttr(AT.REALM, enc(realm)), sxAttr(AT.NONCE, nonce)];
    } else {
      key = await md5(`:${realm}:`);
      aa = [sxAttr(AT.REALM, enc(realm)), sxAttr(AT.NONCE, nonce)];
    }
    const aq = await hmac(sxMsg(MT.AQ, sxTid(), [sxAttr(AT.TRANSP, tp), ...aa]), key);
    const extras = pipeline ? await Promise.all(pipeline(aa, sign)) : [];
    await w.write(extras.length ? cat(aq, ...extras) : aq);
    [msg, ex] = await readSx(r, ex);
    if (!msg) return null;
  } else if (pipeline && msg.type === MT.AO) {
    const extras = await Promise.all(pipeline(aa, sign));
    if (extras.length) await w.write(cat(...extras));
  }
  return msg.type === MT.AO ? { key, aa, ex, sign } : null;
};

// ===== relay TCP connect (RFC 6062) =====
const relayConn = async (rc, targetIp, targetPort) => {
  let ctrl = null, data = null;
  const closeAll = () => safeClose(ctrl, data);
  try {
    const { host, port } = rc;

    console.log('[relayConn] ctrl connect:', host, port);
    ctrl = connect({ hostname: host, port });
    await ctrl.opened;
    const cw = ctrl.writable.getWriter(),
          cr = ctrl.readable.getReader();

    const peer = sxAttr(AT.PEER, xorPeer(targetIp, targetPort));
    console.log('[relayConn] allocating...');
    const auth = await relayAuth(cw, cr, 6, rc, (aa, sign) => [
      sign(sxMsg(MT.PQ, sxTid(), [peer, ...aa])),
      sign(sxMsg(MT.CQ, sxTid(), [peer, ...aa]))
    ]);
    if (!auth) { console.error('[relayConn] allocate failed'); closeAll(); return null; }
    const { aa, sign } = auth;
    let ex = auth.ex;

    let r;
    [r, ex] = await readSx(cr, ex);
    if (r?.type !== MT.PO) { console.error('[relayConn] perm fail'); closeAll(); return null; }
    [r, ex] = await readSx(cr, ex);
    if (r?.type !== MT.CO || !r.attrs[AT.CONNID]) { console.error('[relayConn] conn-attempt fail'); closeAll(); return null; }

    console.log('[relayConn] data connect:', host, port);
    data = connect({ hostname: host, port });
    await data.opened;
    const dw = data.writable.getWriter(),
          dr = data.readable.getReader();
    await dw.write(await sign(
      sxMsg(MT.BQ, sxTid(), [sxAttr(AT.CONNID, r.attrs[AT.CONNID]), ...aa])
    ));
    let extra;
    [r, extra] = await readSx(dr);
    if (r?.type !== MT.BO) { console.error('[relayConn] bind fail'); closeAll(); return null; }

    dr.releaseLock(); dw.releaseLock();
    cr.releaseLock(); cw.releaseLock();

    console.log('[relayConn] established');
    return {
      readable:   data.readable,
      writable:   data.writable,
      extraBytes: extra,
      close:      closeAll
    };
  } catch (e) {
    console.error('[relayConn] error:', e?.message ?? '');
    closeAll();
    return null;
  }
};

// ===== ws handler =====
const ws = async req => {
  const [client, server] = Object.values(new WebSocketPair());
  server.accept({ allowHalfOpen: true });

  const ed     = req.headers.get('sec-websocket-protocol');
  const relay  = getRelay(req.url);

  console.log('[ws] upgrade', { relay: !!relay, edLen: ed?.length ?? 0 });

  const uq = mkQ(CFG.upPack, CFG.upQMax, CFG.upQMax >> 8);
  let curW = null, peer = null, closed = false, busy = false;
  let firstBuf = null;

  const closeAll = () => {
    if (closed) return; closed = true;
    console.log('[ws] closeAll');
    uq.clear();
    firstBuf = null;
    try { curW?.releaseLock(); } catch {}
    safeClose(peer);
    try { server.close(1000, 'end'); } catch {}
  };

  const toU8 = d =>
    d instanceof Uint8Array ? d
    : ArrayBuffer.isView(d) ? new Uint8Array(d.buffer, d.byteOffset, d.byteLength)
    : new Uint8Array(d);

  const thresh = async () => {
    if (busy || closed) return;
    busy = true;
    try {
      for (;;) {
        if (closed) break;

        if (curW) {
          const [d] = uq.bundle();
          if (!d) break;
          await curW.write(d);
          continue;
        }

        const [d] = uq.bundle();
        if (!d) break;
        const r = unpack(d);
        if (!r) { console.error('[thresh] unpack fail'); closeAll(); return; }

        try { server.send(new Uint8Array([d[0], 0])); } catch {}

        const host = addr(r.addrType, r.addrBytes);
        firstBuf = d.subarray(r.dataOff);
        console.log('[thresh] target:', host, r.port);

        if (relay) {
          const ip = r.addrType === 1 ? host : await resolve(host);
          if (!ip) { console.error('[thresh] resolve fail'); closeAll(); return; }
          console.log('[thresh] relay dial:', ip, r.port);
          peer = await relayConn(relay, ip, r.port).catch(() => null);
        } else {
          console.log('[thresh] direct dial:', host, r.port);
          peer = await direct(host, r.port).catch(() => null);
        }
        if (!peer) { console.error('[thresh] dial fail'); closeAll(); return; }

        curW = peer.writable.getWriter();
        if (firstBuf?.byteLength) await curW.write(firstBuf);
        firstBuf = null;

        const dn = mkDn(server);
        if (peer.extraBytes?.byteLength) {
          try { dn.feed(new Uint8Array(peer.extraBytes)); } catch {}
          if (peer.extraBytes.byteLength >= 1024) dn.flush();
        }

        drain(peer.readable, dn).finally(() => { if (!closed) closeAll(); });
        continue;
      }
    } catch (e) {
      console.error('[thresh] error:', e?.message ?? '');
      if (!closed) closeAll();
    } finally {
      busy = false;
      if (!uq.empty && !closed) queueMicrotask(thresh);
    }
  };

  if (ed?.length <= CFG.maxED) {
    try {
      const early = Uint8Array.fromBase64(ed, { alphabet: 'base64url' });
      if (early?.byteLength && uq.add(early)) thresh();
    } catch {}
  }

  const kaId = setInterval(() => {
    if (closed) { clearInterval(kaId); return; }
    try { server.ping?.(); } catch { clearInterval(kaId); closeAll(); }
  }, CFG.kaMs);

  server.addEventListener('message', e => {
    if (closed) return;
    const data = toU8(e.data instanceof ArrayBuffer ? e.data : e.data?.buffer ?? e.data);
    if (!data.byteLength) return;
    if (!uq.add(data)) { closeAll(); return; }
    thresh();
  });
  server.addEventListener('close', () => { clearInterval(kaId); closeAll(); });
  server.addEventListener('error', () => { clearInterval(kaId); closeAll(); });

  return new Response(null, {
    status: 101,
    webSocket: client,
    headers: { 'Sec-WebSocket-Extensions': '' }
  });
};

export default {
  fetch: req =>
    req.headers.get('Upgrade')?.toLowerCase() === 'websocket'
      ? ws(req)
      : new Response('ok')
};