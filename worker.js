import { DurableObject } from "cloudflare:workers";
import { connect } from "cloudflare:sockets";

// ================================================================
// CFG — Recalibrated Tuning
// ================================================================
const CFG = {
  id: "0bc296d4-8f79-42df-9b5d-5c8b880d3449",
  chunk: 64 * 1024,
  dnPack: 8192,
  dnTail: 384,
  dnMs: 0,
  upPack: 4096,
  upQMax: 256 * 1024,
  maxED: 8192,
  concur: 4,
  fastPath: 2048,
  backLogLimit: 256 * 1024,
};

// ================================================================
// UUID
// ================================================================
const hex = (c) => (c > 64 ? c + 9 : c) & 0xf;
const idB = new Uint8Array(16);
for (let i = 0, p = 0, c; i < 16; i++) {
  c = CFG.id.charCodeAt(p++);
  if (c === 45) c = CFG.id.charCodeAt(p++);
  const hi = hex(c);
  c = CFG.id.charCodeAt(p++);
  if (c === 45) c = CFG.id.charCodeAt(p++);
  idB[i] = (hi << 4) | hex(c);
}
const [I0, I1, I2, I3, I4, I5, I6, I7, I8, I9, I10, I11, I12, I13, I14, I15] =
  idB;
const matchID = (c) =>
  c[1] === I0 &&
  c[2] === I1 &&
  c[3] === I2 &&
  c[4] === I3 &&
  c[5] === I4 &&
  c[6] === I5 &&
  c[7] === I6 &&
  c[8] === I7 &&
  c[9] === I8 &&
  c[10] === I9 &&
  c[11] === I10 &&
  c[12] === I11 &&
  c[13] === I12 &&
  c[14] === I13 &&
  c[15] === I14 &&
  c[16] === I15;

// ================================================================
// 通用工具
// ================================================================
const dec = new TextDecoder(),
  enc = (s) => new TextEncoder().encode(s);
const u16 = (b, o = 0) => (b[o] << 8) | b[o + 1],
  pad4 = (n) => -n & 3;
const safeClose = (...a) =>
  a.forEach((x) => {
    try {
      x?.close?.();
    } catch {}
  });
const safeSend = (w, d) => {
  try {
    w.send(d);
  } catch {}
};
const cat = (...a) => {
  const r = new Uint8Array(a.reduce((s, x) => s + x.length, 0));
  a.reduce((o, x) => (r.set(x, o), o + x.length), 0);
  return r;
};
const toU8 = (d) =>
  d instanceof Uint8Array
    ? d
    : ArrayBuffer.isView(d)
      ? new Uint8Array(d.buffer, d.byteOffset, d.byteLength)
      : new Uint8Array(d);

// ---- Small Buffer Pool ----
const _pool = [];
const poolGet = (size) => {
  for (let i = _pool.length - 1; i >= 0; i--) {
    if (_pool[i].byteLength >= size) return _pool.splice(i, 1)[0];
  }
  return new ArrayBuffer(size);
};
const poolPut = (buf) => {
  if (_pool.length < 8 && buf.byteLength <= 8192) _pool.push(buf);
};

// ================================================================
// Protocol
// ================================================================
const addr = (t, b) =>
  t === 1
    ? `${b[0]}.${b[1]}.${b[2]}.${b[3]}`
    : t === 3
      ? dec.decode(b)
      : `[${Array.from({ length: 8 }, (_, i) => u16(b, i * 2).toString(16)).join(":")}]`;
const parseAddr = (b, o, t) => {
  const l = t === 3 ? b[o++] : t === 1 ? 4 : t === 4 ? 16 : 0;
  return l && o + l <= b.length
    ? { addrBytes: b.subarray(o, o + l), dataOffset: o + l }
    : null;
};
const parseReq = (c) => {
  if (c.length < 24 || !matchID(c)) return null;
  let o = 19 + c[17];
  const port = u16(c, o);
  let t = c[o + 2];
  if (t !== 1) t += 1;
  const a = parseAddr(c, o + 3, t);
  return a ? { addrType: t, ...a, port } : null;
};
const parseU = (c) =>
  matchID(c) && c[18 + c[17]] === 3 ? { dataOffset: 19 + c[17] } : null;

// ================================================================
// mkQ — Upstream Queue
// ================================================================
const mkQ = (cap, qCap = cap, itemsMax = Math.max(1, qCap >> 8)) => {
  let q = [],
    h = 0,
    qB = 0,
    buf = null;
  const trim = () => {
    h > 32 && h * 2 >= q.length && ((q = q.slice(h)), (h = 0));
  };
  return {
    get bytes() {
      return qB;
    },
    get empty() {
      return h >= q.length;
    },
    clear() {
      q = [];
      h = 0;
      qB = 0;
    },
    sow(d) {
      const n = d?.byteLength || 0;
      if (!n) return 1;
      if (qB + n > qCap || q.length - h >= itemsMax) return 0;
      q.push(d);
      qB += n;
      return 1;
    },
    take() {
      if (h >= q.length) return null;
      const d = q[h];
      q[h++] = undefined;
      qB -= d.byteLength;
      trim();
      return d;
    },
    bundle(d) {
      d ||= this.take();
      if (!d || h >= q.length || d.byteLength >= cap) return [d, 0];
      let n = d.byteLength,
        e = h;
      while (e < q.length) {
        const nn = n + q[e].byteLength;
        if (nn > cap) break;
        n = nn;
        e++;
      }
      if (e === h) return [d, 0];
      const out = (buf ||= new Uint8Array(cap));
      out.set(d);
      for (let o = d.byteLength; h < e;) {
        const x = q[h];
        q[h++] = undefined;
        qB -= x.byteLength;
        out.set(x, o);
        o += x.byteLength;
      }
      trim();
      return [out.subarray(0, n), 1];
    },
  };
};

// ================================================================
// mkDn — Downstream Batcher
// ================================================================
const mkDn = (w) => {
  const cap = CFG.dnPack,
    tail = CFG.dnTail,
    low = Math.max(4096, tail << 3),
    fastPath = CFG.fastPath;

  // ---- Double Buffer ----
  let bufs = [new Uint8Array(cap), new Uint8Array(cap)];
  let bi = 0;
  let p = 0,
    tp = 0,
    mq = 0,
    gen = 0,
    qk = 0,
    qr = 0;

  const reap = () => {
    tp && clearTimeout(tp);
    tp = 0;
    mq = 0;
    if (!p) return;
    const sendLen = p;
    const sendBuf = bufs[bi];
    bi = 1 - bi;
    p = 0;
    qr = 0;
    // ---- ZERO COPY HANDLING — view into swapped buffer ----
    safeSend(w, new Uint8Array(sendBuf.buffer, 0, sendLen));
  };

  const ripen = () => {
    if (tp || mq) return;
    mq = 1;
    qk = gen;
    queueMicrotask(() => {
      mq = 0;
      if (!p || tp) return;
      if (cap - p < tail) return reap();
      tp = setTimeout(
        () => {
          tp = 0;
          if (!p) return;
          if (cap - p < tail) return reap();
          if (qr < 2 && (gen !== qk || p < low)) {
            qr++;
            qk = gen;
            return ripen();
          }
          reap();
        },
        Math.max(CFG.dnMs, 1),
      );
    });
  };

  return {
    send(u) {
      let o = 0,
        n = u?.byteLength || 0;
      if (!n) return;
      // ---- THE FAST PATH ----
      if (!p && n >= fastPath) {
        safeSend(w, u);
        return;
      }
      while (o < n) {
        const pb = bufs[bi];
        const m = Math.min(cap - p, n - o);
        pb.set(u.subarray(o, o + m), p);
        p += m;
        o += m;
        gen++;
        if (p >= cap || cap - p < tail) reap();
        else ripen();
      }
    },
    reap,
  };
};

// ================================================================
// mill — TCP Relay
// ================================================================
const mill = async (rd, w) => {
  const r = rd.getReader({ mode: "byob" }),
    tx = mkDn(w);
  let buf = new ArrayBuffer(CFG.chunk);
  try {
    for (;;) {
      const { done, value: v } = await r.read(
        new Uint8Array(buf, 0, CFG.chunk),
      );
      if (done) break;
      if (!v?.byteLength) continue;
      // ---- THE FAST PATH ----
      if (v.byteLength >= CFG.fastPath) {
        tx.reap();
        safeSend(w, v);
        buf = new ArrayBuffer(CFG.chunk);
      } else {
        tx.send(v.slice());
        buf = v.buffer;
      }
    }
    tx.reap();
  } catch {
  } finally {
    try {
      tx.reap();
    } catch {}
    try {
      r.releaseLock();
    } catch {}
  }
};

// ================================================================
// TCP 出站
// ================================================================
const sprout = (h, p) => {
  const s = connect({ hostname: h, port: p });
  return s.opened.then(() => s);
};
const raceSprout = (h, p) => {
  if (CFG.concur <= 1) return sprout(h, p);
  const ts = Array(CFG.concur)
    .fill()
    .map(() => sprout(h, p));
  return Promise.any(ts).then((w) => {
    ts.forEach((t) =>
      t.then(
        (s) => s !== w && s.close(),
        () => {},
      ),
    );
    return w;
  });
};

// ================================================================
// STUN / Auth
// ================================================================
const MAGIC = new Uint8Array([0x21, 0x12, 0xa4, 0x42]);
const MT = {
  AQ: 0x003,
  AO: 0x103,
  AE: 0x113,
  PQ: 0x008,
  PO: 0x108,
  CQ: 0x00a,
  CO: 0x10a,
  BQ: 0x00b,
  BO: 0x10b,
  SI: 0x016,
  DI: 0x017,
};
const AT = {
  USER: 0x006,
  MI: 0x008,
  ERR: 0x009,
  PEER: 0x012,
  DATA: 0x013,
  REALM: 0x014,
  NONCE: 0x015,
  TRANSPORT: 0x019,
  CONNID: 0x02a,
};
const tid = () => crypto.getRandomValues(new Uint8Array(12));
const stunAttr = (t, v) => {
  const b = new Uint8Array(4 + v.length + pad4(v.length));
  new DataView(b.buffer).setUint16(0, t);
  new DataView(b.buffer).setUint16(2, v.length);
  b.set(v, 4);
  return b;
};
const stunMsg = (t, id, a) => {
  const bd = cat(...a),
    h = new Uint8Array(20);
  new DataView(h.buffer).setUint16(0, t);
  new DataView(h.buffer).setUint16(2, bd.length);
  h.set(MAGIC, 4);
  h.set(id, 8);
  return cat(h, bd);
};
const xorPeer = (ip, port) => {
  const b = new Uint8Array(8);
  b[1] = 1;
  new DataView(b.buffer).setUint16(2, port ^ 0x2112);
  ip.split(".").forEach((v, i) => (b[4 + i] = +v ^ MAGIC[i]));
  return b;
};

// ---- ZERO COPY HANDLING — .subarray() views, no .slice() ----
const parseStun = (d) => {
  if (d.length < 20 || MAGIC.some((v, i) => d[4 + i] !== v)) return null;
  const dv = new DataView(d.buffer, d.byteOffset, d.byteLength),
    ml = dv.getUint16(2),
    attrs = {};
  for (let o = 20; o + 4 <= 20 + ml;) {
    const t = dv.getUint16(o),
      l = dv.getUint16(o + 2);
    if (o + 4 + l > d.length) break;
    attrs[t] = d.subarray(o + 4, o + 4 + l);
    o += 4 + l + pad4(l);
  }
  return { type: dv.getUint16(0), attrs };
};

const parseErr = (d) => (d?.length >= 4 ? (d[2] & 7) * 100 + d[3] : 0);
const parseXorPeer = (d) =>
  d?.length >= 8
    ? [MAGIC.map((m, i) => d[4 + i] ^ m).join("."), u16(d, 2) ^ 0x2112]
    : ["", 0];

const addIntegrity = async (m, key) => {
  const c = new Uint8Array(m);
  new DataView(c.buffer).setUint16(2, new DataView(c.buffer).getUint16(2) + 24);
  const k = await crypto.subtle.importKey(
    "raw",
    key,
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"],
  );
  return cat(
    c,
    stunAttr(AT.MI, new Uint8Array(await crypto.subtle.sign("HMAC", k, c))),
  );
};

const readStun = async (rd, buf) => {
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
    return [parseStun(b.subarray(0, n)), b.length > n ? b.subarray(n) : null];
  } catch {
    return [null, null];
  }
};

const resolveIP = async (h) =>
  /^\d+\.\d+\.\d+\.\d+$/.test(h)
    ? h
    : ((
        await fetch(
          `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(h)}&type=A`,
          { headers: { Accept: "application/dns-json" } },
        )
          .then((r) => r.json())
          .catch(() => ({}))
      ).Answer?.find((a) => a.type === 1)?.data ?? null);
const md5 = async (s) =>
  new Uint8Array(await crypto.subtle.digest("MD5", enc(s)));

const getCreds = (url) => {
  const m = decodeURIComponent(url).match(/\/rt:\/\/([^?&#\s]*)/i);
  if (!m) return null;
  const t = m[1],
    at = t.lastIndexOf("@");
  const cred = at >= 0 ? t.slice(0, at) : "";
  const hp = t.slice(at + 1),
    [host, p] = hp.split(":");
  const ci = cred.indexOf(":");
  return p
    ? {
        host,
        port: +p,
        user: ci >= 0 ? cred.slice(0, ci) : "",
        pass: ci >= 0 ? cred.slice(ci + 1) : "",
      }
    : null;
};

const doAuth = async (w, r, transport, { tUser, tPass }, pipeline) => {
  const tp = new Uint8Array([transport, 0, 0, 0]);
  await w.write(stunMsg(MT.AQ, tid(), [stunAttr(AT.TRANSPORT, tp)]));
  let [msg, ex] = await readStun(r);
  if (!msg) return null;
  let key = null,
    aa = [];
  const sign = (m) => (key ? addIntegrity(m, key) : Promise.resolve(m));

  if (msg.type === MT.AE && tUser && parseErr(msg.attrs[AT.ERR]) === 401) {
    const realm = dec.decode(msg.attrs[AT.REALM] ?? new Uint8Array(0));
    const nonce = msg.attrs[AT.NONCE] ?? new Uint8Array(0);
    key = await md5(`${tUser}:${realm}:${tPass}`);
    aa = [
      stunAttr(AT.USER, enc(tUser)),
      stunAttr(AT.REALM, enc(realm)),
      stunAttr(AT.NONCE, nonce),
    ];
    const aq = await addIntegrity(
      stunMsg(MT.AQ, tid(), [stunAttr(AT.TRANSPORT, tp), ...aa]),
      key,
    );
    const extras = pipeline ? await Promise.all(pipeline(aa, sign)) : [];
    await w.write(extras.length ? cat(aq, ...extras) : aq);
    [msg, ex] = await readStun(r, ex);
    if (!msg) return null;
  } else if (pipeline && msg.type === MT.AO) {
    const extras = await Promise.all(pipeline(aa, sign));
    if (extras.length) await w.write(cat(...extras));
  }
  return msg.type === MT.AO ? { key, aa, ex, sign } : null;
};

// ================================================================
// tcpRelay — TCP via STUN (RFC 6062)
// ================================================================
const tcpRelay = async ({ host, port, user, pass }, tip, tport) => {
  let ctrl = null,
    data = null;
  const close = () => safeClose(ctrl, data);
  try {
    ctrl = connect({ hostname: host, port });
    await ctrl.opened;
    const cw = ctrl.writable.getWriter(),
      cr = ctrl.readable.getReader();
    const peer = stunAttr(AT.PEER, xorPeer(tip, tport));
    const auth = await doAuth(
      cw,
      cr,
      6,
      { tUser: user, tPass: pass },
      (aa, sign) => [
        sign(stunMsg(MT.PQ, tid(), [peer, ...aa])),
        sign(stunMsg(MT.CQ, tid(), [peer, ...aa])),
      ],
    );
    if (!auth) {
      close();
      return null;
    }
    const { aa, sign } = auth;
    let ex = auth.ex;
    data = connect({ hostname: host, port });
    let r;
    [r, ex] = await readStun(cr, ex);
    if (r?.type !== MT.PO) {
      close();
      return null;
    }
    [r, ex] = await readStun(cr, ex);
    if (r?.type !== MT.CO || !r.attrs[AT.CONNID]) {
      close();
      return null;
    }
    await data.opened;
    const dw = data.writable.getWriter(),
      dr = data.readable.getReader();
    await dw.write(
      await sign(
        stunMsg(MT.BQ, tid(), [stunAttr(AT.CONNID, r.attrs[AT.CONNID]), ...aa]),
      ),
    );
    let extra;
    [r, extra] = await readStun(dr);
    if (r?.type !== MT.BO) {
      close();
      return null;
    }
    cr.releaseLock();
    cw.releaseLock();
    dw.releaseLock();
    dr.releaseLock();
    return { extra, readable: data.readable, writable: data.writable, close };
  } catch {
    close();
    return null;
  }
};

// ================================================================
// Frame Codec
// ================================================================
const writeAddr = (h) => {
  const s = h.replace(/^\[|\]$/g, ""),
    m = s.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (m) return new Uint8Array([0x01, ...m.slice(1).map(Number)]);
  if (s.includes(":")) {
    const b = new Uint8Array(17);
    b[0] = 0x03;
    s.split(":").forEach((x, i) => {
      const v = parseInt(x, 16) || 0;
      b[1 + i * 2] = v >> 8;
      b[2 + i * 2] = v & 0xff;
    });
    return b;
  }
  const e = enc(h);
  return cat(new Uint8Array([0x02, e.length]), e);
};
const frameAddr = (d) => {
  if (!d.length) return ["", 0];
  if (d[0] <= 1)
    return d.length >= 5 ? [d.subarray(1, 5).join("."), 5] : ["", 0];
  if (d[0] === 2)
    return d.length >= 2 + d[1]
      ? [dec.decode(d.subarray(2, 2 + d[1])), 2 + d[1]]
      : ["", 0];
  return d[0] === 3 && d.length >= 17
    ? [
        `[${Array.from({ length: 8 }, (_, i) => u16(d, 1 + i * 2).toString(16)).join(":")}]`,
        17,
      ]
    : ["", 0];
};
const mapType = (h) => {
  const m = h.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  return m && +m[1] === 198 && [18, 19].includes(+m[2])
    ? 4
    : h.replace(/^\[|\]$/g, "").startsWith("fc") && h.includes(":")
      ? 6
      : 0;
};

// ---- ZERO COPY HANDLING — reusable frame object ----
const _frame = { network: 0, port: 0, host: "", payload: null, totalLen: 0 };
const parseFrame = (d) => {
  if (d.length < 6) return null;
  const metaLen = u16(d),
    metaEnd = 2 + metaLen;
  if (metaLen < 4 || metaEnd > d.length) return null;
  _frame.network = metaEnd > 6 ? d[6] : 0;
  _frame.port = metaEnd >= 9 ? u16(d, 7) : 0;
  _frame.host = metaEnd > 9 ? frameAddr(d.subarray(9, metaEnd))[0] : "";
  _frame.payload = null;
  _frame.totalLen = metaEnd;
  if (d[5] & 1 && metaEnd + 2 <= d.length) {
    const pLen = u16(d, metaEnd);
    if (metaEnd + 2 + pLen <= d.length) {
      // ---- ZERO COPY HANDLING — .subarray() view ----
      _frame.payload = d.subarray(metaEnd + 2, metaEnd + 2 + pLen);
      _frame.totalLen = metaEnd + 2 + pLen;
    }
  }
  return _frame;
};

// ---- Reusable header staging buffer ----
const _frameHdr = new Uint8Array(32);
const frameResp = (host, port, payload, directSend) => {
  const a = writeAddr(host),
    ml = 7 + a.length;
  const hdrLen = 2 + ml + 2;
  if (hdrLen > _frameHdr.length) return _frameRespFresh(host, port, payload);

  // ---- THE FAST PATH — two-part send for large payloads ----
  if (payload.byteLength >= CFG.fastPath && directSend) {
    _frameHdr[0] = ml >> 8;
    _frameHdr[1] = ml & 0xff;
    _frameHdr[4] = 2;
    _frameHdr[5] = 1;
    _frameHdr[6] = 2;
    _frameHdr[7] = port >> 8;
    _frameHdr[8] = port & 0xff;
    _frameHdr.set(a, 9);
    const pOff = 2 + ml;
    _frameHdr[pOff] = payload.length >> 8;
    _frameHdr[pOff + 1] = payload.length & 0xff;
    directSend(new Uint8Array(_frameHdr.buffer, 0, hdrLen));
    directSend(payload);
    return null;
  }
  return _frameRespFresh(host, port, payload);
};
const _frameRespFresh = (host, port, payload) => {
  const a = writeAddr(host),
    ml = 7 + a.length,
    buf = new Uint8Array(2 + ml + 2 + payload.length);
  [buf[0], buf[1], buf[4], buf[5], buf[6], buf[7], buf[8]] = [
    ml >> 8,
    ml & 0xff,
    2,
    1,
    2,
    port >> 8,
    port & 0xff,
  ];
  buf.set(a, 9);
  const pOff = 2 + ml;
  [buf[pOff], buf[pOff + 1]] = [payload.length >> 8, payload.length & 0xff];
  buf.set(payload, pOff + 2);
  return buf;
};

// ================================================================
// udpRelay — UDP via STUN with backpressure
// ================================================================
const udpRelay = async ({ host, port, user, pass }, sendWs) => {
  let sock = null,
    closed = false;
  const perms = new Set(),
    sess = new Map(),
    reverse = {};

  // ---- CONGESTION-AWARE BACKPRESSURE DROP ----
  let inFlight = 0;

  let writeChain = Promise.resolve();
  const writeSerial = (data) => {
    const p = writeChain.then(
      () => (closed ? Promise.resolve() : w.write(data)),
      () => {},
    );
    writeChain = p;
    return p;
  };
  let w, r;

  const close = () => {
    if (closed) return;
    closed = true;
    safeClose(sock);
  };

  try {
    sock = connect({ hostname: host, port });
    await sock.opened;
    w = sock.writable.getWriter();
    r = sock.readable.getReader();
    const auth = await doAuth(w, r, 17, { tUser: user, tPass: pass });
    if (!auth) {
      close();
      return null;
    }
    const { aa, sign } = auth;
    let buf = auth.ex;

    (async () => {
      while (!closed) {
        const [m, nx] = await readStun(r, buf);
        buf = nx;
        if (!m) break;
        if (m.type === MT.DI && m.attrs[AT.PEER] && m.attrs[AT.DATA]) {
          const [ip, pt] = parseXorPeer(m.attrs[AT.PEER]),
            s = reverse[`${ip}:${pt}`];
          const dataPayload = m.attrs[AT.DATA];
          const dataLen = dataPayload.byteLength;

          // ---- CONGESTION-AWARE BACKPRESSURE DROP ----
          if (inFlight > CFG.backLogLimit) continue;

          inFlight += dataLen;
          const decN = dataLen;
          setTimeout(() => {
            inFlight -= decN;
          }, 50);

          // ---- THE FAST PATH — two-part send ----
          const resp = frameResp(
            s?.host ?? ip,
            s?.port ?? pt,
            dataPayload,
            (part) => {
              safeSend(sendWs._ws, part);
            },
          );
          if (resp) sendWs(resp);
        }
      }
      if (!closed) close();
    })();

    const ensurePerm = async (ip) => {
      if (perms.has(ip)) return;
      perms.add(ip);
      const msg = await sign(
        stunMsg(MT.PQ, tid(), [stunAttr(AT.PEER, xorPeer(ip, 0)), ...aa]),
      );
      writeSerial(msg);
    };

    const sendPkt = (ip, port, data) => {
      writeSerial(
        stunMsg(MT.SI, tid(), [
          stunAttr(AT.PEER, xorPeer(ip, port)),
          stunAttr(AT.DATA, data),
        ]),
      );
    };

    const getIP = (h, p) => {
      const k = `${h}:${p}`,
        c = sess.get(k);
      if (c) return c.ip;
      const ft = mapType(h);
      if (ft)
        for (const s of sess.values())
          if (s.port === p && s.isV6 === (ft === 6)) {
            const ns = { ip: s.ip, host: h, port: p, isV6: s.isV6 };
            sess.set(k, ns);
            reverse[`${s.ip}:${p}`] = ns;
            return s.ip;
          }
      return null;
    };

    const processData = async (data) => {
      while (data.length >= 6) {
        const f = parseFrame(data);
        if (!f) break;
        if (f.network === 2 && f.payload?.length && f.host) {
          const k = `${f.host}:${f.port}`;
          let ip = getIP(f.host, f.port);
          if (ip) {
            await ensurePerm(ip);
            sendPkt(ip, f.port, f.payload);
          } else if (sess.has(k)) {
            // resolve in progress, skip
          } else {
            sess.set(k, { ip: null, host: f.host, port: f.port, isV6: false });
            const resolvedIp = await resolveIP(f.host);
            if (!resolvedIp || closed) {
              sess.delete(k);
            } else {
              const isV6 = resolvedIp.includes(":");
              const s = { ip: resolvedIp, host: f.host, port: f.port, isV6 };
              sess.set(k, s);
              reverse[`${resolvedIp}:${f.port}`] = s;
              await ensurePerm(resolvedIp);
              sendPkt(resolvedIp, f.port, f.payload);
            }
          }
        }
        // ---- ZERO COPY HANDLING — .subarray() sliding window ----
        data = data.subarray(f.totalLen);
      }
    };

    return { processData, close };
  } catch (e) {
    close();
    return null;
  }
};

// ================================================================
// Worker 入口
// ================================================================
export default {
  async fetch(req, env) {
    if (req.headers.get("Upgrade")?.toLowerCase() !== "websocket")
      return new Response("ok");
    try {
      if (!env.XXPRO_DO)
        return new Response("XXPRO_DO missing", { status: 500 });
      const id = env.XXPRO_DO.newUniqueId();
      return await env.XXPRO_DO.get(id).fetch(req);
    } catch (e) {
      return new Response("Worker error: " + e.message, { status: 500 });
    }
  },
};

// ================================================================
// Durable Object
// ================================================================
export class XxProDO extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
  }

  async fetch(request) {
    try {
      if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket")
        return new Response("Expected WebSocket", { status: 426 });

      const [client, server] = Object.values(new WebSocketPair());
      server.binaryType = "arraybuffer";
      server.accept({ allowHalfOpen: true });

      const creds = getCreds(request.url);
      const edStr = request.headers.get("sec-websocket-protocol");
      const uq = mkQ(CFG.upPack, CFG.upQMax, CFG.upQMax >> 8);
      const dnTx = mkDn(server);

      let curW = null,
        sock = null,
        con = null,
        udp = null,
        closed = false,
        busy = false;

      const wither = () => {
        if (closed) return;
        closed = true;
        uq.clear();
        try {
          dnTx.reap();
        } catch {}
        udp?.close();
        con?.close();
        try {
          curW?.releaseLock();
        } catch {}
        safeClose(sock, server);
      };

      const sow = (d) => {
        const u = toU8(d),
          n = u.byteLength;
        if (!n) return 1;
        if (uq.sow(u)) return 1;
        wither();
        return 0;
      };

      const sendWsFn = (c) => {
        safeSend(server, c);
      };
      sendWsFn._ws = server;

      const thresh = async () => {
        if (busy || closed) return;
        busy = true;
        try {
          for (;;) {
            if (closed) break;

            // TCP 持續傳輸
            if (curW) {
              // ---- CONGESTION-AWARE BACKPRESSURE ----
              const ds = curW.desiredSize;
              if (ds !== null && ds <= 0) break;

              const [d] = uq.bundle();
              if (!d) break;
              await curW.write(d);
              continue;
            }

            // UDP 持續傳輸
            if (udp) {
              const [d] = uq.bundle();
              if (!d) break;
              await udp.processData(d);
              continue;
            }

            // 新連接解析
            const [d] = uq.bundle();
            if (!d) break;

            const u = parseU(d);
            if (u && creds) {
              udp = await udpRelay(creds, sendWsFn);
              if (!udp) return wither();
              safeSend(server, new Uint8Array([d[0], 0]));
              const ud = d.subarray(u.dataOffset);
              if (ud.length) await udp.processData(ud);
              continue;
            }

            const r = parseReq(d);
            if (!r) return wither();
            safeSend(server, new Uint8Array([d[0], 0]));

            const host = addr(r.addrType, r.addrBytes),
              payload = d.subarray(r.dataOffset);

            if (creds) {
              const ip = r.addrType === 1 ? host : await resolveIP(host);
              if (!ip) return wither();
              con = await tcpRelay(creds, ip, r.port).catch(() => null);
              if (!con) return wither();
              curW = con.writable.getWriter();
              const [first] = uq.bundle(payload);
              if (first?.byteLength) await curW.write(first);
              // ---- ZERO COPY HANDLING ----
              if (con.extra?.byteLength) {
                try {
                  server.send(con.extra);
                } catch {
                  return wither();
                }
              }
              mill(con.readable, server).finally(() => wither());
              continue;
            }

            sock = await raceSprout(host, r.port);
            if (!sock) return wither();
            curW = sock.writable.getWriter();
            const [first] = uq.bundle(payload);
            if (first?.byteLength) await curW.write(first);
            mill(sock.readable, server).finally(() => wither());
          }
        } catch {
          wither();
        } finally {
          busy = false;
          if (!uq.empty && !closed) queueMicrotask(thresh);
        }
      };

      if (edStr && edStr.length <= (CFG.maxED * 4) / 3 + 4) {
        try {
          const ed = Uint8Array.fromBase64(edStr, { alphabet: "base64url" });
          if (ed?.byteLength && sow(ed)) thresh();
        } catch {}
      }

      server.addEventListener("message", (e) => {
        if (closed) return;
        sow(e.data) && thresh();
      });
      server.addEventListener("close", wither);
      server.addEventListener("error", wither);

      return new Response(null, {
        status: 101,
        webSocket: client,
        headers: edStr ? { "sec-websocket-protocol": edStr } : {},
      });
    } catch (e) {
      return new Response("DO error: " + e.message, { status: 500 });
    }
  }
}
