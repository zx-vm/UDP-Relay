#!/usr/bin/env node
'use strict';

const net = require('node:net');
const dgram = require('node:dgram');
const dns = require('node:dns').promises;
const http = require('node:http');

const CONFIG = Object.freeze({
    LISTEN_HOST: '0.0.0.0',
    LISTEN_PORT: 8080,
    HANDSHAKE_TIMEOUT_MS: 10000,
    IDLE_TIMEOUT_MS: 300000,
    XUDP_GRACE_MS: 60000,
    MAX_CONNECTIONS: 4096,
    REJECT_UDP_443: true,
});

const RELAY_MAGIC = Buffer.from('VLRLY004', 'ascii');
const RELAY_MODE_FIXED_UDP = 0x01;
const RELAY_MODE_MUX = 0x02;
const RELAY_MODE_PACKET_UDP = 0x03;
const ATYP_IPV4 = 0x01;
const ATYP_DOMAIN = 0x02;
const ATYP_IPV6 = 0x03;
const MUX_STATUS_NEW = 0x01;
const MUX_STATUS_KEEP = 0x02;
const MUX_STATUS_END = 0x03;
const MUX_STATUS_KEEPALIVE = 0x04;
const MUX_OPTION_DATA = 0x01;
const MUX_OPTION_ERROR = 0x02;
const MUX_NETWORK_UDP = 0x02;
const MAX_MUX_META_LEN = 512;
const MAX_PACKET_LEN = 65535;
const utf8Fatal = new TextDecoder('utf-8', { fatal: true });

const START_TIME = Date.now();
const stats = {
    totalConnections: 0,
    activeConnections: 0,
    rejectedConnections: 0,
    modeCounts: { fixedUdp: 0, mux: 0, packetUdp: 0 },
    activeUdpAssociations: 0,
    totalUdpAssociations: 0,
    activeMuxConnections: 0,
    activeXudpSessions: 0,
    totalXudpSessions: 0,
    udpBytesSent: 0,
    udpBytesReceived: 0,
    udpPacketsSent: 0,
    udpPacketsReceived: 0,
    rejectedUdp443: 0,
    errors: 0,
};

const MAX_LOG_ENTRIES = 300;
const logBuffer = [];
function log(level, message, meta) {
    const entry = { ts: Date.now(), level, message, meta: meta === undefined ? null : meta };
    logBuffer.push(entry);
    if (logBuffer.length > MAX_LOG_ENTRIES) logBuffer.shift();
    const line = `[${new Date(entry.ts).toISOString()}] ${level.toUpperCase()} ${message}`;
    if (level === 'error') console.error(line, meta !== undefined ? meta : '');
    else if (level === 'warn') console.warn(line, meta !== undefined ? meta : '');
    else console.log(line, meta !== undefined ? meta : '');
}

function statsSnapshot() {
    return {
        uptimeMs: Date.now() - START_TIME,
        startedAt: new Date(START_TIME).toISOString(),
        listen: `${CONFIG.LISTEN_HOST}:${CONFIG.LISTEN_PORT}`,
        config: {
            maxConnections: CONFIG.MAX_CONNECTIONS,
            handshakeTimeoutMs: CONFIG.HANDSHAKE_TIMEOUT_MS,
            idleTimeoutMs: CONFIG.IDLE_TIMEOUT_MS,
            xudpGraceMs: CONFIG.XUDP_GRACE_MS,
            rejectUdp443: CONFIG.REJECT_UDP_443,
        },
        ...stats,
    };
}

function rejectUdpTarget(target) {
    return Boolean(CONFIG.REJECT_UDP_443 && Number(target?.port) === 443);
}

function buildConfig(overrides = {}) {
    const cfg = {
        listenAddress: { host: CONFIG.LISTEN_HOST, port: CONFIG.LISTEN_PORT },
        handshakeTimeout: CONFIG.HANDSHAKE_TIMEOUT_MS,
        idleTimeout: CONFIG.IDLE_TIMEOUT_MS,
        xudpGrace: CONFIG.XUDP_GRACE_MS,
        maxConns: CONFIG.MAX_CONNECTIONS,
        ...overrides,
    };
    if (!cfg.listenAddress || !Number.isInteger(cfg.listenAddress.port) || cfg.listenAddress.port < 0 || cfg.listenAddress.port > 65535) {
        throw new Error('invalid listen address');
    }
    if (!Number.isInteger(cfg.maxConns) || cfg.maxConns < 1) {
        throw new Error('MAX_CONNECTIONS must be >= 1');
    }
    return cfg;
}

class AsyncByteReader {
    constructor(socket) {
        this.socket = socket;
        this.buffers = [];
        this.available = 0;
        this.waiters = [];
        this.ended = false;
        this.error = null;
        socket.on('data', (chunk) => {
            if (!chunk || chunk.length === 0) return;
            this.buffers.push(Buffer.from(chunk));
            this.available += chunk.length;
            this._flush();
        });
        socket.on('end', () => { this.ended = true; this._flush(); });
        socket.on('close', () => { this.ended = true; this._flush(); });
        socket.on('error', (err) => { this.error = err; this._flush(); });
    }
    readExactly(length) {
        if (!Number.isInteger(length) || length < 0) {
            return Promise.reject(new Error('invalid read length'));
        }
        if (length === 0) return Promise.resolve(Buffer.alloc(0));
        if (this.available >= length) return Promise.resolve(this._take(length));
        if (this.error) return Promise.reject(this.error);
        if (this.ended) return Promise.reject(new Error('unexpected EOF'));
        return new Promise((resolve, reject) => {
            this.waiters.push({ length, resolve, reject });
        });
    }
    _flush() {
        while (this.waiters.length > 0) {
            const waiter = this.waiters[0];
            if (this.available >= waiter.length) {
                this.waiters.shift();
                waiter.resolve(this._take(waiter.length));
                continue;
            }
            if (this.error || this.ended) {
                this.waiters.shift();
                waiter.reject(this.error || new Error('unexpected EOF'));
                continue;
            }
            break;
        }
    }
    _take(length) {
        const out = Buffer.allocUnsafe(length);
        let offset = 0;
        while (offset < length) {
            const first = this.buffers[0];
            const need = length - offset;
            if (first.length <= need) {
                first.copy(out, offset);
                offset += first.length;
                this.buffers.shift();
            } else {
                first.copy(out, offset, 0, need);
                this.buffers[0] = first.subarray(need);
                offset += need;
            }
        }
        this.available -= length;
        return out;
    }
}

async function readLengthPayload(reader) {
    const lenBuf = await reader.readExactly(2);
    const length = lenBuf.readUInt16BE(0);
    return length === 0 ? Buffer.alloc(0) : reader.readExactly(length);
}

async function readEndpoint(reader) {
    const head = await reader.readExactly(3);
    const port = head.readUInt16BE(0);
    const atyp = head[2];
    if (port === 0) throw new Error('zero port');
    return readEndpointBody(reader, atyp, port);
}

async function readEndpointBody(reader, atyp, port) {
    if (atyp === ATYP_IPV4) {
        const b = await reader.readExactly(4);
        return { host: `${b[0]}.${b[1]}.${b[2]}.${b[3]}`, port, atyp };
    }
    if (atyp === ATYP_DOMAIN) {
        const len = (await reader.readExactly(1))[0];
        if (len === 0) throw new Error('empty domain');
        const b = await reader.readExactly(len);
        let host;
        try { host = utf8Fatal.decode(b); } catch { throw new Error('invalid UTF-8 domain'); }
        if (!host) throw new Error('empty domain');
        return { host, port, atyp };
    }
    if (atyp === ATYP_IPV6) {
        const b = await reader.readExactly(16);
        return { host: formatIPv6(b), port, atyp };
    }
    throw new Error(`unknown address type ${atyp}`);
}

function parseEndpointBytes(buffer, offset) {
    if (offset < 0 || buffer.length - offset < 3) throw new Error('unexpected EOF in endpoint');
    const port = buffer.readUInt16BE(offset);
    if (port === 0) throw new Error('zero port');
    const atyp = buffer[offset + 2];
    let cursor = offset + 3;
    if (atyp === ATYP_IPV4) {
        if (buffer.length - cursor < 4) throw new Error('unexpected EOF in IPv4');
        const b = buffer.subarray(cursor, cursor + 4);
        cursor += 4;
        return { endpoint: { host: `${b[0]}.${b[1]}.${b[2]}.${b[3]}`, port, atyp }, next: cursor };
    }
    if (atyp === ATYP_DOMAIN) {
        if (buffer.length - cursor < 1) throw new Error('unexpected EOF in domain length');
        const len = buffer[cursor++];
        if (len === 0 || buffer.length - cursor < len) throw new Error('invalid domain length');
        let host;
        try { host = utf8Fatal.decode(buffer.subarray(cursor, cursor + len)); } catch { throw new Error('invalid UTF-8 domain'); }
        cursor += len;
        return { endpoint: { host, port, atyp }, next: cursor };
    }
    if (atyp === ATYP_IPV6) {
        if (buffer.length - cursor < 16) throw new Error('unexpected EOF in IPv6');
        const host = formatIPv6(buffer.subarray(cursor, cursor + 16));
        cursor += 16;
        return { endpoint: { host, port, atyp }, next: cursor };
    }
    throw new Error(`unknown address type ${atyp}`);
}

function formatIPv6(bytes) {
    const parts = [];
    for (let i = 0; i < 16; i += 2) parts.push(bytes.readUInt16BE(i).toString(16));
    return parts.join(':');
}

function ipv6ToBytes(address) {
    let input = address;
    const zone = input.indexOf('%');
    if (zone >= 0) input = input.slice(0, zone);
    let ipv4Tail = null;
    const lastColon = input.lastIndexOf(':');
    if (input.includes('.') && lastColon >= 0) {
        const ipv4 = input.slice(lastColon + 1).split('.').map(Number);
        if (ipv4.length !== 4 || ipv4.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) {
            throw new Error(`invalid IPv6 address: ${address}`);
        }
        ipv4Tail = [((ipv4[0] << 8) | ipv4[1]).toString(16), ((ipv4[2] << 8) | ipv4[3]).toString(16)];
        input = input.slice(0, lastColon) + ':' + ipv4Tail.join(':');
    }
    const halves = input.split('::');
    if (halves.length > 2) throw new Error(`invalid IPv6 address: ${address}`);
    const left = halves[0] ? halves[0].split(':').filter(Boolean) : [];
    const right = halves.length === 2 && halves[1] ? halves[1].split(':').filter(Boolean) : [];
    const missing = 8 - left.length - right.length;
    if ((halves.length === 1 && missing !== 0) || (halves.length === 2 && missing < 1)) {
        throw new Error(`invalid IPv6 address: ${address}`);
    }
    const words = [...left, ...Array(Math.max(0, missing)).fill('0'), ...right];
    if (words.length !== 8) throw new Error(`invalid IPv6 address: ${address}`);
    const out = Buffer.alloc(16);
    words.forEach((word, i) => {
        if (!/^[0-9a-f]{1,4}$/i.test(word)) throw new Error(`invalid IPv6 address: ${address}`);
        out.writeUInt16BE(parseInt(word, 16), i * 2);
    });
    return out;
}

function encodeUDPSource(rinfo) {
    const port = Number(rinfo.port);
    if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('invalid UDP source port');
    const family = net.isIP(rinfo.address);
    const head = Buffer.alloc(3);
    head.writeUInt16BE(port, 0);
    if (family === 4) {
        head[2] = ATYP_IPV4;
        return Buffer.concat([head, Buffer.from(rinfo.address.split('.').map(Number))]);
    }
    if (family === 6) {
        head[2] = ATYP_IPV6;
        return Buffer.concat([head, ipv6ToBytes(rinfo.address)]);
    }
    throw new Error(`invalid UDP source IP: ${rinfo.address}`);
}

function writeSocket(socket, data) {
    if (socket.destroyed || !socket.writable) return Promise.reject(new Error('socket is closed'));
    return new Promise((resolve, reject) => {
        socket.write(data, (err) => err ? reject(err) : resolve());
    });
}

async function writeControlError(socket, message) {
    let body = Buffer.from(String(message || 'relay error'), 'utf8');
    if (body.length > MAX_PACKET_LEN) body = body.subarray(0, MAX_PACKET_LEN);
    const out = Buffer.allocUnsafe(3 + body.length);
    out[0] = 1;
    out.writeUInt16BE(body.length, 1);
    body.copy(out, 3);
    try { await writeSocket(socket, out); } catch {}
}

async function readControl(reader) {
    const magic = await reader.readExactly(RELAY_MAGIC.length);
    if (!magic.equals(RELAY_MAGIC)) throw new Error('bad magic');
    const mode = (await reader.readExactly(1))[0];
    if (![RELAY_MODE_FIXED_UDP, RELAY_MODE_MUX, RELAY_MODE_PACKET_UDP].includes(mode)) {
        throw new Error('bad mode');
    }
    const target = mode === RELAY_MODE_FIXED_UDP ? await readEndpoint(reader) : null;
    return { mode, target };
}

async function resolveTarget(target) {
    if (target.atyp === ATYP_IPV4) return { address: target.host, family: 4 };
    if (target.atyp === ATYP_IPV6) return { address: target.host, family: 6 };
    const records = await dns.lookup(target.host, { all: true, verbatim: true });
    if (!records.length) throw new Error(`DNS returned no address for ${target.host}`);
    const preferred = records.find((r) => r.family === 4) || records.find((r) => r.family === 6);
    if (!preferred) throw new Error(`DNS returned unsupported address for ${target.host}`);
    return preferred;
}

function bindDgram(socket, port, address) {
    return new Promise((resolve, reject) => {
        const onError = (err) => { cleanup(); reject(err); };
        const onListening = () => { cleanup(); resolve(); };
        const cleanup = () => { socket.off('error', onError); socket.off('listening', onListening); };
        socket.once('error', onError);
        socket.once('listening', onListening);
        socket.bind(port, address);
    });
}

class UDPAssociation {
    constructor() {
        this.udp4 = null;
        this.udp6 = null;
        this.port = 0;
        this.sink = null;
        this.closed = false;
    }
    static async create() {
        const assoc = new UDPAssociation();
        assoc.udp4 = dgram.createSocket({ type: 'udp4', reuseAddr: true });
        await bindDgram(assoc.udp4, 0, '0.0.0.0');
        assoc.port = assoc.udp4.address().port;
        assoc.udp4.on('message', (msg, rinfo) => assoc._onMessage(msg, rinfo));
        assoc.udp4.on('error', () => {});
        assoc.udp6 = dgram.createSocket({ type: 'udp6', reuseAddr: true, ipv6Only: true });
        try {
            await bindDgram(assoc.udp6, assoc.port, '::');
            assoc.udp6.on('message', (msg, rinfo) => assoc._onMessage(msg, rinfo));
            assoc.udp6.on('error', () => {});
        } catch {
            try { assoc.udp6.close(); } catch {}
            assoc.udp6 = null;
        }
        stats.activeUdpAssociations++;
        stats.totalUdpAssociations++;
        return assoc;
    }
    attach(sink) {
        const old = this.sink;
        this.sink = sink;
        return old;
    }
    detach(mux, id) {
        if (this.sink && this.sink.mux === mux && this.sink.id === id) {
            this.sink = null;
            return true;
        }
        return false;
    }
    async send(target, payload) {
        if (this.closed) throw new Error('UDP association is closed');
        if (payload.length > MAX_PACKET_LEN) throw new Error(`UDP payload too large: ${payload.length}`);
        const resolved = await resolveTarget(target);
        const socket = resolved.family === 6 ? this.udp6 : this.udp4;
        if (!socket) throw new Error(`UDP IPv${resolved.family} is unavailable on this host`);
        await new Promise((resolve, reject) => {
            socket.send(payload, target.port, resolved.address, (err) => err ? reject(err) : resolve());
        });
        stats.udpBytesSent += payload.length;
        stats.udpPacketsSent++;
    }
    _onMessage(msg, rinfo) {
        const sink = this.sink;
        if (!sink || this.closed) return;
        stats.udpBytesReceived += msg.length;
        stats.udpPacketsReceived++;
        Promise.resolve(sink.mux.sendUDPData(sink.id, rinfo, Buffer.from(msg))).catch(() => {
        });
    }
    close() {
        if (this.closed) return;
        this.closed = true;
        this.sink = null;
        stats.activeUdpAssociations--;
        if (this.udp4) { try { this.udp4.close(); } catch {} }
        if (this.udp6) { try { this.udp6.close(); } catch {} }
        this.udp4 = null;
        this.udp6 = null;
    }
}

class XUDPManager {
    constructor(graceMs) {
        this.graceMs = graceMs;
        this.entries = new Map();
    }
    async attach(globalID, mux, sessionID) {
        const key = Buffer.from(globalID).toString('hex');
        let entry = this.entries.get(key);
        if (!entry) {
            entry = { assoc: await UDPAssociation.create(), timer: null };
            this.entries.set(key, entry);
        }
        if (entry.timer) {
            clearTimeout(entry.timer);
            entry.timer = null;
        }
        const oldSink = entry.assoc.attach({ mux, id: sessionID });
        return { assoc: entry.assoc, oldSink };
    }
    detach(globalID, mux, sessionID) {
        const key = Buffer.from(globalID).toString('hex');
        const entry = this.entries.get(key);
        if (!entry || !entry.assoc.detach(mux, sessionID)) return;
        if (entry.timer) clearTimeout(entry.timer);
        entry.timer = setTimeout(() => {
            const current = this.entries.get(key);
            if (current !== entry) return;
            this.entries.delete(key);
            entry.assoc.close();
        }, this.graceMs);
        entry.timer.unref?.();
    }
    close() {
        for (const entry of this.entries.values()) {
            if (entry.timer) clearTimeout(entry.timer);
            entry.assoc.close();
        }
        this.entries.clear();
    }
}

async function serveDirectUDP(socket, reader, target) {
    if (rejectUdpTarget(target)) {
        stats.rejectedUdp443++;
        await writeControlError(socket, 'UDP/443 rejected');
        return;
    }
    const assoc = await UDPAssociation.create();
    let closed = false;
    assoc.attach({
        mux: {
            sendUDPData: async (_id, _rinfo, data) => {
                if (closed || socket.destroyed) return;
                if (data.length > MAX_PACKET_LEN) return;
                const frame = Buffer.allocUnsafe(2 + data.length);
                frame.writeUInt16BE(data.length, 0);
                data.copy(frame, 2);
                await writeSocket(socket, frame);
            },
        },
        id: 0,
    });
    try {
        await writeSocket(socket, Buffer.from([0]));
        for (;;) {
            const payload = await readLengthPayload(reader);
            if (payload.length === 0) continue;
            if (rejectUdpTarget(target)) { stats.rejectedUdp443++; continue; }
            await assoc.send(target, payload);
        }
    } finally {
        closed = true;
        assoc.close();
    }
}

async function servePacketUDP(socket, reader) {
    const assoc = await UDPAssociation.create();
    let closed = false;
    const writeChain = { value: Promise.resolve() };
    assoc.attach({
        mux: {
            sendUDPData: (_id, rinfo, data) => {
                if (closed || socket.destroyed || data.length > MAX_PACKET_LEN) return Promise.resolve();
                const endpoint = encodeUDPSource(rinfo);
                const len = Buffer.allocUnsafe(2);
                len.writeUInt16BE(data.length, 0);
                const frame = Buffer.concat([endpoint, len, data]);
                const op = writeChain.value.then(() => writeSocket(socket, frame));
                writeChain.value = op.catch(() => {});
                return op;
            },
        },
        id: 0,
    });
    try {
        await writeSocket(socket, Buffer.from([0]));
        for (;;) {
            const target = await readEndpoint(reader);
            const payload = await readLengthPayload(reader);
            if (payload.length === 0) continue;
            if (rejectUdpTarget(target)) { stats.rejectedUdp443++; continue; }
            await assoc.send(target, payload);
        }
    } finally {
        closed = true;
        assoc.close();
    }
}

async function readMuxFrame(reader) {
    const metaLen = (await reader.readExactly(2)).readUInt16BE(0);
    if (metaLen < 4 || metaLen > MAX_MUX_META_LEN) {
        throw new Error(`invalid mux metadata length ${metaLen}`);
    }
    const meta = await reader.readExactly(metaLen);
    const frame = {
        id: meta.readUInt16BE(0),
        status: meta[2],
        option: meta[3],
        network: 0,
        target: null,
        globalID: null,
        data: Buffer.alloc(0),
    };
    let cursor = 4;
    if (frame.status === MUX_STATUS_NEW) {
        if (cursor >= meta.length) throw new Error('mux New missing network');
        frame.network = meta[cursor++];
        const parsed = parseEndpointBytes(meta, cursor);
        frame.target = parsed.endpoint;
        cursor = parsed.next;
        if (frame.network === MUX_NETWORK_UDP && meta.length - cursor >= 8) {
            const gid = meta.subarray(cursor, cursor + 8);
            if (!gid.equals(Buffer.alloc(8))) frame.globalID = Buffer.from(gid);
            cursor += 8;
        }
        if (cursor !== meta.length) {
            throw new Error(`unexpected ${meta.length - cursor} byte(s) in mux New metadata`);
        }
    } else if (frame.status === MUX_STATUS_KEEP && meta.length > cursor && meta[cursor] === MUX_NETWORK_UDP) {
        frame.network = meta[cursor++];
        frame.target = parseEndpointBytes(meta, cursor).endpoint;
    }
    if ((frame.option & MUX_OPTION_DATA) !== 0) {
        frame.data = await readLengthPayload(reader);
    }
    return frame;
}

class MuxSession {
    constructor(mux, id, network, target) {
        this.mux = mux;
        this.id = id;
        this.network = network;
        this.target = target;
        this.udp = null;
        this.global = false;
        this.gid = null;
        this.closed = false;
        stats.activeXudpSessions++;
        stats.totalXudpSessions++;
    }
    async sendUDP(target, payload) {
        if (!this.udp) throw new Error('UDP session is unavailable');
        await this.udp.send(target, payload);
    }
    closeWithoutRemoving() {
        if (this.closed) return;
        this.closed = true;
        stats.activeXudpSessions--;
        if (this.udp) {
            if (this.global) {
                this.mux.xm.detach(this.gid, this.mux, this.id);
            } else {
                this.udp.detach(this.mux, this.id);
                this.udp.close();
            }
            this.udp = null;
        }
    }
    async close(sendEnd) {
        if (this.mux.sessions.get(this.id) === this) this.mux.sessions.delete(this.id);
        this.closeWithoutRemoving();
        if (sendEnd) await this.mux.sendEnd(this.id, true).catch(() => {});
    }
}

class MuxConnection {
    constructor(socket, reader, cfg, xm) {
        this.socket = socket;
        this.reader = reader;
        this.cfg = cfg;
        this.xm = xm;
        this.sessions = new Map();
        this.closed = false;
        this.writeChain = Promise.resolve();
        stats.activeMuxConnections++;
    }
    async serve() {
        try {
            await writeSocket(this.socket, Buffer.from([0]));
            for (;;) {
                const frame = await readMuxFrame(this.reader);
                await this.handleFrame(frame);
            }
        } finally {
            this.closeAll();
        }
    }
    async handleFrame(frame) {
        if (frame.status === MUX_STATUS_KEEPALIVE) return;
        if (frame.status === MUX_STATUS_NEW) return this.handleNew(frame);
        if (frame.status === MUX_STATUS_KEEP) return this.handleKeep(frame);
        if (frame.status === MUX_STATUS_END) {
            const session = this.sessions.get(frame.id);
            if (session && frame.data.length) {
                await session.sendUDP(session.target, frame.data).catch(() => {});
            }
            this.removeSession(frame.id);
            return;
        }
        throw new Error(`unknown mux status 0x${frame.status.toString(16).padStart(2, '0')}`);
    }
    async handleNew(frame) {
        if (frame.network !== MUX_NETWORK_UDP || !frame.target?.host || !frame.target?.port || rejectUdpTarget(frame.target)) {
            if (frame.network === MUX_NETWORK_UDP && rejectUdpTarget(frame.target)) stats.rejectedUdp443++;
            await this.sendEnd(frame.id, true).catch(() => {});
            return;
        }
        this.removeSession(frame.id);
        const session = new MuxSession(this, frame.id, frame.network, frame.target);
        if (frame.globalID) {
            try {
                const { assoc, oldSink } = await this.xm.attach(frame.globalID, this, frame.id);
                session.udp = assoc;
                session.global = true;
                session.gid = Buffer.from(frame.globalID);
                this.sessions.set(session.id, session);
                if (oldSink && (oldSink.mux !== this || oldSink.id !== frame.id)) {
                    oldSink.mux.removeSession(oldSink.id);
                    await oldSink.mux.sendEnd(oldSink.id, false).catch(() => {});
                }
            } catch {
                await this.sendEnd(frame.id, true).catch(() => {});
                return;
            }
        } else {
            try {
                const assoc = await UDPAssociation.create();
                assoc.attach({ mux: this, id: frame.id });
                session.udp = assoc;
                this.sessions.set(session.id, session);
            } catch {
                await this.sendEnd(frame.id, true).catch(() => {});
                return;
            }
        }
        if (frame.data.length) {
            await session.sendUDP(frame.target, frame.data).catch(() => session.close(true));
        }
    }
    async handleKeep(frame) {
        const session = this.sessions.get(frame.id);
        if (!session) { await this.sendEnd(frame.id, false).catch(() => {}); return; }
        if (!frame.data.length) return;
        let target = session.target;
        if (frame.network === MUX_NETWORK_UDP && frame.target?.host && frame.target?.port) {
            target = frame.target;
            session.target = target;
        }
        if (rejectUdpTarget(target)) { stats.rejectedUdp443++; await session.close(true); return; }
        await session.sendUDP(target, frame.data).catch(() => session.close(true));
    }
    removeSession(id) {
        const session = this.sessions.get(id);
        if (!session) return;
        this.sessions.delete(id);
        session.closeWithoutRemoving();
    }
    closeAll() {
        if (this.closed) return;
        this.closed = true;
        stats.activeMuxConnections--;
        const sessions = [...this.sessions.values()];
        this.sessions.clear();
        for (const session of sessions) session.closeWithoutRemoving();
    }
    _queueWrite(data) {
        const op = this.writeChain.then(() => writeSocket(this.socket, data));
        this.writeChain = op.catch(() => {});
        return op;
    }
    sendUDPData(id, source, data) {
        const addr = encodeUDPSource(source);
        const meta = Buffer.allocUnsafe(5 + addr.length);
        meta.writeUInt16BE(id, 0);
        meta[2] = MUX_STATUS_KEEP;
        meta[3] = MUX_OPTION_DATA;
        meta[4] = MUX_NETWORK_UDP;
        addr.copy(meta, 5);
        return this.writeMuxPacket(meta, data);
    }
    sendEnd(id, hasError) {
        const meta = Buffer.alloc(4);
        meta.writeUInt16BE(id, 0);
        meta[2] = MUX_STATUS_END;
        meta[3] = hasError ? MUX_OPTION_ERROR : 0;
        return this.writeMuxMeta(meta);
    }
    writeMuxPacket(meta, data) {
        if (data.length > MAX_PACKET_LEN) return Promise.reject(new Error(`mux payload too large: ${data.length}`));
        const out = Buffer.allocUnsafe(2 + meta.length + 2 + data.length);
        out.writeUInt16BE(meta.length, 0);
        meta.copy(out, 2);
        const off = 2 + meta.length;
        out.writeUInt16BE(data.length, off);
        data.copy(out, off + 2);
        return this._queueWrite(out);
    }
    writeMuxMeta(meta) {
        const out = Buffer.allocUnsafe(2 + meta.length);
        out.writeUInt16BE(meta.length, 0);
        meta.copy(out, 2);
        return this._queueWrite(out);
    }
}

async function handleConnection(socket, cfg, xm) {
    const reader = new AsyncByteReader(socket);
    let established = false;
    const remote = `${socket.remoteAddress || '?'}:${socket.remotePort || '?'}`;
    socket.setNoDelay(true);
    socket.setTimeout(cfg.handshakeTimeout, () => socket.destroy(new Error('handshake timeout')));
    try {
        const control = await readControl(reader);
        established = true;
        socket.setTimeout(cfg.idleTimeout > 0 ? cfg.idleTimeout : 0, () => socket.destroy(new Error('idle timeout')));
        if (control.mode === RELAY_MODE_FIXED_UDP) {
            stats.modeCounts.fixedUdp++;
            log('info', `relay connection ${remote}: fixed-UDP -> ${control.target.host}:${control.target.port}`);
            await serveDirectUDP(socket, reader, control.target);
        } else if (control.mode === RELAY_MODE_PACKET_UDP) {
            stats.modeCounts.packetUdp++;
            log('info', `relay connection ${remote}: packet-UDP`);
            await servePacketUDP(socket, reader);
        } else {
            stats.modeCounts.mux++;
            log('info', `relay connection ${remote}: mux (xudp)`);
            const mux = new MuxConnection(socket, reader, cfg, xm);
            await mux.serve();
        }
    } catch (err) {
        if (!established && !socket.destroyed) {
            stats.rejectedConnections++;
            await writeControlError(socket, 'malformed control header');
        } else if (!isNormalClose(err)) {
            stats.errors++;
            log('error', `relay connection ${remote}: ${err.message || err}`);
        }
    } finally {
        socket.destroy();
    }
}

function isNormalClose(err) {
    if (!err) return true;
    const code = err.code || '';
    if (['EOF', 'ECONNRESET', 'EPIPE', 'ERR_STREAM_PREMATURE_CLOSE'].includes(code)) return true;
    const msg = String(err.message || err).toLowerCase();
    return msg.includes('unexpected eof') || msg.includes('socket is closed') || msg.includes('idle timeout');
}

function sniffAndRoute(socket, onRelay, onHttp) {
    let buf = Buffer.alloc(0);
    let decided = false;
    const cleanup = () => {
        socket.removeListener('data', onData);
        socket.removeListener('close', onClose);
        socket.removeListener('error', onError);
        clearTimeout(timer);
    };
    const decide = (isRelay) => {
        if (decided) return;
        decided = true;
        cleanup();
        if (buf.length) socket.unshift(buf);
        (isRelay ? onRelay : onHttp)(socket);
    };
    const onData = (chunk) => {
        buf = buf.length ? Buffer.concat([buf, chunk]) : chunk;
        const matchLen = Math.min(buf.length, RELAY_MAGIC.length);
        if (!buf.subarray(0, matchLen).equals(RELAY_MAGIC.subarray(0, matchLen))) {
            decide(false);
            return;
        }
        if (buf.length >= RELAY_MAGIC.length) decide(true);
    };
    const onClose = () => { if (!decided) { decided = true; cleanup(); } };
    const onError = () => { if (!decided) { decided = true; cleanup(); } };
    const timer = setTimeout(() => decide(false), 5000);
    timer.unref?.();
    socket.on('data', onData);
    socket.once('close', onClose);
    socket.once('error', onError);
}

function createRelayServer(cfg = buildConfig()) {
    const xm = new XUDPManager(cfg.xudpGrace);
    const httpServer = createHttpServer();
    const server = net.createServer((socket) => {
        sniffAndRoute(
            socket,
            (sock) => {
                if (stats.activeConnections >= cfg.maxConns) {
                    stats.rejectedConnections++;
                    writeControlError(sock, 'server busy').finally(() => sock.destroy());
                    return;
                }
                stats.totalConnections++;
                stats.activeConnections++;
                sock.once('close', () => { stats.activeConnections--; });
                handleConnection(sock, cfg, xm).catch((err) => {
                    stats.errors++;
                    log('error', `connection handler error: ${err?.message || err}`);
                    sock.destroy();
                });
            },
            (sock) => {
                httpServer.emit('connection', sock);
            },
        );
    });
    server.on('close', () => xm.close());
    server.xudpManager = xm;
    server.httpServer = httpServer;
    return server;
}

async function startRelay(overrides = {}) {
    const cfg = buildConfig(overrides);
    const server = createRelayServer(cfg);
    await new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen(cfg.listenAddress.port, cfg.listenAddress.host, () => {
            server.off('error', reject);
            resolve();
        });
    });
    return { server, cfg };
}

const DASHBOARD_HTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>UDP/XUDP Relay — Monitor</title>
<style>
  :root {
    color-scheme: dark;
    --bg: #0b0e14;
    --panel: #131826;
    --panel-2: #0f1420;
    --border: #232a3b;
    --text: #e6e9f0;
    --muted: #8993a8;
    --accent: #5ea1ff;
    --good: #35d399;
    --warn: #f5b942;
    --bad: #ff6b6b;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    background: var(--bg);
    color: var(--text);
    padding: 1.25rem;
  }
  header {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: space-between;
    gap: 0.75rem;
    margin-bottom: 1.25rem;
  }
  h1 {
    font-size: 1.1rem;
    margin: 0;
    letter-spacing: 0.02em;
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }
  .dot {
    width: 10px; height: 10px; border-radius: 50%;
    background: var(--muted);
    box-shadow: 0 0 0 3px rgba(255,255,255,0.05);
  }
  .dot.live { background: var(--good); }
  .dot.down { background: var(--bad); }
  .meta { color: var(--muted); font-size: 0.8rem; }
  .grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
    gap: 0.75rem;
    margin-bottom: 1.5rem;
  }
  .card {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 0.85rem 1rem;
  }
  .card .label { color: var(--muted); font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.05em; }
  .card .value { font-size: 1.5rem; font-weight: 700; margin-top: 0.25rem; }
  .card .sub { color: var(--muted); font-size: 0.75rem; margin-top: 0.2rem; }
  section { margin-bottom: 1.5rem; }
  section h2 {
    font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.05em;
    color: var(--muted); margin: 0 0 0.6rem 0;
  }
  .panel { background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 1rem; }
  .log-list { max-height: 420px; overflow-y: auto; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.8rem; }
  .log-row { display: flex; gap: 0.6rem; padding: 0.3rem 0; border-bottom: 1px solid var(--border); }
  .log-row .ts { color: var(--muted); white-space: nowrap; }
  .log-row .lvl { width: 4.5rem; flex: none; font-weight: 700; }
  .log-row.info .lvl { color: var(--accent); }
  .log-row.warn .lvl { color: var(--warn); }
  .log-row.error .lvl { color: var(--bad); }
  .log-row .msg { flex: 1; word-break: break-word; }
  .empty { color: var(--muted); padding: 0.75rem 0; font-size: 0.85rem; }
</style>
</head>
<body>

<header>
  <h1><span class="dot" id="statusDot"></span> UDP / XUDP Relay Monitor</h1>
  <span class="meta" id="listenMeta">connecting…</span>
</header>

<div class="grid" id="statGrid"></div>

<section>
  <h2>Live log <span class="meta" id="logCount"></span></h2>
  <div class="panel">
    <div class="log-list" id="logList"><div class="empty">Waiting for data…</div></div>
  </div>
</section>

<script>
(function () {
  const POLL_MS = 3000;
  const statusDot = document.getElementById('statusDot');
  const listenMeta = document.getElementById('listenMeta');
  const statGrid = document.getElementById('statGrid');
  const logList = document.getElementById('logList');
  const logCount = document.getElementById('logCount');

  function fmtBytes(n) {
    if (!n) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    let i = 0;
    let v = n;
    while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
    return v.toFixed(i === 0 ? 0 : 1) + ' ' + units[i];
  }
  function fmtDuration(ms) {
    let s = Math.floor(ms / 1000);
    const d = Math.floor(s / 86400); s -= d * 86400;
    const h = Math.floor(s / 3600); s -= h * 3600;
    const m = Math.floor(s / 60); s -= m * 60;
    const parts = [];
    if (d) parts.push(d + 'd');
    if (h || d) parts.push(h + 'h');
    if (m || h || d) parts.push(m + 'm');
    parts.push(s + 's');
    return parts.join(' ');
  }
  function fmtNum(n) { return (n || 0).toLocaleString(); }

  function card(label, value, sub) {
    const el = document.createElement('div');
    el.className = 'card';
    el.innerHTML = '<div class="label"></div><div class="value"></div><div class="sub"></div>';
    el.querySelector('.label').textContent = label;
    el.querySelector('.value').textContent = value;
    if (sub) el.querySelector('.sub').textContent = sub;
    return el;
  }

  function renderStats(s) {
    statGrid.innerHTML = '';
    statGrid.appendChild(card('Uptime', fmtDuration(s.uptimeMs), 'since ' + s.startedAt));
    statGrid.appendChild(card('Active connections', fmtNum(s.activeConnections), fmtNum(s.totalConnections) + ' total'));
    statGrid.appendChild(card('Active UDP associations', fmtNum(s.activeUdpAssociations), fmtNum(s.totalUdpAssociations) + ' total'));
    statGrid.appendChild(card('Active XUDP sessions', fmtNum(s.activeXudpSessions), fmtNum(s.totalXudpSessions) + ' total'));
    statGrid.appendChild(card('Active mux connections', fmtNum(s.activeMuxConnections)));
    statGrid.appendChild(card('UDP sent', fmtBytes(s.udpBytesSent), fmtNum(s.udpPacketsSent) + ' packets'));
    statGrid.appendChild(card('UDP received', fmtBytes(s.udpBytesReceived), fmtNum(s.udpPacketsReceived) + ' packets'));
    statGrid.appendChild(card('Rejected UDP/443', fmtNum(s.rejectedUdp443), s.config.rejectUdp443 ? 'blocking enabled' : 'blocking disabled'));
    statGrid.appendChild(card('Rejected connections', fmtNum(s.rejectedConnections), 'bad handshake / server busy'));
    statGrid.appendChild(card('Errors', fmtNum(s.errors)));
    statGrid.appendChild(card('Max connections', fmtNum(s.config.maxConnections)));
    statGrid.appendChild(card('XUDP grace window', (s.config.xudpGraceMs / 1000).toFixed(0) + 's'));

    listenMeta.textContent = 'listening on ' + s.listen;
  }

  function renderLogs(entries) {
    if (!entries.length) {
      logList.innerHTML = '<div class="empty">No log entries yet.</div>';
      logCount.textContent = '';
      return;
    }
    logCount.textContent = '(' + entries.length + ')';
    logList.innerHTML = '';
    entries.forEach(function (e) {
      const row = document.createElement('div');
      row.className = 'log-row ' + (e.level || 'info');
      const ts = new Date(e.ts).toLocaleTimeString();
      row.innerHTML = '<span class="ts"></span><span class="lvl"></span><span class="msg"></span>';
      row.querySelector('.ts').textContent = ts;
      row.querySelector('.lvl').textContent = (e.level || 'info').toUpperCase();
      row.querySelector('.msg').textContent = e.message + (e.meta ? ' ' + JSON.stringify(e.meta) : '');
      logList.appendChild(row);
    });
  }

  async function refresh() {
    try {
      const [statsRes, logsRes] = await Promise.all([
        fetch('/api/stats'),
        fetch('/api/logs'),
      ]);
      const stats = await statsRes.json();
      const logs = await logsRes.json();
      renderStats(stats);
      renderLogs(logs.logs || []);
      statusDot.className = 'dot live';
    } catch (err) {
      statusDot.className = 'dot down';
    }
  }

  refresh();
  setInterval(refresh, POLL_MS);
})();
</script>
</body>
</html>
`;

function sendJson(res, status, body) {
    const payload = Buffer.from(JSON.stringify(body));
    res.writeHead(status, {
        'Content-Type': 'application/json; charset=utf-8',
        'Content-Length': payload.length,
        'Cache-Control': 'no-store',
    });
    res.end(payload);
}

function createHttpServer() {
    return http.createServer((req, res) => {
        let url;
        try {
            url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
        } catch {
            res.writeHead(400, { 'Content-Type': 'text/plain' });
            res.end('bad request');
            return;
        }
        if (url.pathname === '/health') {
            res.writeHead(200, { 'Content-Type': 'text/plain' });
            res.end('ok');
            return;
        }
        if (url.pathname === '/api/stats') {
            return sendJson(res, 200, statsSnapshot());
        }
        if (url.pathname === '/api/logs') {
            return sendJson(res, 200, { logs: logBuffer.slice().reverse() });
        }
        if (url.pathname === '/' || url.pathname === '/index.html' || url.pathname === '/dashboard') {
            res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
            res.end(DASHBOARD_HTML);
            return;
        }
        res.writeHead(404, { 'Content-Type': 'text/plain' });
        res.end('not found');
    });
}

async function main() {
    const { server, cfg } = await startRelay();
    const addr = server.address();
    log('info', `Relay listening on ${addr.address}:${addr.port} | xudp-grace=${cfg.xudpGrace}ms`);
    const shutdown = () => {
        log('info', 'shutting down');
        server.close(() => process.exit(0));
        setTimeout(() => process.exit(1), 5000).unref();
    };
    process.once('SIGINT', shutdown);
    process.once('SIGTERM', shutdown);
}

if (require.main === module) {
    main().catch((err) => {
        console.error(err?.stack || err);
        process.exitCode = 1;
    });
}

module.exports = {
    CONFIG,
    ATYP_IPV4,
    ATYP_DOMAIN,
    ATYP_IPV6,
    RELAY_MAGIC,
    RELAY_MODE_FIXED_UDP,
    RELAY_MODE_MUX,
    RELAY_MODE_PACKET_UDP,
    buildConfig,
    startRelay,
    createRelayServer,
    createHttpServer,
    statsSnapshot,
    stats,
    log,
    readMuxFrame,
    AsyncByteReader,
    encodeUDPSource,
};
