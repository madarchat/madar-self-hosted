import dgram from 'node:dgram';
import { logger } from '../lib/logger.js';

/**
 * Minimal STUN server (RFC 5389 Binding method) so WebRTC peers can discover their
 * public address without relying on any third-party STUN service.
 *
 * Supports IPv4 and IPv6 over UDP. Answers Binding Requests with a Binding Success
 * Response carrying XOR-MAPPED-ADDRESS (and MAPPED-ADDRESS for very old clients).
 */
const MAGIC_COOKIE = 0x2112a442;
const BINDING_REQUEST = 0x0001;
const BINDING_SUCCESS = 0x0101;
const BINDING_ERROR = 0x0111;
const ATTR_MAPPED_ADDRESS = 0x0001;
const ATTR_XOR_MAPPED_ADDRESS = 0x0020;
const ATTR_SOFTWARE = 0x8022;
const ATTR_ERROR_CODE = 0x0009;
const SOFTWARE = Buffer.from('madar-stun/1.0');

function pad4(buf) {
  const rem = buf.length % 4;
  return rem === 0 ? buf : Buffer.concat([buf, Buffer.alloc(4 - rem)]);
}

function attr(type, value) {
  const header = Buffer.alloc(4);
  header.writeUInt16BE(type, 0);
  header.writeUInt16BE(value.length, 2);
  return Buffer.concat([header, pad4(value)]);
}

function addressAttr(type, rinfo, transactionId) {
  const isV6 = rinfo.family === 'IPv6';
  const family = isV6 ? 0x02 : 0x01;
  const ip = Buffer.from(isV6 ? ipv6ToBytes(rinfo.address) : rinfo.address.split('.').map(Number));
  const port = Buffer.alloc(2);
  port.writeUInt16BE(rinfo.port, 0);
  if (type === ATTR_XOR_MAPPED_ADDRESS) {
    port.writeUInt16BE(rinfo.port ^ (MAGIC_COOKIE >>> 16), 0);
    const key = Buffer.alloc(16);
    key.writeUInt32BE(MAGIC_COOKIE, 0);
    transactionId.copy(key, 4);
    for (let i = 0; i < ip.length; i++) ip[i] ^= key[i];
  }
  return attr(type, Buffer.concat([Buffer.from([0, family]), port, ip]));
}

function ipv6ToBytes(address) {
  const clean = address.split('%')[0];
  const parts = clean.split('::');
  const head = parts[0] ? parts[0].split(':') : [];
  const tail = parts[1] ? parts[1].split(':') : [];
  const fill = new Array(8 - head.length - tail.length).fill('0');
  const groups = [...head, ...fill, ...tail].map((g) => parseInt(g || '0', 16));
  const out = [];
  for (const g of groups) out.push((g >> 8) & 0xff, g & 0xff);
  return out;
}

function buildMessage(type, transactionId, attributes) {
  const body = Buffer.concat(attributes);
  const header = Buffer.alloc(20);
  header.writeUInt16BE(type, 0);
  header.writeUInt16BE(body.length, 2);
  header.writeUInt32BE(MAGIC_COOKIE, 4);
  transactionId.copy(header, 8);
  return Buffer.concat([header, body]);
}

export function handleStunPacket(msg, rinfo) {
  if (msg.length < 20) return null;
  const type = msg.readUInt16BE(0);
  const cookie = msg.readUInt32BE(4);
  if ((type & 0xc000) !== 0 || cookie !== MAGIC_COOKIE) return null;
  const transactionId = msg.subarray(8, 20);
  if (type !== BINDING_REQUEST) {
    const code = Buffer.concat([Buffer.from([0, 0, 4, 0]), Buffer.from('Bad Request')]);
    return buildMessage(BINDING_ERROR, transactionId, [attr(ATTR_ERROR_CODE, code), attr(ATTR_SOFTWARE, SOFTWARE)]);
  }
  return buildMessage(BINDING_SUCCESS, transactionId, [
    addressAttr(ATTR_XOR_MAPPED_ADDRESS, rinfo, transactionId),
    addressAttr(ATTR_MAPPED_ADDRESS, rinfo, transactionId),
    attr(ATTR_SOFTWARE, SOFTWARE),
  ]);
}

export function startStunServer(port, host = '0.0.0.0') {
  const sockets = [];
  const bind = (type, address) =>
    new Promise((resolve) => {
      const socket = dgram.createSocket({ type, reuseAddr: true });
      socket.on('message', (msg, rinfo) => {
        const reply = handleStunPacket(msg, rinfo);
        if (reply) socket.send(reply, rinfo.port, rinfo.address);
      });
      socket.on('error', (err) => {
        logger.warn({ err: err.message, type }, 'stun socket error');
        resolve(null);
      });
      socket.bind(port, address, () => {
        logger.info({ port, address, type }, 'stun: listening');
        sockets.push(socket);
        resolve(socket);
      });
    });

  return Promise.all([bind('udp4', host), bind('udp6', '::')]).then(() => ({
    close: () => sockets.forEach((s) => s.close()),
  }));
}
