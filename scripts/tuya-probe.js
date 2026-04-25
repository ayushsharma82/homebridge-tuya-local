#!/usr/bin/env node
'use strict';

/**
 * tuya-probe.js — Detect the Tuya Local Protocol version of a device on the
 * local network and optionally run a full communication test.
 *
 * Usage:
 *   node scripts/tuya-probe.js <ip> [options]
 *
 * Examples:
 *   node scripts/tuya-probe.js 192.168.1.50
 *   node scripts/tuya-probe.js 192.168.1.50 --id abc123 --key 0123456789abcdef
 *   node scripts/tuya-probe.js 192.168.1.50 --protocol 3.4 --id abc123 --key 0123456789abcdef
 */

const net = require('net');
const dgram = require('dgram');
const crypto = require('crypto');
const os = require('os');
const path = require('path');
const program = require('commander');

const ROOT = path.resolve(__dirname, '..');

// ─── v3.5 UDP discovery key (same as TuyaDiscovery.js) ────────────────────────
// MD5 of the well-known Tuya broadcast passphrase
const UDP_V35_KEY = crypto
  .createHash('md5')
  .update('yGAdlopoPVldABfn')
  .digest();

// ─── CRC32 / HMAC / AES helpers (mirrors TuyaAccessory internals) ─────────────

const _crc32Table = (() => {
  const t = [];
  for (let i = 0; i < 256; i++) {
    let c = i;
    for (let j = 0; j < 8; j++) c = c & 1 ? (c >>> 1) ^ 3988292384 : c >>> 1;
    t.push(c);
  }
  return t;
})();

const getCRC32 = (buf) => {
  let crc = 0xffffffff;
  for (const b of buf) crc = _crc32Table[b ^ (crc & 0xff)] ^ (crc >>> 8);
  return ~crc;
};

const hmac256 = (data, key) =>
  crypto.createHmac('sha256', key).update(data).digest();

const aesEcbEncrypt = (data, key) => {
  const c = crypto.createCipheriv('aes-128-ecb', key, null);
  c.setAutoPadding(false);
  const out = c.update(data);
  c.final();
  return out;
};

// ─── Logger ────────────────────────────────────────────────────────────────────

const ts = () => new Date().toISOString();

const log = {
  debug: (...a) => console.log(`[DEBUG] ${ts()}`, ...a),
  info: (...a) => console.log(`[INFO ] ${ts()}`, ...a),
  warn: (...a) => console.warn(`[WARN ] ${ts()}`, ...a),
  error: (...a) => console.error(`[ERROR] ${ts()}`, ...a),
};

const hexDump = (direction, buf, versionLabel) =>
  log.debug(
    `${direction} [${versionLabel}] (${buf.length} bytes): ${buf.toString('hex')}`,
  );

// ─── Minimal packet builders (for detection phase, no TuyaAccessory) ──────────

/** Tuya 3.1 / 3.3 heartbeat  (cmd = 9) */
function buildHeartbeat_3x(seq = 1) {
  // Structure: 000055aa | seq(4) | cmd(4) | size(4) | crc(4) | 0000aa55
  const buf = Buffer.alloc(24);
  buf.writeUInt32BE(0x000055aa, 0);
  buf.writeUInt32BE(seq, 4);
  buf.writeUInt32BE(9, 8); // cmd = 9
  buf.writeUInt32BE(8, 12); // payload size = 8 (crc + footer)
  buf.writeInt32BE(getCRC32(buf.slice(0, 16)), 16);
  buf.writeUInt32BE(0x0000aa55, 20);
  return buf;
}

/** Tuya 3.4 session-key negotiation start  (cmd = 3) */
function buildSessionStart_3_4(nonce, key, seq = 1) {
  // Pad nonce to next 16-byte boundary (PKCS-style)
  const padding = 0x10 - (nonce.length & 0x0f);
  const padded = Buffer.alloc(nonce.length + padding, padding);
  nonce.copy(padded);

  const enc = aesEcbEncrypt(padded, key);

  // Header(4) + seq(4) + cmd(4) + size(4) + enc + HMAC(32) + footer(4) = 52 extra
  const buf = Buffer.alloc(enc.length + 52);
  buf.writeUInt32BE(0x000055aa, 0);
  buf.writeUInt32BE(seq, 4);
  buf.writeUInt32BE(3, 8); // cmd = 3
  buf.writeUInt32BE(enc.length + 0x24, 12); // size
  enc.copy(buf, 16);
  hmac256(buf.subarray(0, enc.length + 16), key).copy(buf, enc.length + 16);
  buf.writeUInt32BE(0x0000aa55, enc.length + 48);
  return buf;
}

/** Tuya 3.5 session-key negotiation start  (cmd = 3) */
function buildSessionStart_3_5(nonce, key, seq = 1) {
  const iv = nonce.slice(0, 12);

  // Build header, then encrypt twice so the payload length is correct in the AAD
  const hdr = Buffer.alloc(18);
  hdr.writeUInt32BE(0x00006699, 0);
  hdr.writeUInt16BE(0, 4);
  hdr.writeUInt32BE(seq, 6);
  hdr.writeUInt32BE(3, 10); // cmd = 3

  // First pass — get the real encrypted length
  hdr.writeUInt32BE(iv.length + nonce.length + 16, 14); // placeholder
  const c1 = crypto.createCipheriv('aes-128-gcm', key, iv);
  c1.setAAD(hdr.subarray(4, 18));
  const enc1 = c1.update(nonce);
  c1.final();

  // Update header with accurate payload length, then re-encrypt
  hdr.writeUInt32BE(iv.length + enc1.length + 16, 14);
  const c2 = crypto.createCipheriv('aes-128-gcm', key, iv);
  c2.setAAD(hdr.subarray(4, 18));
  const enc2 = c2.update(nonce);
  c2.final();
  const tag = c2.getAuthTag();

  return Buffer.concat([hdr, iv, enc2, tag, Buffer.from('00009966', 'hex')]);
}

// ─── v3.5 UDP discovery broadcast ────────────────────────────────────────────

/**
 * Determine the local IPv4 address on the same subnet as targetIp, and the
 * corresponding directed broadcast address.
 */
function getLocalNetworkInfo(targetIp) {
  const ifaces = os.networkInterfaces();
  const targetOctets = targetIp.split('.').map(Number);

  for (const name of Object.keys(ifaces)) {
    for (const iface of ifaces[name]) {
      if (iface.family !== 'IPv4' || iface.internal) continue;

      const ifaceOctets = iface.address.split('.').map(Number);
      const maskOctets = iface.netmask.split('.').map(Number);
      const sameSubnet = ifaceOctets.every(
        (o, i) => (o & maskOctets[i]) === (targetOctets[i] & maskOctets[i]),
      );

      if (sameSubnet) {
        const broadcast = ifaceOctets
          .map((o, i) => (o & maskOctets[i]) | (~maskOctets[i] & 0xff))
          .join('.');
        return { localIp: iface.address, broadcast };
      }
    }
  }

  // Fallback: assume /24 subnet
  const p = targetIp.split('.');
  return { localIp: null, broadcast: `${p[0]}.${p[1]}.${p[2]}.255` };
}

/**
 * Build a Tuya v3.5 client-discovery broadcast packet.
 * Payload: {"from":"app","ip":"<localIp>"}
 * Encrypted with AES-128-GCM using UDP_V35_KEY.
 */
function buildV35ClientBroadcast(localIp, seq = 1) {
  const payload = Buffer.from(
    JSON.stringify({ from: 'app', ip: localIp }),
    'utf8',
  );
  const iv = crypto.randomBytes(12);

  // Build header with a placeholder payload length, then fix it after we know
  // the true encrypted length.
  const hdr = Buffer.alloc(18);
  hdr.writeUInt32BE(0x00006699, 0);
  hdr.writeUInt16BE(0, 4); // unknown field
  hdr.writeUInt32BE(seq, 6); // sequence
  hdr.writeUInt32BE(0, 10); // cmd = 0  (generic client broadcast)
  hdr.writeUInt32BE(iv.length + payload.length + 16, 14); // placeholder

  // First pass — determine real encrypted size
  const c1 = crypto.createCipheriv('aes-128-gcm', UDP_V35_KEY, iv);
  c1.setAAD(hdr.subarray(4, 18));
  const enc1 = c1.update(payload);
  c1.final();

  // Write accurate payload length into AAD and re-encrypt
  hdr.writeUInt32BE(iv.length + enc1.length + 16, 14);
  const c2 = crypto.createCipheriv('aes-128-gcm', UDP_V35_KEY, iv);
  c2.setAAD(hdr.subarray(4, 18));
  const enc2 = c2.update(payload);
  c2.final();
  const tag = c2.getAuthTag();

  return Buffer.concat([hdr, iv, enc2, tag, Buffer.from('00009966', 'hex')]);
}

/**
 * v3.5 UDP probe:
 *   1. Bind a UDP socket on port 7000.
 *   2. Broadcast the client-discovery packet to <subnet>.255:7000.
 *   3. Wait for a directed UDP reply from targetIp on port 7000.
 *
 * Newer v3.5 devices do NOT send unsolicited discovery broadcasts; they
 * only reply after receiving this client broadcast.  If the device replies
 * in 3.5 GCM format we know it is a v3.5 device.
 */
function probeV35_udp(targetIp, ms) {
  return new Promise((resolve) => {
    const { localIp, broadcast } = getLocalNetworkInfo(targetIp);

    if (!localIp) {
      log.debug('[v3.5 UDP] Could not determine local IP — skipping UDP probe');
      return resolve(false);
    }

    log.debug(`[v3.5 UDP] Local IP: ${localIp}  Broadcast: ${broadcast}`);

    const sock = dgram.createSocket({ type: 'udp4', reuseAddr: true });
    let settled = false;

    const settle = (result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try {
        sock.close();
      } catch (_) {}
      resolve(result);
    };

    const timer = setTimeout(() => {
      log.debug(`[v3.5 UDP] No response within ${ms} ms`);
      settle(false);
    }, ms);

    sock.on('error', (err) => {
      log.debug(`[v3.5 UDP] Socket error: ${err.message}`);
      settle(false);
    });

    sock.on('message', (msg, rinfo) => {
      hexDump('← UDP RECV', msg, 'v3.5 UDP');
      log.debug(`[v3.5 UDP] Packet from ${rinfo.address}:${rinfo.port}`);

      // Only accept a reply from the device we are probing
      if (rinfo.address !== targetIp) return;

      if (msg.length >= 4 && msg.readUInt32BE(0) === 0x00006699) {
        log.info(
          '[v3.5 UDP] Device replied to client broadcast with 3.5 format ✓',
        );

        // Opportunistically decrypt and log the discovery payload
        try {
          const hdr = msg.slice(4, 18);
          const iv = msg.slice(18, 30);
          const tag = msg.slice(msg.length - 20, msg.length - 4);
          const encrypted = msg.slice(30, msg.length - 20);

          const d = crypto.createDecipheriv('aes-128-gcm', UDP_V35_KEY, iv);
          d.setAAD(hdr);
          d.setAuthTag(tag);
          const plain = Buffer.concat([d.update(encrypted), d.final()]);

          // Device discovery packets have a 4-byte return code prepended
          const json =
            plain.length >= 4
              ? plain.slice(4).toString('utf8')
              : plain.toString('utf8');

          log.debug(`[v3.5 UDP] Discovery payload: ${json}`);
          try {
            const info = JSON.parse(json);
            if (info.gwId) log.info(`[v3.5 UDP]   gwId    : ${info.gwId}`);
            if (info.ip) log.info(`[v3.5 UDP]   ip      : ${info.ip}`);
            if (info.productKey)
              log.info(`[v3.5 UDP]   product : ${info.productKey}`);
          } catch (_) {}
        } catch (ex) {
          log.debug(
            `[v3.5 UDP] Could not decrypt discovery response: ${ex.message}`,
          );
        }

        settle(true);
      }
    });

    sock.bind(7000, () => {
      sock.setBroadcast(true);
      const pkt = buildV35ClientBroadcast(localIp);
      hexDump('→ UDP SEND', pkt, 'v3.5 UDP broadcast');
      sock.send(pkt, 7000, broadcast, (err) => {
        if (err) {
          log.debug(`[v3.5 UDP] Failed to send broadcast: ${err.message}`);
          settle(false);
        } else {
          log.info(`[v3.5 UDP] Client broadcast sent to ${broadcast}:7000`);
        }
      });
    });
  });
}

// ─── Single-version raw TCP probe ─────────────────────────────────────────────

/**
 * Attempt to detect a specific Tuya protocol version on the device.
 * Sends the appropriate negotiation / heartbeat packet and checks whether
 * the device replies in the expected packet format.
 *
 * @param {string} version   - '3.1' | '3.3' | '3.4' | '3.5'
 * @param {string} ip
 * @param {number} port
 * @param {string|null} key  - Device key (used for 3.4/3.5 probes). If absent a
 *                             random key is used; the device will still respond,
 *                             allowing format detection even without the real key.
 * @param {number} ms        - Timeout in milliseconds
 * @returns {Promise<boolean>}
 */
function probeVersion(version, ip, port, key, ms) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let settled = false;

    const settle = (result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      resolve(result);
    };

    const timer = setTimeout(() => {
      log.debug(`[v${version}] No response within ${ms} ms`);
      settle(false);
    }, ms);

    socket.once('connect', () => {
      log.debug(`[v${version}] TCP connected to ${ip}:${port}`);

      const nonce = crypto.randomBytes(16);
      // Use provided key (truncated/padded to 16 bytes) or a random fallback
      const probeKey = key
        ? Buffer.from(key.slice(0, 16).padEnd(16, '\x00'))
        : crypto.randomBytes(16);

      let pkt;
      switch (version) {
        case '3.5':
          pkt = buildSessionStart_3_5(nonce, probeKey);
          break;
        case '3.4':
          pkt = buildSessionStart_3_4(nonce, probeKey);
          break;
        default:
          pkt = buildHeartbeat_3x();
          break;
      }

      hexDump('→ SEND', pkt, `probe v${version}`);
      socket.write(pkt);
    });

    socket.on('data', (data) => {
      hexDump('← RECV', data, `probe v${version}`);
      if (data.length < 4) return;

      const hdr = data.readUInt32BE(0);

      if (version === '3.5') {
        if (hdr === 0x00006699) {
          log.info(`[v${version}] Device replied with 3.5 packet format ✓`);
          settle(true);
        } else if (hdr === 0x000055aa) {
          // Device responded in classic format — definitely not 3.5
          log.debug(
            `[v${version}] Device replied with classic format (not 3.5)`,
          );
          settle(false);
        }
      } else {
        if (hdr === 0x000055aa) {
          const cmd = data.length >= 12 ? data.readUInt32BE(8) : -1;
          log.info(
            `[v${version}] Device replied with classic format (cmd=${cmd}) ✓`,
          );
          settle(true);
        } else if (hdr === 0x00006699) {
          // Device responded in 3.5 format — stop probing this version
          log.debug(`[v${version}] Device replied with 3.5 format (skipping)`);
          settle(false);
        }
      }
    });

    socket.on('error', (err) => {
      log.debug(`[v${version}] Socket error: ${err.message}`);
      settle(false);
    });

    socket.connect(port, ip);
  });
}

// ─── Multi-version detection ──────────────────────────────────────────────────

/**
 * Try each Tuya protocol version and return the first one the device responds to.
 *
 * Order of operations:
 *  1. UDP client broadcast on port 7000  — catches v3.5 devices that do NOT
 *     send unsolicited discovery broadcasts (newer firmware).
 *  2. TCP probes in descending version order  — catches devices that are
 *     already discoverable or respond to session-key negotiation directly.
 */
async function detectVersion(ip, port, key, probeTimeout) {
  log.info('─── Protocol Detection ──────────────────────────────────────────');

  // Step 1 — v3.5 UDP solicited-discovery broadcast
  log.info('Probing Tuya 3.5 (UDP client broadcast on port 7000)...');
  if (await probeV35_udp(ip, probeTimeout)) return '3.5';

  // Step 2 — TCP probes (v3.5 may still respond if already in a session;
  //           v3.4 / 3.3 / 3.1 only speak TCP)
  const candidates = ['3.5', '3.4', '3.3', '3.1'];
  for (const v of candidates) {
    log.info(`Probing Tuya ${v} (TCP)...`);
    if (await probeVersion(v, ip, port, key, probeTimeout)) return v;
  }
  return null;
}

// ─── Full communication test using TuyaAccessory ──────────────────────────────

/**
 * Patch net.Socket so every byte sent/received by TuyaAccessory is debug-logged.
 * Returns a restore function to undo the patch.
 */
function patchNetSocket(versionLabel) {
  const OrigSocket = net.Socket;

  function PatchedSocket(opts) {
    // Handle both `new PatchedSocket()` and `PatchedSocket()` (no-new) call styles
    if (!(this instanceof PatchedSocket)) return new PatchedSocket(opts);

    const s = new OrigSocket(opts);
    const ow = s.write.bind(s);

    s.write = function (data, enc, cb) {
      const buf = Buffer.isBuffer(data) ? data : Buffer.from(data || '');
      hexDump('→ SEND', buf, versionLabel);
      return ow(data, enc, cb);
    };

    s.on('data', (d) => hexDump('← RECV', d, versionLabel));

    return s; // returning an object from a constructor overrides `this`
  }

  // Preserve prototype so instanceof checks in Node.js internals still work
  PatchedSocket.prototype = OrigSocket.prototype;
  Object.setPrototypeOf(PatchedSocket, OrigSocket);

  net.Socket = PatchedSocket;
  return () => {
    net.Socket = OrigSocket;
  };
}

/**
 * Connect to the device with the given protocol version using TuyaAccessory
 * and wait for it to emit a state change (proof of successful communication).
 */
function fullTest(ip, port, id, key, version, testTimeout) {
  return new Promise((resolve) => {
    log.info(
      '─── Full Communication Test ──────────────────────────────────────',
    );
    log.info(`Version: ${version} | IP: ${ip}:${port} | ID: ${id}`);

    const restoreSocket = patchNetSocket(version);

    // Require TuyaAccessory AFTER patching so the patched net.Socket is used
    // at runtime when _connect() calls net.Socket().
    const TuyaAccessory = require(path.join(ROOT, 'lib', 'TuyaAccessory'));

    const accessory = new TuyaAccessory({
      log,
      id,
      key,
      ip,
      port,
      version,
      name: `ProbeDevice-${ip}`,
      connectTimeout: Math.max(10, Math.ceil(testTimeout / 1000)),
    });

    let settled = false;
    const settle = (result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      restoreSocket();
      resolve(result);
    };

    const timer = setTimeout(() => {
      log.warn('Full test timed out — no state data received');
      settle({ success: false, reason: 'timeout' });
    }, testTimeout);

    accessory.on('connect', () => {
      log.info(
        `[v${version}] TCP session established, waiting for device state…`,
      );
    });

    accessory.on('change', (changes, state) => {
      log.info(`[v${version}] ✓ State update received`);
      log.info(`  Changes : ${JSON.stringify(changes, null, 2)}`);
      log.info(`  State   : ${JSON.stringify(state, null, 2)}`);
      settle({ success: true, version, changes, state });
    });
  });
}

// ─── CLI definition ────────────────────────────────────────────────────────────

program
  .name('tuya-probe')
  .description(
    'Probe a Tuya device on the local network to detect its protocol version\n' +
      'and optionally run a full communication test.\n\n' +
      'All raw requests and responses are printed as debug hex dumps.',
  )
  .arguments('<ip>')
  .option('--id <id>', 'Device ID  (enables full communication test)')
  .option(
    '--key <key>',
    'Device local key, exactly 16 chars  (enables full communication test)',
  )
  .option('--port <port>', 'Device port', '6668')
  .option(
    '--protocol <version>',
    'Force a specific protocol version (3.1 | 3.3 | 3.4 | 3.5) and skip auto-detection',
  )
  .option('--timeout <ms>', 'Per-probe timeout in ms', '8000')
  .on('--help', () => {
    console.log('');
    console.log('Examples:');
    console.log('  $ node scripts/tuya-probe.js 192.168.1.50');
    console.log(
      '  $ node scripts/tuya-probe.js 192.168.1.50 --id abc123 --key 0123456789abcdef',
    );
    console.log(
      '  $ node scripts/tuya-probe.js 192.168.1.50 --protocol 3.4 --id abc --key 0123456789abcdef --timeout 12000',
    );
  })
  .parse(process.argv);

// ─── Entry point ───────────────────────────────────────────────────────────────

(async () => {
  const ip = program.args[0];
  const port = parseInt(program.port, 10) || 6668;
  const timeout = parseInt(program.timeout, 10) || 8000;
  const deviceId = program.id;
  const deviceKey = program.key;
  const forcedVersion = program.protocol;

  if (!ip) {
    console.error('\nError: IP address is required as the first argument.\n');
    program.help(); // exits
  }

  console.log('');
  console.log('╔══════════════════════════════════════════════╗');
  console.log('║      Tuya Local Protocol Probe  v1.0.0      ║');
  console.log('╚══════════════════════════════════════════════╝');
  console.log(`  Target  : ${ip}:${port}`);
  if (deviceId) console.log(`  ID      : ${deviceId}`);
  if (deviceKey) console.log(`  Key     : ${'*'.repeat(deviceKey.length)}`);
  if (forcedVersion) console.log(`  Version : ${forcedVersion} (forced)`);
  console.log('');

  // ── Step 1: version detection ──────────────────────────────────────────────
  let version = forcedVersion || null;

  if (!version) {
    version = await detectVersion(ip, port, deviceKey, timeout);
    if (!version) {
      console.log('\n✗  Could not detect Tuya protocol version.');
      console.log(
        '   • Verify the device is powered on and reachable at that IP',
      );
      console.log('   • Confirm port 6668 is not blocked by a firewall');
      console.log('   • Try increasing --timeout\n');
      process.exit(1);
    }
    console.log(`\n✓  Detected protocol version: Tuya ${version}\n`);
  } else {
    log.info(`Skipping auto-detection — using forced version: ${version}`);
    console.log('');
  }

  // ── Step 2: optional full communication test ───────────────────────────────
  if (deviceId && deviceKey) {
    const result = await fullTest(
      ip,
      port,
      deviceId,
      deviceKey,
      version,
      timeout * 3,
    );
    console.log('');
    if (result.success) {
      console.log(`✓  Full test PASSED  (${result.version})`);
      console.log('   Device state:');
      console.log(
        JSON.stringify(result.state, null, 4)
          .split('\n')
          .map((l) => '   ' + l)
          .join('\n'),
      );
    } else {
      console.log(`✗  Full test FAILED: ${result.reason}`);
      process.exit(1);
    }
  } else {
    console.log(
      '  Tip: pass --id <device_id> --key <device_key> to run a full',
    );
    console.log('       communication test and retrieve device state.\n');
  }

  console.log('');
  process.exit(0);
})().catch((err) => {
  log.error('Fatal:', err);
  process.exit(1);
});
