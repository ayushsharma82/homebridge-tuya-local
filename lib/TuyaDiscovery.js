const dgram = require('dgram');
const crypto = require('crypto');
const EventEmitter = require('events');

const UDP_KEY = Buffer.from('6c1ec8e2bb9bb59ab50b0daf649b410a', 'hex');
const UDP_GCM_KEY = Buffer.from('6c1ec8e2bb9bb59ab50b0daf649b410a', 'hex');
// Tuya v3.5 discovery broadcast key - MD5 of 'yGAdlopoPVldABfn'
const UDP_V35_KEY = crypto
  .createHash('md5')
  .update('yGAdlopoPVldABfn')
  .digest();

class TuyaDiscovery extends EventEmitter {
  constructor() {
    super();

    this.discovered = new Map();
    this.limitedIds = [];
    this._servers = {};
    this._running = false;
  }

  start(props) {
    this.log = props.log;

    const opts = props || {};

    if (opts.clear) {
      this.removeAllListeners();
      this.discovered.clear();
    }

    this.limitedIds.splice(0);
    if (Array.isArray(opts.ids)) [].push.apply(this.limitedIds, opts.ids);

    this._running = true;
    this._start(6666);
    this._start(6667);
    this._start(7000); // Add support for Tuya v3.5 discovery on port 7000

    return this;
  }

  stop() {
    this._running = false;
    this._stop(6666);
    this._stop(6667);
    this._stop(7000);

    return this;
  }

  end() {
    this.stop();
    process.nextTick(() => {
      this.removeAllListeners();
      this.discovered.clear();
      this.log.info('Discovery ended.');
      this.emit('end');
    });

    return this;
  }

  _isBase64(str) {
    // Accepts a base64 string of reasonable length for Tuya UDP
    if (!str || typeof str !== 'string') return false;
    if (str.length < 40) return false;
    // Basic base64 check
    return /^[A-Za-z0-9+/=]+$/.test(str) && str.length % 4 === 0;
  }

  _start(port) {
    this._stop(port);

    const server = (this._servers[port] = dgram.createSocket({
      type: 'udp4',
      reuseAddr: true,
    }));
    server.on('error', this._onDgramError.bind(this, port));
    server.on('close', this._onDgramClose.bind(this, port));
    server.on('message', this._onDgramMessage.bind(this, port));

    server.bind(port, () => {
      this.log.info(`Discovery - Discovery started on port ${port}.`);
    });
  }

  _stop(port) {
    if (this._servers[port]) {
      this._servers[port].removeAllListeners();
      this._servers[port].close();
      this._servers[port] = null;
    }
  }

  _onDgramError(port, err) {
    this._stop(port);

    if (err && err.code === 'EADDRINUSE') {
      this.log.warn(
        `Discovery - Port ${port} is in use. Will retry in 15 seconds.`
      );

      setTimeout(() => {
        this._start(port);
      }, 15000);
    } else {
      this.log.error(`Discovery - Port ${port} failed:\n${err.stack}`);
    }
  }

  _onDgramClose(port) {
    this._stop(port);

    this.log.info(
      `Discovery - Port ${port} closed.${this._running ? ' Restarting...' : ''}`
    );
    if (this._running)
      setTimeout(() => {
        this._start(port);
      }, 1000);
  }

  _onDgramMessage(port, msg, info) {
    const len = msg.length;
    //  this.log.info(`Discovery - UDP from ${info.address}:${port} 0x${msg.readUInt32BE(0).toString(16).padStart(8, '0')}...0x${msg.readUInt32BE(len - 4).toString(16).padStart(8, '0')}`);

    const prefix = msg.readUInt32BE(0);

    // Check for Tuya v3.5 format (6699 prefix)
    if (prefix === 0x00006699 && len >= 34) {
      this._handleV35Message(msg, info, port);
      return;
    }

    // Existing v3.2-v3.4 format (55AA prefix)
    if (
      len < 16 ||
      prefix !== 0x000055aa ||
      msg.readUInt32BE(len - 4) !== 0x0000aa55
    ) {
      this.log.error(
        `Discovery - UDP from ${info.address}:${port}`,
        msg.toString('hex')
      );
      return;
    }

    const size = msg.readUInt32BE(12);
    if (len - size < 8) {
      this.log.error(
        `Discovery - UDP from ${info.address}:${port} size ${len - size}`
      );
      return;
    }

    //const result = {cmd: msg.readUInt32BE(8)};
    const cleanMsg = msg.slice(len - size + 4, len - 8);

    let decryptedMsg;
    if (port === 6667) {
      try {
        const decipher = crypto.createDecipheriv('aes-128-ecb', UDP_KEY, '');
        decryptedMsg = decipher.update(cleanMsg, 'utf8', 'utf8');
        decryptedMsg += decipher.final('utf8');
      } catch (ex) {}
    }

    if (!decryptedMsg) decryptedMsg = cleanMsg.toString('utf8');

    try {
      const result = JSON.parse(decryptedMsg);
      if (result && result.gwId && result.ip) this._onDiscover(result);
      else
        this.log.error(
          `Discovery - UDP from ${info.address}:${port} decrypted`,
          cleanMsg.toString('hex')
        );
    } catch (ex) {
      this.log.error(
        `Discovery - Failed to parse discovery response on port ${port}: ${decryptedMsg}`
      );
      this.log.error(
        `Discovery - Failed to parse discovery raw message on port ${port}: ${msg.toString(
          'hex'
        )}`
      );
    }
  }

  _handleV35Message(msg, info, port) {
    try {
      const len = msg.length;

      // Validate footer
      if (msg.readUInt32BE(len - 4) !== 0x00009966) {
        this.log.error(
          `Discovery - Invalid v3.5 footer from ${info.address}:${port}`,
          msg.toString('hex')
        );
        return;
      }

      // Extract packet components
      // 00006699UUUUSSSSSSSSMMMMMMMMLLLLLLLL(II*12)DD..DD(TT*16)00009966
      const header = msg.slice(4, 18); // UUUU + SSSSSSSS + MMMMMMMM + LLLLLLLL
      const packetLength = msg.readUInt32BE(14); // LLLLLLLL
      const iv = msg.slice(18, 30); // 12-byte IV/nonce

      // Calculate payload and tag positions based on packet length
      const payloadStart = 30;
      const payloadEnd = len - 20; // 16-byte tag + 4-byte footer
      const tagStart = payloadEnd;
      const tagEnd = len - 4;

      const payload = msg.slice(payloadStart, payloadEnd);
      const tag = msg.slice(tagStart, tagEnd);

      // Validate packet length
      if (packetLength !== iv.length + payload.length + tag.length) {
        this.log.error(
          `Discovery - Invalid v3.5 packet length from ${
            info.address
          }:${port}, expected ${packetLength}, got ${
            iv.length + payload.length + tag.length
          }`
        );
        return;
      }

      // Decrypt using AES-GCM
      let decryptedPayload;
      try {
        const cipher = crypto.createDecipheriv('aes-128-gcm', UDP_V35_KEY, iv);
        cipher.setAAD(header); // Header is authenticated but not encrypted
        cipher.setAuthTag(tag);
        decryptedPayload = Buffer.concat([
          cipher.update(payload),
          cipher.final(),
        ]);
      } catch (ex) {
        this.log.error(
          `Discovery - Failed to decrypt v3.5 message from ${info.address}:${port}: ${ex.message}`
        );
        return;
      }

      // For device discovery packets, strip the 4-byte return code at the beginning
      let jsonPayload;
      if (decryptedPayload.length >= 4) {
        // Skip first 4 bytes (return code) for device packets
        jsonPayload = decryptedPayload.slice(4).toString('utf8');
      } else {
        jsonPayload = decryptedPayload.toString('utf8');
      }

      // Parse JSON and handle discovery
      try {
        const result = JSON.parse(jsonPayload);
        if (result && result.gwId && result.ip) {
          this._onDiscover(result);
        } else {
          this.log.error(
            `Discovery - Invalid v3.5 discovery data from ${info.address}:${port}`,
            jsonPayload
          );
        }
      } catch (ex) {
        this.log.error(
          `Discovery - Failed to parse v3.5 discovery response from ${info.address}:${port}: ${jsonPayload}`
        );
      }
    } catch (ex) {
      this.log.error(
        `Discovery - Error processing v3.5 message from ${info.address}:${port}: ${ex.message}`
      );
    }
  }

  _onDiscover(data) {
    // Extract previous IP using gwId
    const prevIp = this.discovered.get(data.gwId);

    // Normalize id field
    data.id = data.gwId;
    delete data.gwId;

    // Always update IP for dynamic IP support
    this.discovered.set(data.id, data.ip);

    if (!prevIp) {
      // First time discovery: emit 'discover' event
      this.emit('discover', data);
    } else if (prevIp !== data.ip) {
      // IP changed: emit 'ipChanged' event only
      this.emit('ipChanged', { id: data.id, oldIp: prevIp, newIp: data.ip });
      this.log.info(
        `Discovery - Device ${data.id} IP changed from ${prevIp} to ${data.ip}`
      );
    }
    // If IP is unchanged, do nothing (no event)

    // Check if all limitedIds are discovered
    if (
      this.limitedIds.length &&
      this.limitedIds.includes(data.id) &&
      this.limitedIds.length <= this.discovered.size &&
      this.limitedIds.every((id) => this.discovered.has(id))
    ) {
      process.nextTick(() => {
        this.end();
      });
    }
  }

  sendClientBroadcast(ip) {
    // Tuya 3.5 client broadcast: AES-GCM encrypted JSON payload
    // Key: MD5('yGAdlopoPVldABfn')
    const payload = Buffer.from(
      JSON.stringify({ from: 'app', ip: ip || '255.255.255.255' }),
      'utf8'
    );
    const iv = crypto.randomBytes(12);
    const header = Buffer.alloc(14, 0); // UUUU + SSSSSSSS + MMMMMMMM + LLLLLLLL

    // Set packet length in header (last 4 bytes)
    const packetLen = iv.length + payload.length + 16; // IV + payload + auth tag
    header.writeUInt32BE(packetLen, 10);

    const cipher = crypto.createCipheriv('aes-128-gcm', UDP_V35_KEY, iv);
    cipher.setAAD(header);
    const encrypted = Buffer.concat([cipher.update(payload), cipher.final()]);
    const tag = cipher.getAuthTag();

    // Build packet: 00006699 + header + iv + encrypted + tag + 00009966
    const prefix = Buffer.from([0x00, 0x00, 0x66, 0x99]);
    const suffix = Buffer.from([0x00, 0x00, 0x99, 0x66]);

    // Compose full packet
    const packet = Buffer.concat([prefix, header, iv, encrypted, tag, suffix]);

    // Send to broadcast address on port 7000
    const client = dgram.createSocket('udp4');
    client.setBroadcast(true);

    client.send(packet, 0, packet.length, 7000, '255.255.255.255', (err) => {
      client.close();
      if (err) {
        this.log.error(
          `Failed to send Tuya 3.5 client broadcast: ${err.message}`
        );
      } else {
        this.log.info('Sent Tuya 3.5 client broadcast for discovery');
      }
    });
  }
}

module.exports = new TuyaDiscovery();
