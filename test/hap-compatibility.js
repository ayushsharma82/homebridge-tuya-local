'use strict';

const assert = require('assert');
const EventEmitter = require('events');

function verify(hap, label) {
    const categories = hap.Categories || hap.Accessory.Categories;
    const permissions = hap.Perms || hap.Characteristic.Perms;
    const read = permissions.PAIRED_READ || permissions.READ;
    const write = permissions.PAIRED_WRITE || permissions.WRITE;
    const formats = hap.Formats || hap.Characteristic.Formats;
    class PlatformAccessory extends hap.Accessory {
        constructor(name, uuid, category) {
            super(name, uuid);
            this.category = category;
        }
    }
    let Platform;
    require('../index')({
        platformAccessory: PlatformAccessory,
        hap,
        registerPlatform(plugin, name, implementation) {
            assert.strictEqual(plugin, 'homebridge-tuya-local');
            assert.strictEqual(name, 'TuyaLan');
            Platform = implementation;
        }
    });
    const log = Object.assign(function() {}, {info() {}, warn() {}, error() {}, debug() {}});
    const api = {
        hap,
        on() {},
        unregisterPlatformAccessories() { throw new Error('Cached outlet must not be removed'); },
        registerPlatformAccessories() { throw new Error('Cached outlet must not be registered again'); }
    };
    const id = 'fixture-outlet';
    const uuid = hap.uuid.generate('homebridge-tuya-local:' + id);
    const platform = new Platform(log, {devices: [{id}]}, api);
    const accessory = new PlatformAccessory('Fixture Outlet', uuid, categories.OUTLET);
    const outlet = accessory.addService(hap.Service.Outlet, 'Fixture Outlet');
    const on = outlet.getCharacteristic(hap.Characteristic.On);
    assert(on.props.perms.includes(write));
    assert(on.props.perms.includes(permissions.NOTIFY));

    // Exercise the original cached-accessory crash, then the Categories lookup
    // used when the discovered device is attached to the restored accessory.
    platform.configureAccessory(accessory);
    assert.strictEqual(platform.cachedAccessories.get(uuid), accessory);
    const device = new EventEmitter();
    device.context = {id, UUID: uuid, name: 'Fixture Outlet', type: 'Outlet', ip: '192.0.2.1', version: '3.3'};
    device.connected = true;
    device.state = {'1': false};
    device._connect = function() {};
    platform.addAccessory(device);
    assert.strictEqual(platform.cachedAccessories.get(uuid).accessory, accessory);
    device.emit('connect');
    device.emit('change', device.state, device.state);
    assert.strictEqual(on.value, false);
    assert.strictEqual(accessory.UUID, uuid);
    assert.strictEqual(accessory.category, categories.OUTLET);

    const expectedFormats = {
        Amperes: formats.FLOAT,
        KilowattHours: formats.FLOAT,
        KilowattVoltAmpereHour: formats.UINT32,
        VoltAmperes: formats.UINT16,
        Volts: formats.FLOAT,
        Watts: formats.FLOAT
    };
    const energy = hap.EnergyCharacteristics;
    assert.strictEqual(Object.keys(energy).length, 6);
    for (const name of Object.keys(energy)) {
        const characteristic = new energy[name]();
        assert.deepStrictEqual(characteristic.props.perms, [read, permissions.NOTIFY]);
        assert(!characteristic.props.perms.includes(undefined));
        assert.strictEqual(characteristic.props.format, expectedFormats[name]);
        assert.strictEqual(typeof characteristic.value, 'number');
    }
    console.log('PASS: ' + label + ' cached outlet identity, discovery attachment, and six energy characteristics');
}

const modern = require('@homebridge/hap-nodejs');
assert.strictEqual(modern.Characteristic.Perms, undefined);
assert.strictEqual(modern.Characteristic.Formats, undefined);
assert.strictEqual(modern.Accessory.Categories, undefined);
verify(modern, 'HAP 2.2.2');

const legacy = require('hap-nodejs-legacy');
verify(legacy, 'HAP 0.9.8');
// Check the old API shape explicitly so compatibility cannot accidentally rely
// on the top-level aliases still present in this legacy HAP release.
assert(legacy.Characteristic.Perms && legacy.Characteristic.Formats && legacy.Accessory.Categories);
verify({Characteristic: legacy.Characteristic, Service: legacy.Service, Accessory: legacy.Accessory, uuid: legacy.uuid}, 'legacy static enum API');
