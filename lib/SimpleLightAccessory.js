const BaseAccessory = require('./BaseAccessory');

class SimpleLightAccessory extends BaseAccessory {
    static getCategory(Categories) {
        return Categories.LIGHTBULB;
    }

    constructor(...props) {
        super(...props);
    }

    _registerPlatformAccessory() {
        const {Service} = this.hap;

        this.accessory.addService(Service.Lightbulb, this.device.context.name);

        super._registerPlatformAccessory();
    }

    _registerCharacteristics(dps) {
        const {Service, Characteristic} = this.hap;
        const service = this.accessory.getService(Service.Lightbulb);
        this._checkServiceName(service, this.device.context.name);

        this.dpPower = this._getCustomDP(this.device.context.dpPower) || '1';

        const characteristicOn = service.getCharacteristic(Characteristic.On)
            .updateValue(dps[this.dpPower])
            .on('get', this.getState.bind(this, this.dpPower))
            .on('set', this.setPower.bind(this));

        this.device.on('change', (changes, state) => {
            if (changes.hasOwnProperty(this.dpPower) && characteristicOn.value !== changes[this.dpPower]) characteristicOn.updateValue(changes[this.dpPower]);
            this.log.info('SimpleLight changed: ' + JSON.stringify(state));
        });
    }

    setPower(value, callback) {
        const dps = {[this.dpPower]: value};
        // powerOnDps: extra datapoints asserted on every power-on, so devices
        // exposed with reduced controls always return to a known mode (e.g.
        // {"21": "white", "23": 0} for warm white). Already-correct values are
        // skipped by setMultiState.
        if (value && this.device.context.powerOnDps) Object.assign(dps, this.device.context.powerOnDps);
        this.setMultiState(dps, callback);
    }
}

module.exports = SimpleLightAccessory;
