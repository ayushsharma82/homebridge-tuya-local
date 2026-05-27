const BaseAccessory = require('./BaseAccessory');

class SimpleDimmerAccessory extends BaseAccessory {
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
        this.dpBrightness = this._getCustomDP(this.device.context.dpBrightness) || this._getCustomDP(this.device.context.dp) || '2';

        const characteristicOn = service.getCharacteristic(Characteristic.On)
            .updateValue(dps[this.dpPower])
            .onGet(() => this.getStatePromise(this.dpPower))
            .onSet(v => this.setStatePromise(this.dpPower, v));

        const characteristicBrightness = service.getCharacteristic(Characteristic.Brightness)
            .updateValue(this.convertBrightnessFromTuyaToHomeKit(dps[this.dpBrightness]))
            .onGet(() => this.getBrightness())
            .onSet(v => this.setBrightness(v));

        this.device.on('change', changes => {
            if (changes.hasOwnProperty(this.dpPower) && characteristicOn.value !== changes[this.dpPower]) characteristicOn.updateValue(changes[this.dpPower]);
            if (changes.hasOwnProperty(this.dpBrightness) && this.convertBrightnessFromHomeKitToTuya(characteristicBrightness.value) !== changes[this.dpBrightness])
                characteristicBrightness.updateValue(this.convertBrightnessFromTuyaToHomeKit(changes[this.dpBrightness]));
        });
    }

    getBrightness() {
        return this.convertBrightnessFromTuyaToHomeKit(this.device.state[this.dpBrightness]);
    }

    setBrightness(value) {
        this.setStatePromise(this.dpBrightness, this.convertBrightnessFromHomeKitToTuya(value));
    }
}

module.exports = SimpleDimmerAccessory;