const BaseAccessory = require('./BaseAccessory');

class TWLightAccessory extends BaseAccessory {
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
        const {Service, Characteristic, AdaptiveLightingController} = this.hap;
        const service = this.accessory.getService(Service.Lightbulb);
        this._checkServiceName(service, this.device.context.name);

        this.dpPower = this._getCustomDP(this.device.context.dpPower) || '1';
        this.dpBrightness = this._getCustomDP(this.device.context.dpBrightness) || '2';
        this.dpColorTemperature = this._getCustomDP(this.device.context.dpColorTemperature) || '3';

        const characteristicOn = service
          .getCharacteristic(Characteristic.On)
          .updateValue(dps[this.dpPower])
          .onGet(() => this.getStatePromise(this.dpPower))
          .onSet(v => this.setStatePromise(this.dpPower, v));

        const characteristicBrightness = service.getCharacteristic(Characteristic.Brightness)
            .updateValue(this.convertBrightnessFromTuyaToHomeKit(dps[this.dpBrightness]))
            .onGet(() => this.getBrightness())
            .onSet(v => this.setBrightness(v));

        const characteristicColorTemperature = service.getCharacteristic(Characteristic.ColorTemperature)
            .setProps({
                minValue: 0,
                maxValue: 600
            })
            .updateValue(this.convertColorTemperatureFromTuyaToHomeKit(dps[this.dpColorTemperature]))
            .onGet(() => this.getColorTemperature())
            .onSet(v => this.setColorTemperature(v));

        this.characteristicColorTemperature = characteristicColorTemperature;

        if (this.adaptiveLightingSupport()) {
            this.adaptiveLightingController = new AdaptiveLightingController(service);
            this.accessory.configureController(this.adaptiveLightingController);
            this.accessory.adaptiveLightingController = this.adaptiveLightingController;
        }

        this.device.on('change', (changes, state) => {
            if (changes.hasOwnProperty(this.dpPower) && characteristicOn.value !== changes[this.dpPower]) characteristicOn.updateValue(changes[this.dpPower]);

            if (changes.hasOwnProperty(this.dpBrightness) && this.convertBrightnessFromHomeKitToTuya(characteristicBrightness.value) !== changes[this.dpBrightness])
                characteristicBrightness.updateValue(this.convertBrightnessFromTuyaToHomeKit(changes[this.dpBrightness]));

            if (changes.hasOwnProperty(this.dpColorTemperature)) {
                if (this.convertColorTemperatureFromHomeKitToTuya(characteristicColorTemperature.value) !== changes[this.dpColorTemperature])
                    characteristicColorTemperature.updateValue(this.convertColorTemperatureFromTuyaToHomeKit(changes[this.dpColorTemperature]));
            } else if (changes[this.dpBrightness]) {
                characteristicColorTemperature.updateValue(this.convertColorTemperatureFromTuyaToHomeKit(state[this.dpColorTemperature]));
            }
        });
    }

    getBrightness() {
        return this.convertBrightnessFromTuyaToHomeKit(this.device.state[this.dpBrightness]);
    }

    setBrightness(value) {
        this.setStatePromise(this.dpBrightness, this.convertBrightnessFromHomeKitToTuya(value));
    }

    getColorTemperature() {
        return this.convertColorTemperatureFromTuyaToHomeKit(this.device.state[this.dpColorTemperature]);
    }

    setColorTemperature(value) {
        if (value === 0) return;
        this.setStatePromise(this.dpColorTemperature, this.convertColorTemperatureFromHomeKitToTuya(value));
    }
}

module.exports = TWLightAccessory;