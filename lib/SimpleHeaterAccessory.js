const BaseAccessory = require('./BaseAccessory');

class SimpleHeaterAccessory extends BaseAccessory {
    static getCategory(Categories) {
        return Categories.AIR_HEATER;
    }

    constructor(...props) {
        super(...props);
    }

    _registerPlatformAccessory() {
        const {Service} = this.hap;

        this.accessory.addService(Service.HeaterCooler, this.device.context.name);

        super._registerPlatformAccessory();
    }

    _registerCharacteristics(dps) {
        const {Service, Characteristic} = this.hap;
        const service = this.accessory.getService(Service.HeaterCooler);
        this._checkServiceName(service, this.device.context.name);

        this.dpActive = this._getCustomDP(this.device.context.dpActive) || '1';
        this.dpDesiredTemperature = this._getCustomDP(this.device.context.dpDesiredTemperature) || '2';
        this.dpCurrentTemperature = this._getCustomDP(this.device.context.dpCurrentTemperature) || '3';
        this.temperatureDivisor = parseInt(this.device.context.temperatureDivisor) || 1;
        this.thresholdTemperatureDivisor = parseInt(this.device.context.thresholdTemperatureDivisor) || 1;
        this.targetTemperatureDivisor = parseInt(this.device.context.targetTemperatureDivisor) || 1;

        const characteristicActive = service.getCharacteristic(Characteristic.Active)
            .updateValue(this._getActive(dps[this.dpActive]))
            .onGet(() => this.getActive())
            .onSet(v => this.setActive(v));

        service.getCharacteristic(Characteristic.CurrentHeaterCoolerState)
            .updateValue(this._getCurrentHeaterCoolerState(dps))
            .onGet(() => this.getCurrentHeaterCoolerState());

        service.getCharacteristic(Characteristic.TargetHeaterCoolerState)
            .setProps({
                minValue: 1,
                maxValue: 1,
                validValues: [Characteristic.TargetHeaterCoolerState.HEAT]
            })
            .updateValue(this._getTargetHeaterCoolerState())
            .onGet(() => this.getTargetHeaterCoolerState())
            .onSet(v => this.setTargetHeaterCoolerState(v));

        const characteristicCurrentTemperature = service.getCharacteristic(Characteristic.CurrentTemperature)
            .updateValue(this._getDividedState(dps[this.dpCurrentTemperature], this.temperatureDivisor))
            .onGet(() => this.getDividedStatePromise(this.dpCurrentTemperature, this.temperatureDivisor));

        const characteristicHeatingThresholdTemperature = service.getCharacteristic(Characteristic.HeatingThresholdTemperature)
            .setProps({
                minValue: this.device.context.minTemperature || 15,
                maxValue: this.device.context.maxTemperature || 35,
                minStep: this.device.context.minTemperatureSteps || 1
            })
            .updateValue(this._getDividedState(dps[this.dpDesiredTemperature], this.thresholdTemperatureDivisor))
            .onGet(() => this.getDividedStatePromise(this.dpDesiredTemperature, this.thresholdTemperatureDivisor))
            .onSet(v => this.setTargetThresholdTemperature(v));

        this.characteristicHeatingThresholdTemperature = characteristicHeatingThresholdTemperature;

        this.device.on('change', (changes, state) => {
            if (changes.hasOwnProperty(this.dpActive)) {
                const newActive = this._getActive(changes[this.dpActive]);
                if (characteristicActive.value !== newActive) {
                    characteristicActive.updateValue(newActive);
                }
            }

            if (changes.hasOwnProperty(this.dpDesiredTemperature)) {
                if (characteristicHeatingThresholdTemperature.value !== changes[this.dpDesiredTemperature])
                    characteristicHeatingThresholdTemperature.updateValue(changes[this.dpDesiredTemperature * this.targetTemperatureDivisor]);
            }

            if (changes.hasOwnProperty(this.dpCurrentTemperature) && characteristicCurrentTemperature.value !== changes[this.dpCurrentTemperature]) characteristicCurrentTemperature.updateValue(this._getDividedState(changes[this.dpCurrentTemperature], this.temperatureDivisor));

            this.log.info('SimpleHeater changed: ' + JSON.stringify(state));
        });
    }

    getActive() {
        return this._getActive(this.device.state[this.dpActive]);
    }

    _getActive(dp) {
        const {Characteristic} = this.hap;
        return dp ? Characteristic.Active.ACTIVE : Characteristic.Active.INACTIVE;
    }

    setActive(value) {
        const {Characteristic} = this.hap;

        switch (value) {
            case Characteristic.Active.ACTIVE:
                return this.setStatePromise(this.dpActive, true);

            case Characteristic.Active.INACTIVE:
                return this.setStatePromise(this.dpActive, false);
        }
    }

    getCurrentHeaterCoolerState() {
        return this._getCurrentHeaterCoolerState(this.device.state);
    }

    _getCurrentHeaterCoolerState(dps) {
        const {Characteristic} = this.hap;
        return dps[this.dpActive] ? Characteristic.CurrentHeaterCoolerState.HEATING : Characteristic.CurrentHeaterCoolerState.INACTIVE;
    }

    getTargetHeaterCoolerState() {
        return this._getTargetHeaterCoolerState();
    }

    _getTargetHeaterCoolerState() {
        const {Characteristic} = this.hap;
        return Characteristic.TargetHeaterCoolerState.HEAT;
    }

    setTargetHeaterCoolerState(value) {
        return this.setStatePromise(this.dpActive, true);
    }

    setTargetThresholdTemperature(value) {
        return this.setStatePromise(this.dpDesiredTemperature, value * this.thresholdTemperatureDivisor);
    }
}

module.exports = SimpleHeaterAccessory;
