const BaseAccessory = require('./BaseAccessory');

class OccupancySensorAccessory extends BaseAccessory {
    static getCategory(Categories) {
        return Categories.SENSOR;
    }

    constructor(...props) {
        super(...props);
    }

    _registerPlatformAccessory() {
        const {Service} = this.hap;

        this.accessory.addService(Service.OccupancySensor, this.device.context.name);
        this.accessory.addService(Service.LightSensor, this.device.context.name + " Light");

        super._registerPlatformAccessory();
    }

    _registerCharacteristics(dps) {
        const {Service, Characteristic} = this.hap;
        const occupancyService = this.accessory.getService(Service.OccupancySensor);
        const lightService = this.accessory.getService(Service.LightSensor);

        this._checkServiceName(occupancyService, this.device.context.name);
        this._checkServiceName(lightService, this.device.context.name + " Light");

        this.dpOccupancy = this._getCustomDP(this.device.context.dpOccupancy) || '1';
        this.dpLight = this._getCustomDP(this.device.context.dpLight) || '104';

        const characteristicOccupancy = occupancyService.getCharacteristic(Characteristic.OccupancyDetected)
            .updateValue(dps[this.dpOccupancy] === 'presence' ? Characteristic.OccupancyDetected.OCCUPANCY_DETECTED : Characteristic.OccupancyDetected.OCCUPANCY_NOT_DETECTED)
            .onGet(() => this.getOccupancyState(this.dpOccupancy));

        const characteristicLight = lightService.getCharacteristic(Characteristic.CurrentAmbientLightLevel)
            .updateValue(dps[this.dpLight])
            .onGet(() => this.getStatePromise(this.dpLight));

        this.device.on('change', changes => {
            if (changes.hasOwnProperty(this.dpOccupancy) && characteristicOccupancy.value !== (changes[this.dpOccupancy] === 'presence' ? Characteristic.OccupancyDetected.OCCUPANCY_DETECTED : Characteristic.OccupancyDetected.OCCUPANCY_NOT_DETECTED)) {
                characteristicOccupancy.updateValue(changes[this.dpOccupancy] === 'presence' ? Characteristic.OccupancyDetected.OCCUPANCY_DETECTED : Characteristic.OccupancyDetected.OCCUPANCY_NOT_DETECTED);
            }

            if (changes.hasOwnProperty(this.dpLight) && characteristicLight.value !== changes[this.dpLight]) {
                characteristicLight.updateValue(changes[this.dpLight]);
            }
        });
    }

    getOccupancyState(dp) {
        const {Characteristic} = this.hap;
        return this.device.state[dp] === 'presence' ? Characteristic.OccupancyDetected.OCCUPANCY_DETECTED : Characteristic.OccupancyDetected.OCCUPANCY_NOT_DETECTED;
    }
}

module.exports = OccupancySensorAccessory;