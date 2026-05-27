const BaseAccessory = require('./BaseAccessory');

class SimpleFanLightAccessory extends BaseAccessory {
    static getCategory(Categories) {
        return Categories.FANLIGHT;
    }

    constructor(...props) {
        super(...props);
    }

    _registerPlatformAccessory() {
        const {Service} = this.hap;
        this.accessory.addService(Service.Fan, this.device.context.name);
        this.accessory.addService(Service.Lightbulb, this.device.context.name + " Light");
        super._registerPlatformAccessory();
    }

    _registerCharacteristics(dps) {
        const {Service, Characteristic} = this.hap;
        const serviceFan = this.accessory.getService(Service.Fan);
        const serviceLightbulb = this.accessory.getService(Service.Lightbulb);
        this._checkServiceName(serviceFan, this.device.context.name);
        this._checkServiceName(serviceLightbulb, this.device.context.name + " Light");
        this.dpFanOn = this._getCustomDP(this.device.context.dpFanOn) || '1';
        this.dpRotationSpeed = this._getCustomDP(this.device.context.dpRotationSpeed) || '3';
        this.dpLightOn = this._getCustomDP(this.device.context.dpLightOn) || '9';
        this.dpBrightness = this._getCustomDP(this.device.context.dpBrightness) || '10';
        this.useLight = this._coerceBoolean(this.device.context.useLight, true);
        this.useBrightness = this._coerceBoolean(this.device.context.useBrightness, false);
        this.maxSpeed = parseInt(this.device.context.maxSpeed) || 3;
        // This variable is here so that we can set the fans to turn onto speed one instead of 3 on start.
        this.fanDefaultSpeed = parseInt(this.device.context.fanDefaultSpeed) || 1;
        // This variable is here as a workaround to allow for the on/off function to work.
        this.fanCurrentSpeed = 0;
        // Add setting to use .toString() on return values or not.
        this.useStrings = this._coerceBoolean(this.device.context.useStrings, true);

        const characteristicFanOn = serviceFan.getCharacteristic(Characteristic.On)
            .updateValue(this._getFanOn(dps[this.dpFanOn]))
            .onGet(() => this.getFanOn())
            .onSet(v => this.setFanOn(v));

        const characteristicRotationSpeed = serviceFan.getCharacteristic(Characteristic.RotationSpeed)
            .setProps({
                minValue: 0,
                maxValue: 100,
                minStep: Math.max(100 / this.maxSpeed)
            })
            .updateValue(this.convertRotationSpeedFromTuyaToHomeKit(dps[this.dpRotationSpeed]))
            .onGet(() => this.getSpeed())
            .onSet(v => this.setSpeed(v));

        let characteristicLightOn;
        let characteristicBrightness;
        if (this.useLight) {
            characteristicLightOn = serviceLightbulb.getCharacteristic(Characteristic.On)
                .updateValue(this._getLightOn(dps[this.dpLightOn]))
                .onGet(() => this.getLightOn())
                .onSet(v => this.setLightOn(v));

            if (this.useBrightness) {
                characteristicBrightness = serviceLightbulb.getCharacteristic(Characteristic.Brightness)
                    .setProps({
                        minValue: 0,
                        maxValue: 1000,
                        minStep: 100
                    })
                    .updateValue(this.convertBrightnessFromTuyaToHomeKit(dps[this.dpBrightness]))
                    .onGet(() => this.getBrightness())
                    .onSet(v => this.setBrightness(v));
            }
        }

        this.device.on('change', (changes, state) => {
            if (changes.hasOwnProperty(this.dpFanOn) && characteristicFanOn.value !== changes[this.dpFanOn])
                characteristicFanOn.updateValue(changes[this.dpFanOn]);

            if (changes.hasOwnProperty(this.dpRotationSpeed) && this.convertRotationSpeedFromHomeKitToTuya(characteristicRotationSpeed.value) !== changes[this.dpRotationSpeed])
                characteristicRotationSpeed.updateValue(this.convertRotationSpeedFromTuyaToHomeKit(changes[this.dpRotationSpeed]));

            if (changes.hasOwnProperty(this.dpLightOn) && characteristicLightOn && characteristicLightOn.value !== changes[this.dpLightOn])
                characteristicLightOn.updateValue(changes[this.dpLightOn]);

            if (changes.hasOwnProperty(this.dpBrightness) && characteristicBrightness && characteristicBrightness.value !== changes[this.dpBrightness])
                characteristicBrightness.updateValue(changes[this.dpBrightness]);

            this.log.debug('SimpleFanLight changed: ' + JSON.stringify(state));
        });
    }

    /*************************** FAN ***************************/
    // Get the Current Fan State
    getFanOn() {
        return this._getFanOn(this.device.state[this.dpFanOn]);
    }

    _getFanOn(dp) {
        return dp;
    }

    setFanOn(value) {
        // This uses the multistatelegacy set command to send the fan on and speed request in one call.
        if (value == false ) {
          this.fanCurrentSpeed = 0;
          // This will turn off the fan speed if it is set to be 0.
          return this.setStatePromise(this.dpFanOn, false);
        } else {
          if (this.fanCurrentSpeed === 0) {
            // The current fanDefaultSpeed Variable is there to have the fan set to a sensible default if turned on.
            if (this.useStrings) {
                return this.setMultiStateLegacyPromise({[this.dpFanOn]: value, [this.dpRotationSpeed]: this.fanDefaultSpeed.toString()});
            } else {
                return this.setMultiStateLegacyPromise({[this.dpFanOn]: value, [this.dpRotationSpeed]: this.fanDefaultSpeed});
            }
          } else {
            // The current fanCurrentSpeed Variable is there to ensure the fan speed doesn't change if the fan is already on.
            if (this.useStrings) {
              return this.setMultiStateLegacyPromise({[this.dpFanOn]: value, [this.dpRotationSpeed]: this.fanCurrentSpeed.toString()});
            } else {
              return this.setMultiStateLegacyPromise({[this.dpFanOn]: value, [this.dpRotationSpeed]: this.fanCurrentSpeed});
            }
          }
        }
    }

    // Get the Current Fan Speed
    getSpeed() {
        return this.convertRotationSpeedFromTuyaToHomeKit(this.device.state[this.dpRotationSpeed]);
    }

    // Set the new fan speed
    setSpeed(value) {
      if (value === 0) {
        // This is to set the fan speed variable to be 1 when the fan is off.
        if (this.useStrings) {
            return this.setMultiStateLegacyPromise({[this.dpFanOn]: false, [this.dpRotationSpeed]: this.fanDefaultSpeed.toString()});
        } else {
            return this.setMultiStateLegacyPromise({[this.dpFanOn]: false, [this.dpRotationSpeed]: this.fanDefaultSpeed});
        }
      } else {
        // This is to set the fan speed variable to match the current speed.
        this.fanCurrentSpeed = this.convertRotationSpeedFromHomeKitToTuya(value);
        // This uses the multistatelegacy set command to send the fan on and speed request in one call.
        if (this.useStrings) {
            return this.setMultiStateLegacyPromise({[this.dpFanOn]: true, [this.dpRotationSpeed]: this.convertRotationSpeedFromHomeKitToTuya(value).toString()});
        } else {
            return this.setMultiStateLegacyPromise({[this.dpFanOn]: true, [this.dpRotationSpeed]: this.convertRotationSpeedFromHomeKitToTuya(value)});
        }
      }
    }

    /*************************** LIGHT ***************************/
    //Lightbulb State
    getLightOn() {
        return this._getLightOn(this.device.state[this.dpLightOn]);
    }

    _getLightOn(dp) {
        return dp;
    }

    setLightOn(value) {
        return this.setStatePromise(this.dpLightOn, value);
    }

    //Lightbulb Brightness
    getBrightness() {
        return this.device.state[this.dpBrightness];
    }

    setBrightness(value) {
        return this.setStatePromise(this.dpBrightness, value);
    }
}

module.exports = SimpleFanLightAccessory;
