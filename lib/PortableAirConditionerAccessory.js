const BaseAccessory = require('./BaseAccessory');

const STATE_OTHER = 9;
const STATE_DRY   = 3;
const STATE_FAN   = 4;

// Tuya category: ydkt (Portable Air Conditioner)
// DP mapping (verified from real device data):
//   1   -> Power (boolean)
//   2   -> Set Temperature (number, °C)
//   3   -> Current Temperature (number, °C)
//  17   -> Max temperature limit (e.g. 32)
//  20   -> Fault code (0 = no fault)
//  101  -> Mode (string: "1"=Cool, "2"=Heat, "3"=Dry, "4"=Auto, "5"=Fan)
//  103  -> Sleep mode (boolean)
//  104  -> Fan Speed (string: "1"=High, "3"=Low)
//  105  -> Timer (number, minutes, 0=off) – not mapped
//  106  -> ignored
//  109  -> ignored
//  112  -> ignored

class PortableAirConditionerAccessory extends BaseAccessory {
    static getCategory(Categories) {
        return Categories.AIR_CONDITIONER;
    }

    constructor(...props) {
        super(...props);

        // Mode command strings – verified from real device data
        this.cmdCool = '1';
        if (this.device.context.cmdCool) {
            if (/^\S+$/.test(this.device.context.cmdCool)) this.cmdCool = ('' + this.device.context.cmdCool).trim();
            else throw new Error('The cmdCool doesn\'t appear to be valid: ' + this.device.context.cmdCool);
        }

        this.cmdHeat = '2';
        if (this.device.context.cmdHeat) {
            if (/^\S+$/.test(this.device.context.cmdHeat)) this.cmdHeat = ('' + this.device.context.cmdHeat).trim();
            else throw new Error('The cmdHeat doesn\'t appear to be valid: ' + this.device.context.cmdHeat);
        }

        this.cmdDry = '3';
        if (this.device.context.cmdDry) {
            if (/^\S+$/.test(this.device.context.cmdDry)) this.cmdDry = ('' + this.device.context.cmdDry).trim();
            else throw new Error('The cmdDry doesn\'t appear to be valid: ' + this.device.context.cmdDry);
        }

        this.cmdAuto = '4';
        if (this.device.context.cmdAuto) {
            if (/^\S+$/.test(this.device.context.cmdAuto)) this.cmdAuto = ('' + this.device.context.cmdAuto).trim();
            else throw new Error('The cmdAuto doesn\'t appear to be valid: ' + this.device.context.cmdAuto);
        }

        this.cmdFan = '5';
        if (this.device.context.cmdFan) {
            if (/^\S+$/.test(this.device.context.cmdFan)) this.cmdFan = ('' + this.device.context.cmdFan).trim();
            else throw new Error('The cmdFan doesn\'t appear to be valid: ' + this.device.context.cmdFan);
        }

        // Fan speed levels: 3 = Low/Mid/High (default), 2 = Low/High only
        this._fanSpeeds = (this.device.context.fanSpeeds === 2) ? 2 : 3;
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

        this.dpActive             = this._getCustomDP(this.device.context.dpActive)            || '1';
        this.dpThreshold          = this._getCustomDP(this.device.context.dpThreshold)         || '2';
        this.dpCurrentTemperature = this._getCustomDP(this.device.context.dpCurrentTemperature)|| '3';
        this.dpMode               = this._getCustomDP(this.device.context.dpMode)              || '101';
        this.dpSleep              = this._getCustomDP(this.device.context.dpSleep)             || '103';
        this.dpFanSpeed           = this._getCustomDP(this.device.context.dpFanSpeed)          || '104';

        this.log.debug('[PortableAC] Initial DPs: %s', JSON.stringify(dps));
        this.log.debug('[PortableAC] DP mapping: active=%s threshold=%s currentTemp=%s mode=%s sleep=%s fanSpeed=%s',
            this.dpActive, this.dpThreshold, this.dpCurrentTemperature,
            this.dpMode, this.dpSleep, this.dpFanSpeed);

        // --- Active ---
        const characteristicActive = service.getCharacteristic(Characteristic.Active)
            .updateValue(this._getActive(dps[this.dpActive]))
            .on('get', this.getActive.bind(this))
            .on('set', this.setActive.bind(this));

        // --- CurrentHeaterCoolerState ---
        const characteristicCurrentHeaterCoolerState = service.getCharacteristic(Characteristic.CurrentHeaterCoolerState)
            .updateValue(this._getCurrentHeaterCoolerState(dps))
            .on('get', this.getCurrentHeaterCoolerState.bind(this));

        // --- TargetHeaterCoolerState: AUTO(0), HEAT(1), COOL(2), DRY(3), FAN(4) ---
        // Modes can be disabled via: noAuto, noHeat, noDry, noFanMode in device context
        const _validModes = [Characteristic.TargetHeaterCoolerState.COOL];
        if (!this.device.context.noHeat)    _validModes.push(Characteristic.TargetHeaterCoolerState.HEAT);
        if (!this.device.context.noAuto)    _validModes.push(Characteristic.TargetHeaterCoolerState.AUTO);
        if (!this.device.context.noDry)     _validModes.push(STATE_DRY);
        if (!this.device.context.noFanMode) _validModes.push(STATE_FAN);

        const characteristicTargetHeaterCoolerState = service.getCharacteristic(Characteristic.TargetHeaterCoolerState)
            .setProps({maxValue: 9, validValues: _validModes})
            .updateValue(this._getTargetHeaterCoolerState(dps[this.dpMode]))
            .on('get', this.getTargetHeaterCoolerState.bind(this))
            .on('set', this.setTargetHeaterCoolerState.bind(this));

        // --- CurrentTemperature ---
        const characteristicCurrentTemperature = service.getCharacteristic(Characteristic.CurrentTemperature)
            .updateValue(dps[this.dpCurrentTemperature])
            .on('get', this.getState.bind(this, this.dpCurrentTemperature));

        // --- CoolingThresholdTemperature ---
        const characteristicCoolingThresholdTemperature = service.getCharacteristic(Characteristic.CoolingThresholdTemperature)
            .setProps({
                minValue: this.device.context.minTemperature || 16,
                maxValue: this.device.context.maxTemperature || 32,
                minStep:  this.device.context.minTemperatureSteps || 1
            })
            .updateValue(dps[this.dpThreshold])
            .on('get', this.getState.bind(this, this.dpThreshold))
            .on('set', this.setTargetThresholdTemperature.bind(this));

        // --- HeatingThresholdTemperature (for HEAT mode) ---
        const characteristicHeatingThresholdTemperature = service.getCharacteristic(Characteristic.HeatingThresholdTemperature)
            .setProps({
                minValue: this.device.context.minTemperature || 16,
                maxValue: this.device.context.maxTemperature || 32,
                minStep:  this.device.context.minTemperatureSteps || 1
            })
            .updateValue(dps[this.dpThreshold])
            .on('get', this.getState.bind(this, this.dpThreshold))
            .on('set', this.setTargetThresholdTemperature.bind(this));

        // --- RotationSpeed (fan speed: "1"=High/100%, "2"=Mid/66%, "3"=Low/33%) ---
        const characteristicRotationSpeed = service.getCharacteristic(Characteristic.RotationSpeed)
            .setProps({minValue: 0, maxValue: 100, minStep: 1})
            .updateValue(this._getFanSpeedPercent(dps[this.dpFanSpeed]))
            .on('get', this.getFanSpeed.bind(this))
            .on('set', this.setFanSpeed.bind(this));

        // Child lock, temperature display units and swing not available on this device
        this._removeCharacteristic(service, Characteristic.LockPhysicalControls);
        this._removeCharacteristic(service, Characteristic.TemperatureDisplayUnits);
        this._removeCharacteristic(service, Characteristic.SwingMode);

        // --- Change listener ---
        this.device.on('change', (changes, state) => {
            this.log.debug('[PortableAC] change event - changes: %s', JSON.stringify(changes));
            this.log.debug('[PortableAC] change event - full state: %s', JSON.stringify(state));
            if (changes.hasOwnProperty(this.dpActive)) {
                const newActive = this._getActive(changes[this.dpActive]);
                if (characteristicActive.value !== newActive) {
                    characteristicActive.updateValue(newActive);
                }
                if (!changes.hasOwnProperty(this.dpMode)) {
                    characteristicCurrentHeaterCoolerState.updateValue(this._getCurrentHeaterCoolerState(state));
                }
            }

            if (changes.hasOwnProperty(this.dpThreshold)) {
                if (characteristicCoolingThresholdTemperature.value !== changes[this.dpThreshold])
                    characteristicCoolingThresholdTemperature.updateValue(changes[this.dpThreshold]);
                if (characteristicHeatingThresholdTemperature.value !== changes[this.dpThreshold])
                    characteristicHeatingThresholdTemperature.updateValue(changes[this.dpThreshold]);
            }

            if (changes.hasOwnProperty(this.dpCurrentTemperature) && characteristicCurrentTemperature.value !== changes[this.dpCurrentTemperature]) {
                characteristicCurrentTemperature.updateValue(changes[this.dpCurrentTemperature]);
            }

            if (changes.hasOwnProperty(this.dpMode)) {
                const newTargetState  = this._getTargetHeaterCoolerState(changes[this.dpMode]);
                const newCurrentState = this._getCurrentHeaterCoolerState(state);
                if (characteristicTargetHeaterCoolerState.value !== newTargetState)   characteristicTargetHeaterCoolerState.updateValue(newTargetState);
                if (characteristicCurrentHeaterCoolerState.value !== newCurrentState) characteristicCurrentHeaterCoolerState.updateValue(newCurrentState);
            }

            if (changes.hasOwnProperty(this.dpFanSpeed)) {
                const newSpeed = this._getFanSpeedPercent(changes[this.dpFanSpeed]);
                if (characteristicRotationSpeed.value !== newSpeed) characteristicRotationSpeed.updateValue(newSpeed);
            }
        });
    }

    // ── Active ──────────────────────────────────────────────────────────────

    getActive(callback) {
        this.getState(this.dpActive, (err, dp) => {
            if (err) return callback(err);
            callback(null, this._getActive(dp));
        });
    }

    _getActive(dp) {
        const {Characteristic} = this.hap;
        return dp ? Characteristic.Active.ACTIVE : Characteristic.Active.INACTIVE;
    }

    setActive(value, callback) {
        const {Characteristic} = this.hap;
        this.log.debug('[PortableAC] setActive: %s', value);
        switch (value) {
            case Characteristic.Active.ACTIVE:
                return this.setState(this.dpActive, true, callback);
            case Characteristic.Active.INACTIVE:
                return this.setState(this.dpActive, false, callback);
        }
        callback();
    }

    // ── CurrentHeaterCoolerState ─────────────────────────────────────────────

    getCurrentHeaterCoolerState(callback) {
        this.getState([this.dpActive, this.dpMode], (err, dps) => {
            if (err) return callback(err);
            callback(null, this._getCurrentHeaterCoolerState(dps));
        });
    }

    _getCurrentHeaterCoolerState(dps) {
        const {Characteristic} = this.hap;
        if (!dps[this.dpActive]) return Characteristic.CurrentHeaterCoolerState.INACTIVE;

        switch (dps[this.dpMode]) {
            case this.cmdCool:
                return Characteristic.CurrentHeaterCoolerState.COOLING;
            case this.cmdHeat:
                return Characteristic.CurrentHeaterCoolerState.HEATING;
            default:
                return Characteristic.CurrentHeaterCoolerState.IDLE;
        }
    }

    // ── TargetHeaterCoolerState ──────────────────────────────────────────────

    getTargetHeaterCoolerState(callback) {
        this.getState(this.dpMode, (err, dp) => {
            if (err) return callback(err);
            callback(null, this._getTargetHeaterCoolerState(dp));
        });
    }

    _getTargetHeaterCoolerState(dp) {
        const {Characteristic} = this.hap;
        switch (dp) {
            case this.cmdCool: return Characteristic.TargetHeaterCoolerState.COOL;
            case this.cmdHeat: return Characteristic.TargetHeaterCoolerState.HEAT;
            case this.cmdAuto: return Characteristic.TargetHeaterCoolerState.AUTO;
            case this.cmdDry:  return STATE_DRY;
            case this.cmdFan:  return STATE_FAN;
            default:           return STATE_OTHER;
        }
    }

    setTargetHeaterCoolerState(value, callback) {
        const {Characteristic} = this.hap;
        this.log.debug('[PortableAC] setTargetHeaterCoolerState: %s', value);
        switch (value) {
            case Characteristic.TargetHeaterCoolerState.COOL: return this.setState(this.dpMode, this.cmdCool, callback);
            case Characteristic.TargetHeaterCoolerState.HEAT:
                if (this.device.context.noHeat) return callback();
                return this.setState(this.dpMode, this.cmdHeat, callback);
            case Characteristic.TargetHeaterCoolerState.AUTO:
                if (this.device.context.noAuto) return callback();
                return this.setState(this.dpMode, this.cmdAuto, callback);
            case STATE_DRY:
                if (this.device.context.noDry) return callback();
                return this.setState(this.dpMode, this.cmdDry, callback);
            case STATE_FAN:
                if (this.device.context.noFanMode) return callback();
                return this.setState(this.dpMode, this.cmdFan, callback);
        }
        callback();
    }

    // ── CoolingThresholdTemperature ──────────────────────────────────────────

    setTargetThresholdTemperature(value, callback) {
        this.log.debug('[PortableAC] setTargetThresholdTemperature: %s°C', value);
        this.setState(this.dpThreshold, value, callback);
    }

    // ── Fan Speed ────────────────────────────────────────────────────────────

    getFanSpeed(callback) {
        this.getState(this.dpFanSpeed, (err, dp) => {
            if (err) return callback(err);
            callback(null, this._getFanSpeedPercent(dp));
        });
    }

    _getFanSpeedPercent(dp) {
        // "1"=High, "2"=Mid, "3"=Low (verified from real device data)
        if (this._fanSpeeds === 2) {
            const map = {'1': 100, '3': 33};
            return map['' + dp] !== undefined ? map['' + dp] : 0;
        }
        const map = {'1': 100, '2': 66, '3': 33};
        return map['' + dp] !== undefined ? map['' + dp] : 0;
    }

    setFanSpeed(value, callback) {
        this.log.debug('[PortableAC] setFanSpeed: %s%%', value);
        if (value <= 0) {
            return this.setState(this.dpActive, false, callback);
        }

        let tuyaValue;
        if (this._fanSpeeds === 2) {
            tuyaValue = value <= 50 ? '3' : '1'; // Low / High
        } else {
            if (value <= 33)      tuyaValue = '3'; // Low
            else if (value <= 66) tuyaValue = '2'; // Mid
            else                  tuyaValue = '1'; // High
        }

        this.log.debug('[PortableAC] setFanSpeed -> Tuya value: %s', tuyaValue);
        this.setState(this.dpFanSpeed, tuyaValue, callback);
    }

}

module.exports = PortableAirConditionerAccessory;
