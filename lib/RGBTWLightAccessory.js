const BaseAccessory = require('./BaseAccessory');

class RGBTWLightAccessory extends BaseAccessory {
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
        this.dpMode = this._getCustomDP(this.device.context.dpMode) || '2';
        this.dpBrightness = this._getCustomDP(this.device.context.dpBrightness) || '3';
        this.dpColorTemperature = this._getCustomDP(this.device.context.dpColorTemperature) || '4';
        this.dpColor = this._getCustomDP(this.device.context.dpColor) || '5';

        this._detectColorFunction(dps[this.dpColor]);

        this.cmdWhite = 'white';
        if (this.device.context.cmdWhite) {
            if (/^w[a-z]+$/i.test(this.device.context.cmdWhite)) this.cmdWhite = ('' + this.device.context.cmdWhite).trim();
            else throw new Error(`The cmdWhite doesn't appear to be valid: ${this.device.context.cmdWhite}`);
        }

        this.cmdColor = 'colour';
        if (this.device.context.cmdColor) {
            if (/^c[a-z]+$/i.test(this.device.context.cmdColor)) this.cmdColor = ('' + this.device.context.cmdColor).trim();
            else throw new Error(`The cmdColor doesn't appear to be valid: ${this.device.context.cmdColor}`);
        } else if (this.device.context.cmdColour) {
            if (/^c[a-z]+$/i.test(this.device.context.cmdColour)) this.cmdColor = ('' + this.device.context.cmdColour).trim();
            else throw new Error(`The cmdColour doesn't appear to be valid: ${this.device.context.cmdColour}`);
        }

        const characteristicOn = service.getCharacteristic(Characteristic.On)
            .updateValue(dps[this.dpPower])
            .onGet(() => this.getStatePromise(this.dpPower))
            .onSet(v => this.setStatePromise(this.dpPower, v));

        const characteristicBrightness = service.getCharacteristic(Characteristic.Brightness)
            .updateValue(dps[this.dpMode] === this.cmdWhite ? this.convertBrightnessFromTuyaToHomeKit(dps[this.dpBrightness]) : this.convertColorFromTuyaToHomeKit(dps[this.dpColor]).b)
            .onGet(() => this.getBrightness())
            .onSet(v => this.setBrightness(v));

        const characteristicColorTemperature = service.getCharacteristic(Characteristic.ColorTemperature)
            .setProps({
                minValue: 0,
                maxValue: 600
            })
            .updateValue(dps[this.dpMode] === this.cmdWhite ? this.convertColorTemperatureFromTuyaToHomeKit(dps[this.dpColorTemperature]) : 0)
            .onGet(() => this.getColorTemperature())
            .onSet(v => this.setColorTemperature(v));

        const characteristicHue = service.getCharacteristic(Characteristic.Hue)
            .updateValue(dps[this.dpMode] === this.cmdWhite ? 0 : this.convertColorFromTuyaToHomeKit(dps[this.dpColor]).h)
            .onGet(() => this.getHue())
            .onSet(v => this.setHue(v));

        const characteristicSaturation = service.getCharacteristic(Characteristic.Saturation)
            .updateValue(dps[this.dpMode] === this.cmdWhite ? 0 : this.convertColorFromTuyaToHomeKit(dps[this.dpColor]).s)
            .onGet(() => this.getSaturation())
            .onSet(v => this.setSaturation(v));

        this.characteristicHue = characteristicHue;
        this.characteristicSaturation = characteristicSaturation;
        this.characteristicColorTemperature = characteristicColorTemperature;

        if (this.adaptiveLightingSupport()) {
            this.adaptiveLightingController = new AdaptiveLightingController(service);
            this.accessory.configureController(this.adaptiveLightingController);
            this.accessory.adaptiveLightingController = this.adaptiveLightingController;
        }

        this.device.on('change', (changes, state) => {
            if (changes.hasOwnProperty(this.dpPower) && characteristicOn.value !== changes[this.dpPower]) characteristicOn.updateValue(changes[this.dpPower]);

            switch (state[this.dpMode]) {
                case this.cmdWhite:
                    if (changes.hasOwnProperty(this.dpBrightness) && this.convertBrightnessFromHomeKitToTuya(characteristicBrightness.value) !== changes[this.dpBrightness])
                        characteristicBrightness.updateValue(this.convertBrightnessFromTuyaToHomeKit(changes[this.dpBrightness]));

                    if (changes.hasOwnProperty(this.dpColorTemperature) && this.convertColorTemperatureFromHomeKitToTuya(characteristicColorTemperature.value) !== changes[this.dpColorTemperature]) {

                        const newColorTemperature = this.convertColorTemperatureFromTuyaToHomeKit(changes[this.dpColorTemperature]);
                        const newColor = this.convertHomeKitColorTemperatureToHomeKitColor(newColorTemperature);

                        characteristicHue.updateValue(newColor.h);
                        characteristicSaturation.updateValue(newColor.s);
                        characteristicColorTemperature.updateValue(newColorTemperature);

                    } else if (changes[this.dpMode] && !changes.hasOwnProperty(this.dpColorTemperature)) {

                        const newColorTemperature = this.convertColorTemperatureFromTuyaToHomeKit(state[this.dpColorTemperature]);
                        const newColor = this.convertHomeKitColorTemperatureToHomeKitColor(newColorTemperature);

                        characteristicHue.updateValue(newColor.h);
                        characteristicSaturation.updateValue(newColor.s);
                        characteristicColorTemperature.updateValue(newColorTemperature);
                    }

                    break;

                default:
                    if (changes.hasOwnProperty(this.dpColor)) {
                        const oldColor = this.convertColorFromTuyaToHomeKit(this.convertColorFromHomeKitToTuya({
                            h: characteristicHue.value,
                            s: characteristicSaturation.value,
                            b: characteristicBrightness.value
                        }));
                        const newColor = this.convertColorFromTuyaToHomeKit(changes[this.dpColor]);

                        if (oldColor.b !== newColor.b) characteristicBrightness.updateValue(newColor.b);
                        if (oldColor.h !== newColor.h) characteristicHue.updateValue(newColor.h);

                        if (oldColor.s !== newColor.s) characteristicSaturation.updateValue(newColor.h);

                        if (characteristicColorTemperature.value !== 0) characteristicColorTemperature.updateValue(0);

                    } else if (changes[this.dpMode]) {
                        if (characteristicColorTemperature.value !== 0) characteristicColorTemperature.updateValue(0);
                    }
            }
        });
    }

    getBrightness() {
        if (this.device.state[this.dpMode] === this.cmdWhite) return this.convertBrightnessFromTuyaToHomeKit(this.device.state[this.dpBrightness]);
        return this.convertColorFromTuyaToHomeKit(this.device.state[this.dpColor]).b;
    }

    setBrightness(value) {
        if (this.device.state[this.dpMode] === this.cmdWhite) return this.setStatePromise(this.dpBrightness, this.convertBrightnessFromHomeKitToTuya(value));
        this.setStatePromise(this.dpColor, this.convertColorFromHomeKitToTuya({b: value}));
    }

    getColorTemperature() {
        if (this.device.state[this.dpMode] !== this.cmdWhite) return 0;
        return this.convertColorTemperatureFromTuyaToHomeKit(this.device.state[this.dpColorTemperature]);
    }

    setColorTemperature(value) {
        this.log.debug(`setColorTemperature: ${value}`);
        if (value === 0) return;

        const newColor = this.convertHomeKitColorTemperatureToHomeKitColor(value);
        this.characteristicHue.updateValue(newColor.h);
        this.characteristicSaturation.updateValue(newColor.s);

        this.setMultiStatePromise({[this.dpMode]: this.cmdWhite, [this.dpColorTemperature]: this.convertColorTemperatureFromHomeKitToTuya(value)});
    }

    getHue() {
        if (this.device.state[this.dpMode] === this.cmdWhite) return 0;
        return this.convertColorFromTuyaToHomeKit(this.device.state[this.dpColor]).h;
    }

    setHue(value) {
        return this._setHueSaturation({h: value});
    }

    getSaturation() {
        if (this.device.state[this.dpMode] === this.cmdWhite) return 0;
        return this.convertColorFromTuyaToHomeKit(this.device.state[this.dpColor]).s;
    }

    setSaturation(value) {
        return this._setHueSaturation({s: value});
    }

    _setHueSaturation(prop) {
        if (!this._pendingHueSaturation) {
            this._pendingHueSaturation = {props: {}, resolvers: []};
        }

        if (prop) {
            if (this._pendingHueSaturation.timer) clearTimeout(this._pendingHueSaturation.timer);

            this._pendingHueSaturation.props = {...this._pendingHueSaturation.props, ...prop};
            const p = new Promise(resolve => this._pendingHueSaturation.resolvers.push(resolve));

            this._pendingHueSaturation.timer = setTimeout(() => {
                this._setHueSaturation();
            }, 500);
            return p;
        }

        const resolvers = this._pendingHueSaturation.resolvers;
        const resolveAll = () => {
            resolvers.forEach(r => r());
            this.characteristicColorTemperature.updateValue(0);
        };

        const isSham = this._pendingHueSaturation.props.h === 0 && this._pendingHueSaturation.props.s === 0;
        const newValue = this.convertColorFromHomeKitToTuya(this._pendingHueSaturation.props);
        this._pendingHueSaturation = null;

        if (this.device.state[this.dpMode] === this.cmdWhite && isSham) return resolveAll();

        this.setMultiStatePromise({[this.dpMode]: this.cmdColor, [this.dpColor]: newValue});
        resolveAll();
    }

    getControllers() {
        if (!this.adaptiveLightingController) {
            return [];
        } else {
            return [this.adaptiveLightingController];
        }
    }
}

module.exports = RGBTWLightAccessory;
