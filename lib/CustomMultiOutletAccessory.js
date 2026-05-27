const BaseAccessory = require('./BaseAccessory');

class CustomMultiOutletAccessory extends BaseAccessory {
    static getCategory(Categories) {
        return Categories.OUTLET;
    }

    constructor(...props) {
        super(...props);
    }

    _registerPlatformAccessory() {
        this._verifyCachedPlatformAccessory();
        this._justRegistered = true;

        super._registerPlatformAccessory();
    }

    _verifyCachedPlatformAccessory() {
        if (this._justRegistered) return;

        const {Service} = this.hap;

        if (!Array.isArray(this.device.context.outlets)) {
            throw new Error('The outlets definition is missing or is malformed: ' + this.device.context.outlets);
        }
        const _validServices = [];
        this.device.context.outlets.forEach((outlet, i) => {
            if (!outlet || !outlet.hasOwnProperty('name') || !outlet.hasOwnProperty('dp') || !isFinite(outlet.dp))
                throw new Error('The outlet definition #${i} is missing or is malformed: ' + outlet);

            const name = ((outlet.name || '').trim() || 'Unnamed') + ' - ' + this.device.context.name;
            let service = this.accessory.getServiceByUUIDAndSubType(Service.Outlet, 'outlet ' + outlet.dp);
            if (service) this._checkServiceName(service, name);
            else service = this.accessory.addService(Service.Outlet, name, 'outlet ' + outlet.dp);

            _validServices.push(service);
        });

        this.accessory.services
            .filter(service => service.UUID === Service.Outlet.UUID && !_validServices.includes(service))
            .forEach(service => {
                this.accessory.removeService(service);
            });
    }

    _registerCharacteristics(dps) {
        this._verifyCachedPlatformAccessory();

        const {Service, Characteristic} = this.hap;

        const characteristics = {};
        this.accessory.services.forEach(service => {
            if (service.UUID !== Service.Outlet.UUID || !service.subtype) return false;

            let match;
            if ((match = service.subtype.match(/^outlet (\d+)$/)) === null) return;

            characteristics[match[1]] = service.getCharacteristic(Characteristic.On)
                .updateValue(dps[match[1]])
                .onGet(() => this.getPower(match[1]))
                .onSet(v => this.setPower(match[1], v));
        });

        this.device.on('change', (changes, state) => {
            Object.keys(changes).forEach(key => {
                if (characteristics[key] && characteristics[key].value !== changes[key]) characteristics[key].updateValue(changes[key]);
            });
        });
    }

    getPower(dp) {
        return this.device.state[dp];
    }

    setPower(dp, value) {
        if (!this._pendingPower) {
            this._pendingPower = {props: {}, resolvers: []};
        }

        if (dp) {
            if (this._pendingPower.timer) clearTimeout(this._pendingPower.timer);

            this._pendingPower.props = {...this._pendingPower.props, ...{[dp]: value}};
            const p = new Promise(resolve => this._pendingPower.resolvers.push(resolve));

            this._pendingPower.timer = setTimeout(() => {
                this.setPower();
            }, 500);
            return p;
        }

        const resolvers = this._pendingPower.resolvers;
        const resolveAll = () => resolvers.forEach(r => r());

        const newValue = this._pendingPower.props;
        this._pendingPower = null;

        this.setMultiStatePromise(newValue);
        resolveAll();
    }
}

module.exports = CustomMultiOutletAccessory;