'use strict';

/**
 * Medios de pago de FERUMI.
 * La pasarela online queda como un proveedor enchufable: hoy no hay ninguno activo.
 * Transferencia y efectivo siguen operando sin depender de un tercero.
 */

const METHODS = {
    transferencia: {
        id: 'transferencia',
        label: 'Transferencia bancaria',
        public: true,
        needsReceipt: true,
        online: false
    },
    efectivo_retiro: {
        id: 'efectivo_retiro',
        label: 'Efectivo al retirar',
        public: true,
        needsReceipt: false,
        online: false,
        pickupOnly: true
    },
    efectivo: {
        id: 'efectivo',
        label: 'Efectivo',
        public: true,
        needsReceipt: false,
        online: false
    },
    mixto: {
        id: 'mixto',
        label: 'Pago mixto',
        public: false,
        needsReceipt: true,
        online: false
    },
    online: {
        id: 'online',
        label: 'Pago online',
        public: false,
        needsReceipt: false,
        online: true
    }
};

const providers = [];

function registerProvider(provider) {
    if (!provider || !provider.id) throw new Error('El proveedor de pago necesita un id.');
    const existing = providers.findIndex((item) => item.id === provider.id);
    if (existing >= 0) providers.splice(existing, 1, provider);
    else providers.push(provider);
}

function activeProvider() {
    return providers.find((provider) => {
        try { return provider.configured() === true; } catch (err) { return false; }
    }) || null;
}

function onlineAvailable() {
    return Boolean(activeProvider());
}

function isKnown(method) {
    return Boolean(METHODS[String(method || '')]);
}

function label(method) {
    return METHODS[String(method || '')]?.label || 'Pago a coordinar';
}

function methodsForShipping(shippingMethod) {
    const list = ['transferencia'];
    if (shippingMethod === 'retiro') list.push('efectivo_retiro');
    if (onlineAvailable()) list.unshift('online');
    return list.map((id) => METHODS[id]);
}

function chargeTotal(subtotal, shipping = 0) {
    const goods = Math.round(Number(subtotal) || 0);
    const ship = Math.round(Number(shipping) || 0);
    return Math.max(0, goods + ship);
}

function assertCheckoutMethod(paymentMethod, shippingMethod) {
    const method = String(paymentMethod || '');
    if (method === 'online' && !onlineAvailable()) {
        return { ok: false, message: 'El pago con tarjeta o QR no está disponible. Podés transferir o, si retirás, pagar en efectivo.' };
    }
    if (!METHODS[method] || method === 'mixto') {
        return { ok: false, message: 'Elegí transferencia o efectivo al retirar.' };
    }
    if ((method === 'efectivo_retiro' || method === 'efectivo') && shippingMethod !== 'retiro') {
        return { ok: false, message: 'El efectivo solo está disponible si retirás en Ferumishop.' };
    }
    return { ok: true, method: method === 'efectivo' ? 'efectivo_retiro' : method };
}

module.exports = {
    METHODS,
    registerProvider,
    activeProvider,
    onlineAvailable,
    isKnown,
    label,
    methodsForShipping,
    chargeTotal,
    assertCheckoutMethod
};
