'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const shop = require('../lib/orders');
const pagopar = require('../lib/pagopar');

test('haversine Asunción to Luque is within Motobolt range', () => {
    const km = shop.haversineKm(-25.28646, -57.647, -25.267, -57.484);
    assert.ok(km > 5 && km < 40, `unexpected km ${km}`);
});

test('interior city does not get Motobolt', () => {
    const info = shop.shippingOptions({
        lat: -27.33, lng: -55.86, city: 'Encarnación',
        siteConfig: { storeLat: -25.28646, storeLng: -57.647, motoboltMaxKm: 40 }
    });
    const ids = info.options.map((o) => o.id);
    assert.ok(!ids.includes('motobolt') || info.far);
    assert.ok(ids.includes('transportadora'));
    assert.ok(ids.includes('retiro'));
    assert.equal(ids.filter((i) => i === 'motobolt').length, info.central ? 1 : 0);
});

test('central city offers Motobolt', () => {
    const info = shop.shippingOptions({
        lat: -25.286, lng: -57.64, city: 'Asunción',
        siteConfig: { storeLat: -25.28646, storeLng: -57.647, motoboltMaxKm: 40 }
    });
    assert.equal(info.central, true);
    assert.ok(info.options.some((o) => o.id === 'motobolt'));
});

test('efectivo only makes sense with retiro (enforced in route, shipping still lists retiro)', () => {
    const info = shop.shippingOptions({ city: 'Luque', lat: -25.27, lng: -57.49, siteConfig: {} });
    assert.ok(info.options.some((o) => o.id === 'retiro'));
});

test('pagopar tokens are sha1 hex', () => {
    process.env.PAGOPAR_PRIVATE_KEY = 'secret';
    process.env.PAGOPAR_PUBLIC_KEY = 'pub';
    const t = pagopar.tokenIniciar('abc', 10000);
    assert.equal(t.length, 40);
    assert.equal(pagopar.tokenConsulta().length, 40);
    assert.equal(pagopar.tokenWebhook('hash1').length, 40);
    assert.equal(pagopar.timingSafeEqual(pagopar.tokenWebhook('hash1'), pagopar.tokenWebhook('hash1')), true);
});

test('parsePrice strips thousand dots', () => {
    assert.equal(shop.parsePrice('25.000'), 25000);
    assert.equal(shop.parsePrice(25000), 25000);
});
