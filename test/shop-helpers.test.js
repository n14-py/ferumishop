'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const shop = require('../lib/orders');
const pagopar = require('../lib/pagopar');
const r2 = require('../lib/r2');

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

test('thermal ticket QR is dual-use pedido URL', () => {
    const pedido = shop.thermalPedidoFromWebOrder({
        _id: '65f000000000000000000001',
        customerName: 'Ana',
        customerPhone: '0981',
        items: [{ quantity: 1, name: 'Labial', price: 25000 }],
        totalAmount: 25000,
        createdAt: new Date(),
        ticketCode: 'FM-ABC',
        orderNumber: 'FER-1',
        shippingMethod: 'motobolt'
    });
    assert.match(pedido.qrPayload, /\/pedido\/FM-ABC/);
    assert.match(pedido.qrHint, /Motobolt/i);
    assert.equal(pedido.shippingLabel, 'Motobolt');
});

test('scan extracts ticket from URL or FERUMI code', () => {
    assert.equal(shop.extractScanCode('FERUMI|FM-ABC'), 'FM-ABC');
    assert.equal(shop.extractScanCode('https://www.ferumi.shop/pedido/FM-ABC'), 'FM-ABC');
    assert.equal(shop.extractScanCode('https://ferumi.shop/pedido/FM-ABC?x=1'), 'FM-ABC');
});

test('motobolt ready WhatsApp asks to order moto without 1 hour', () => {
    const text = shop.customerWhatsAppText({
        customerName: 'Ana',
        orderNumber: 'FER-1',
        ticketCode: 'FM-ABC',
        totalAmount: 25000,
        items: [{ quantity: 1, name: 'Labial' }]
    }, {}, 'preparado_motobolt');
    assert.match(text, /Pedí tu Motobolt ahora/);
    assert.doesNotMatch(text, /1 hora/);
});

test('scanning QR does not rewind delivered or already prepared orders', () => {
    const delivered = shop.scanQrOutcome({ orderNumber: 'FER-1', fulfillmentStatus: 'entregado' });
    assert.equal(delivered.apply, false);
    assert.match(delivered.message, /ya fue entregado/);
    const ready = shop.scanQrOutcome({ orderNumber: 'FER-1', fulfillmentStatus: 'esperando_motobolt' });
    assert.equal(ready.apply, false);
    assert.match(ready.message, /ya está preparado/);
    const packed = shop.scanQrOutcome({ orderNumber: 'FER-1', fulfillmentStatus: 'preparado' });
    assert.equal(packed.apply, false);
    const cancelled = shop.scanQrOutcome({ orderNumber: 'FER-1', fulfillmentStatus: 'cancelado' });
    assert.equal(cancelled.apply, false);
    const pending = shop.scanQrOutcome({ orderNumber: 'FER-1', fulfillmentStatus: 'pagado' });
    assert.equal(pending.apply, true);
    const packing = shop.scanQrOutcome({ orderNumber: 'FER-1', fulfillmentStatus: 'preparando' });
    assert.equal(packing.apply, true);
});

test('bot catalog JSON includes name stock price and all videos', () => {
    const json = r2.botProductJson({
        _id: '65f000000000000000000001',
        name: 'Labial',
        description: '<p>Rosa</p>',
        price: 25000,
        stock: 4,
        hasVariants: false,
        variants: [],
        photos: ['https://img/a.jpg'],
        videos: [
            { url: 'https://r2/v1.mp4', key: 'k1', originalName: 'a.mp4' },
            { url: 'https://r2/v2.mp4', key: 'k2', originalName: 'b.mp4' },
            { url: 'https://r2/v3.mp4', key: 'k3', originalName: 'c.mp4' }
        ]
    });
    assert.equal(json.name, 'Labial');
    assert.equal(json.stock, 4);
    assert.equal(json.price, 25000);
    assert.equal(json.videos.length, 3);
    assert.equal(r2.shopVideos({ videos: json.videos }, 2).length, 2);
    assert.equal(r2.r2Config().ok, false);
});
