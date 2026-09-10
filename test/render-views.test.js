'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const ejs = require('ejs');
const pagopar = require('../lib/pagopar');

const views = path.join(__dirname, '..', 'views');
const formatPrice = (v) => new Intl.NumberFormat('es-PY', { style: 'currency', currency: 'PYG', maximumFractionDigits: 0 }).format(v || 0);

function locals(extra = {}) {
    return {
        path: '/',
        query: {},
        siteConfig: {
            logoUrl: '',
            whatsappNumber: '595987301591',
            storeMapsUrl: 'https://share.google/39F8jWwL96lFY65Th',
            storeAddress: 'Ferumishop',
            instagramUrl: 'https://instagram.com/ferumishop',
            tiktokUrl: 'https://tiktok.com/@ferumishop',
            facebookUrl: '',
            aboutUsText: ''
        },
        formatPrice,
        baseUrl: 'https://www.ferumi.shop',
        filename: path.join(views, 'public/index.html'),
        ...extra
    };
}

test('checkout view renders', async () => {
    const html = await ejs.renderFile(path.join(views, 'public/checkout.html'), locals({
        pageTitle: 'Checkout',
        store: { lat: -25.28, lng: -57.64, mapsUrl: 'https://share.google/39F8jWwL96lFY65Th', address: 'Ferumishop' }
    }));
    assert.match(html, /Usar mi ubicación/);
    assert.match(html, /Pagopar/);
});

test('tracking view renders', async () => {
    const html = await ejs.renderFile(path.join(views, 'public/tracking.html'), locals({ pageTitle: 'Tracking' }));
    assert.match(html, /Tracking de pedidos/);
});

test('ticket view renders QR and items', async () => {
    const html = await ejs.renderFile(path.join(views, 'public/ticket.html'), locals({
        pageTitle: 'Ticket',
        qrUrl: 'https://example.com/qr.png',
        printNow: false,
        store: { address: 'Ferumishop', mapsUrl: 'https://share.google/39F8jWwL96lFY65Th' },
        order: {
            orderNumber: 'FER-TEST',
            ticketCode: 'FM-ABC',
            tracking: { title: 'Preparando' },
            customerName: 'Ana',
            customerDocument: '123',
            customerPhone: '0981',
            paymentMethod: 'pagopar',
            paymentStatus: 'pagado',
            shippingMethod: 'motobolt',
            shippingAddress: '',
            items: [{ quantity: 1, name: 'Labial', price: 25000 }],
            totalAmount: 25000
        }
    }));
    assert.match(html, /FER-TEST/);
    assert.match(html, /FM-ABC/);
});

test('despacho admin view renders', async () => {
    const html = await ejs.renderFile(path.join(views, 'admin/despacho.html'), {
        filename: path.join(views, 'admin/despacho.html'),
        path: '/admin/despacho',
        pageTitle: 'Despacho',
        filter: 'activos',
        counts: { activos: 1, preparar: 1, listos: 0 },
        success: null,
        error: null,
        store: { mapsUrl: 'https://share.google/39F8jWwL96lFY65Th', address: 'Ferumishop' },
        orders: [{
            _id: '65f000000000000000000001',
            orderNumber: 'FER-1',
            ticketCode: 'FM-1',
            createdAt: new Date(),
            fulfillmentStatus: 'preparando',
            customerName: 'Ana',
            customerDocument: '1',
            customerPhone: '0981123456',
            customerEmail: 'a@b.c',
            paymentMethod: 'pagopar',
            paymentStatus: 'pagado',
            shippingMethod: 'motobolt',
            shippingDistanceKm: 8,
            shippingAddress: 'Centro',
            shippingCity: 'Asunción',
            shippingReference: '',
            items: [{ quantity: 1, name: 'Labial' }],
            totalAmount: 25000,
            housePhotoUrl: ''
        }]
    });
    assert.match(html, /Despachar compras/);
    assert.match(html, /FER-1/);
    assert.match(html, /Escanear ticket/);
});

test('webhook extract + echo shape', () => {
    const body = { resultado: [{ hash_pedido: 'abc', token: 't', pagado: true, numero_pedido: 29008559 }] };
    const info = pagopar.extractResultado(body);
    assert.equal(info.hash_pedido, 'abc');
    assert.equal(info.numero_pedido, 29008559);
});
