'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const ejs = require('ejs');
const crypto = require('crypto');
const slug = require('../lib/wa-slug');
const wa = require('../lib/whatsapp');
const agent = require('../lib/wa-agent');
const pagopar = require('../lib/pagopar');

test('checkout slug matches ferumi.shop/099987382mariapedido', () => {
    assert.equal(slug.makeCheckoutSlug({ phone: '59599987382', name: 'María Pedroza' }), '099987382mariapedido');
    assert.equal(slug.makeCheckoutSlug({ phone: '099987382', name: 'Maria' }), '099987382mariapedido');
    assert.equal(slug.makeCheckoutSlug({ phone: '099987382', name: 'Maria', suffix: '2' }), '099987382mariapedido2');
    assert.equal(slug.isPaySlug('099987382mariapedido'), true);
    assert.equal(slug.isPaySlug('tienda'), false);
    assert.equal(slug.isPaySlug('checkout'), false);
    assert.equal(slug.isPaySlug('robots.txt'), false);
    assert.equal(slug.isPaySlug('0981123456anapedido'), true);
});

test('pay and tracking URLs stay on ferumi.shop', () => {
    const prev = process.env.BASE_URL;
    process.env.BASE_URL = 'https://www.ferumi.shop';
    assert.equal(slug.publicPayUrl('099987382mariapedido'), 'https://www.ferumi.shop/099987382mariapedido');
    assert.match(slug.publicTrackingUrl('FM-ABC'), /\/tracking\?q=FM-ABC/);
    process.env.BASE_URL = prev;
});

test('canCreateOrder requires pagopar data, cart and shipping', () => {
    const empty = agent.canCreateOrder({ cart: [], customer: {}, shipping: {} });
    assert.equal(empty.ok, false);
    const almost = agent.canCreateOrder({
        cart: [{ name: 'Labial', price: 25000, quantity: 1 }],
        customer: { name: 'Maria', document: '123', email: 'a@b.c', phone: '0981' },
        shipping: { method: 'motobolt', far: true, lat: 1, lng: 1 }
    });
    assert.equal(almost.ok, false);
    assert.match(almost.message, /Motobolt/);
    const ok = agent.canCreateOrder({
        cart: [{ name: 'Labial', price: 25000, quantity: 1 }],
        customer: { name: 'Maria', document: '123', email: 'a@b.c', phone: '0981' },
        shipping: { method: 'motobolt', far: false, lat: -25.2, lng: -57.6, address: 'Centro' }
    });
    assert.equal(ok.ok, true);
    assert.equal(ok.total, 25000);
});

test('looksLikeConfirm understands si and the WhatsApp button', () => {
    assert.equal(agent.looksLikeConfirm('sí', ''), true);
    assert.equal(agent.looksLikeConfirm('esta bien', ''), true);
    assert.equal(agent.looksLikeConfirm('hola', ''), false);
    assert.equal(agent.looksLikeConfirm('', 'confirm_order'), true);
});

test('paid message includes tracking and motobolt warning', () => {
    const text = agent.paidCustomerText({
        ticketCode: 'FM-ABC',
        orderNumber: 'FER-1',
        shippingMethod: 'motobolt'
    });
    assert.match(text, /Recibimos tu pago/);
    assert.match(text, /tracking/);
    assert.match(text, /Motobolt/);
    assert.match(text, /no se puede pedir Motobolt dos veces/i);
    assert.match(agent.MOTOBOLT_RULES, /pedidos en curso/);
});

test('media replies send real product photos and videos', () => {
    const replies = agent.mediaReplies({
        name: 'Labial',
        price: 25000,
        photos: ['https://img/a.jpg', 'https://img/b.jpg'],
        videos: [{ url: 'https://r2/v1.mp4', originalName: 'efecto.mp4' }],
        variants: [{ name: 'Rosa', photoUrl: 'https://img/rosa.jpg' }]
    }, 'both', 'Rosa');
    assert.equal(replies[0].type, 'image');
    assert.equal(replies[0].link, 'https://img/rosa.jpg');
    assert.ok(replies.some((r) => r.type === 'video' && r.link === 'https://r2/v1.mp4'));
});

test('WhatsApp webhook extracts text, location and button', () => {
    const messages = wa.extractMessages({
        entry: [{
            changes: [{
                field: 'messages',
                value: {
                    metadata: { phone_number_id: '123' },
                    contacts: [{ profile: { name: 'Maria' }, wa_id: '59599987382' }],
                    messages: [
                        { id: 'w1', from: '59599987382', type: 'text', text: { body: 'Hola' } },
                        { id: 'w2', from: '59599987382', type: 'location', location: { latitude: -25.28, longitude: -57.64, address: 'Asunción' } },
                        { id: 'w3', from: '59599987382', type: 'interactive', interactive: { button_reply: { id: 'confirm_order', title: 'Sí, está bien' } } }
                    ]
                }
            }]
        }]
    });
    assert.equal(messages.length, 3);
    assert.equal(messages[0].text, 'Hola');
    assert.equal(messages[1].location.lat, -25.28);
    assert.equal(messages[2].buttonId, 'confirm_order');
});

test('webhook verify token and signature', () => {
    process.env.WHATSAPP_VERIFY_TOKEN = 'ferumi-secret';
    const ok = wa.challengeResponse({ 'hub.mode': 'subscribe', 'hub.verify_token': 'ferumi-secret', 'hub.challenge': 'abc' });
    assert.equal(ok.ok, true);
    assert.equal(ok.challenge, 'abc');
    const bad = wa.challengeResponse({ 'hub.mode': 'subscribe', 'hub.verify_token': 'nope', 'hub.challenge': 'abc' });
    assert.equal(bad.ok, false);

    process.env.WHATSAPP_APP_SECRET = 'app-secret';
    const body = '{"ok":true}';
    const header = 'sha256=' + crypto.createHmac('sha256', 'app-secret').update(body).digest('hex');
    assert.equal(wa.verifySignature(body, header).ok, true);
    assert.equal(wa.verifySignature(body, 'sha256=deadbeef').ok, false);
});

test('text chunks stay under WhatsApp limit', () => {
    const parts = wa.chunkText('a'.repeat(5000), 3900);
    assert.ok(parts.length >= 2);
    assert.ok(parts.every((p) => p.length <= 3900));
});

test('missing Pagopar fields are listed', () => {
    assert.deepEqual(agent.missingCustomer({}), ['nombre', 'cédula', 'correo', 'teléfono']);
    assert.equal(agent.missingCustomer({
        name: 'Ana', document: '1', email: 'a@b.c', phone: '0981'
    }).length, 0);
});

test('private pay page is a Pagopar button only', async () => {
    const html = await ejs.renderFile(path.join(__dirname, '../views/public/wa-pagar.html'), {
        paid: false,
        cancelled: false,
        payUrl: '/api/whatsapp/ir-a-pagar/099987382mariapedido',
        trackingUrl: '/tracking?q=FM-1',
        siteConfig: { logoUrl: '' },
        order: {
            customerName: 'Maria Perez',
            orderNumber: 'FER-1',
            items: [{ quantity: 1, name: 'Labial' }],
            totalAmount: 25000,
            shippingMethod: 'motobolt'
        }
    });
    assert.match(html, /noindex/);
    assert.match(html, /Pagar con Pagopar/);
    assert.match(html, /099987382mariapedido/);
    assert.doesNotMatch(html, /Pedir por WhatsApp/);
    assert.doesNotMatch(html, /carrito/i);
});

test('despacho shows WhatsApp badge for bot orders', async () => {
    const html = await ejs.renderFile(path.join(__dirname, '../views/admin/despacho.html'), {
        filename: path.join(__dirname, '../views/admin/despacho.html'),
        path: '/admin/despacho',
        pageTitle: 'Despacho',
        filter: 'activos',
        counts: { activos: 1, preparar: 1, listos: 0 },
        success: null,
        error: null,
        store: { mapsUrl: 'https://share.google/39F8jWwL96lFY65Th', address: 'Ferumishop' },
        orders: [{
            _id: '65f000000000000000000001',
            orderNumber: 'FER-WA',
            ticketCode: 'FM-WA',
            source: 'whatsapp',
            createdAt: new Date(),
            fulfillmentStatus: 'preparando',
            customerName: 'Maria',
            customerDocument: '1',
            customerPhone: '099987382',
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
    assert.match(html, /FER-WA/);
    assert.match(html, /WhatsApp/);
});

test('pagopar webhook extract still works after ecommerce hook', () => {
    const info = pagopar.extractResultado({ resultado: [{ hash_pedido: 'abc', pagado: true }] });
    assert.equal(info.hash_pedido, 'abc');
    assert.equal(info.pagado, true);
});
