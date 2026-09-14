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
    assert.match(html, /Permitir que Ferumishop vea tu ubicación/);
    assert.match(html, /Copiar link para abrir en Safari o Chrome/);
    assert.match(html, /Instagram, TikTok o WhatsApp/);
    assert.match(html, /Pagopar/);
    assert.match(html, /Pedir por WhatsApp/);
});

test('product detail shows at most two videos', async () => {
    const html = await ejs.renderFile(path.join(views, 'public/producto-detalle.html'), locals({
        pageTitle: 'Labial',
        product: {
            _id: '65f000000000000000000001',
            name: 'Labial',
            description: 'Rosa',
            price: 25000,
            photos: ['https://img/a.jpg'],
            videos: [
                { url: 'https://r2/v1.mp4' },
                { url: 'https://r2/v2.mp4' },
                { url: 'https://r2/v3.mp4' }
            ],
            hasVariants: false,
            category: { name: 'Labiales' }
        },
        recommendedProducts: []
    }));
    assert.match(html, /https:\/\/r2\/v1\.mp4/);
    assert.match(html, /https:\/\/r2\/v2\.mp4/);
    assert.doesNotMatch(html, /https:\/\/r2\/v3\.mp4/);
    assert.match(html, /product-swipe/);
    assert.match(html, /product-swipe-slide is-video/);
    assert.match(html, /Deslizá: primero las fotos, después los videos/);
    assert.match(html, /max-width: 100%/);
    assert.equal((html.match(/product-swipe-slide is-video/g) || []).length, 2);
});

test('tracking view renders', async () => {
    const html = await ejs.renderFile(path.join(views, 'public/tracking.html'), locals({ pageTitle: 'Tracking' }));
    assert.match(html, /Dónde está mi pedido/);
    assert.doesNotMatch(html, /Ver ticket \/ QR/);
});

test('compra-ok thank you has tracking and no customer QR', async () => {
    const html = await ejs.renderFile(path.join(views, 'public/compra-ok.html'), locals({
        pageTitle: 'Pedido recibido',
        store: { address: 'Ferumishop', mapsUrl: 'https://share.google/39F8jWwL96lFY65Th' },
        order: {
            orderNumber: 'FER-TEST',
            ticketCode: 'FM-ABC',
            tracking: { title: 'Preparando', detail: 'Armando tu pedido' },
            paymentMethod: 'pagopar',
            shippingMethod: 'motobolt'
        }
    }));
    assert.match(html, /FER-TEST/);
    assert.match(html, /Ver mi tracking/);
    assert.doesNotMatch(html, /qrserver|Ticket QR|Imprimir ticket/i);
});

test('pago resultado thank you has tracking and no QR', async () => {
    const html = await ejs.renderFile(path.join(views, 'public/pago-resultado.html'), locals({
        pageTitle: 'Pago',
        estado: { pagado: true, numero_pedido: 1, monto: 25000 },
        orderView: {
            orderNumber: 'FER-1',
            ticketCode: 'FM-1',
            tracking: { title: 'Pagado', detail: 'Recibimos tu pago' },
            shippingMethod: 'motobolt'
        },
        store: { mapsUrl: 'https://share.google/39F8jWwL96lFY65Th' }
    }));
    assert.match(html, /Pago confirmado/);
    assert.match(html, /Ver mi tracking/);
    assert.doesNotMatch(html, /qrserver|Ticket QR/i);
});

test('printed thermal ticket has dual-use pedido QR', async () => {
    const html = await ejs.renderFile(path.join(views, 'public/cola-impresion.html'), locals({
        pageTitle: 'Cola',
        autoPrint: false,
        pedido: {
            id: '65f000000000000000000001',
            cliente: 'Ana',
            items: [{ nombre: '1x Labial', precio: 25000 }],
            total: 25000,
            fecha: new Date(),
            orderNumber: 'FER-TEST',
            ticketCode: 'FM-ABC',
            shippingLabel: 'Motobolt',
            qrPayload: 'https://www.ferumi.shop/pedido/FM-ABC',
            qrHint: 'Preparar / Motobolt'
        }
    }));
    assert.match(html, /FER-TEST/);
    assert.match(html, /FM-ABC/);
    assert.match(html, /\/pedido\/FM-ABC/);
    assert.match(html, /Preparar \/ Motobolt/);
});

test('delivery detail shows client WhatsApp and map', async () => {
    const html = await ejs.renderFile(path.join(views, 'public/detalle-delivery.html'), locals({
        filename: path.join(views, 'public/detalle-delivery.html'),
        pageTitle: 'Detalle para Delivery',
        pedido: {
            cliente: 'Ana',
            telefonoOriginal: '0981123456',
            telefonoWa: '595981123456',
            items: [{ nombre: '1x Labial', precio: 25000 }],
            total: 25000,
            fecha: new Date(),
            lat: -25.28,
            lng: -57.64,
            address: 'Centro, Asunción',
            orderNumber: 'FER-1',
            housePhotoUrl: ''
        }
    }));
    assert.match(html, /Ana/);
    assert.match(html, /0981123456/);
    assert.match(html, /Escribir al WhatsApp/);
    assert.match(html, /Abrir en Google Maps/);
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
    assert.match(html, /Despachar/);
    assert.match(html, /Videos Shorts/);
    assert.match(html, /FER-1/);
    assert.match(html, /Escanear para marcar PREPARADO/);
    assert.match(html, /Marcar PREPARADO/);
    assert.match(html, /ya está preparado o entregado/);
    assert.match(html, /alreadyDone/);
});

test('dashboard shows shorts bot status', async () => {
    const html = await ejs.renderFile(path.join(views, 'admin/dashboard.html'), {
        filename: path.join(views, 'admin/dashboard.html'),
        path: '/admin/dashboard',
        pageTitle: 'Dashboard',
        mostViewedProducts: [],
        stats: {
            totalProducts: 3,
            totalCategories: 2,
            pendingGifts: 0,
            pendingDispatch: 1,
            paidToday: 2,
            videoBot: { enabled: true, used: 12, quota: 50, last: 'ok' }
        }
    });
    assert.match(html, /Bot Shorts/);
    assert.match(html, /12\/50 JSON hoy/);
    assert.match(html, /\/admin\/videos/);
});

test('edit product shows R2 video uploader', async () => {
    const html = await ejs.renderFile(path.join(views, 'admin/edit-producto.html'), {
        filename: path.join(views, 'admin/edit-producto.html'),
        path: '/admin/producto/edit/1',
        pageTitle: 'Editar',
        r2Configured: true,
        success: null,
        error: null,
        categories: [{ _id: 'c1', name: 'Labiales' }],
        product: {
            _id: '65f000000000000000000001',
            name: 'Labial',
            description: 'Rosa',
            costPrice: 10000,
            price: 25000,
            stock: 4,
            hasVariants: false,
            variants: [],
            photos: [],
            videos: [
                { _id: 'v1', url: 'https://r2/v1.mp4', key: 'k1', originalName: 'a.mp4' },
                { _id: 'v2', url: 'https://r2/v2.mp4', key: 'k2', originalName: 'b.mp4' }
            ],
            category: { _id: 'c1' },
            isFeatured: false,
            isForSale: true,
            isForRent: false
        }
    });
    assert.match(html, /Videos \(Cloudflare R2\)/);
    assert.match(html, /Subir videos a R2/);
    assert.match(html, /https:\/\/r2\/v1\.mp4/);
    assert.match(html, /Ahora hay 2/);
});

test('webhook extract + echo shape', () => {
    const body = { resultado: [{ hash_pedido: 'abc', token: 't', pagado: true, numero_pedido: 29008559 }] };
    const info = pagopar.extractResultado(body);
    assert.equal(info.hash_pedido, 'abc');
    assert.equal(info.numero_pedido, 29008559);
});

test('legal pages cover store, WhatsApp AI and data deletion email', async () => {
    const terms = await ejs.renderFile(path.join(views, 'public/terminos.html'), locals({
        pageTitle: 'Términos',
        path: '/terminos'
    }));
    assert.match(terms, /Términos y condiciones/);
    assert.match(terms, /asistente de WhatsApp/);
    assert.match(terms, /Pagopar/);
    assert.match(terms, /ferumishop@gmail.com/);
    assert.match(terms, /Motobolt/);

    const privacy = await ejs.renderFile(path.join(views, 'public/privacidad.html'), locals({
        pageTitle: 'Privacidad',
        path: '/privacidad'
    }));
    assert.match(privacy, /Política de privacidad/);
    assert.match(privacy, /DeepSeek/);
    assert.match(privacy, /Eliminar mis datos/);
    assert.match(privacy, /ferumishop@gmail.com/);
    assert.match(privacy, /WhatsApp/);

    const deletion = await ejs.renderFile(path.join(views, 'public/eliminacion-datos.html'), locals({
        pageTitle: 'Eliminación',
        path: '/eliminacion-de-datos'
    }));
    assert.match(deletion, /Eliminación de datos/);
    assert.match(deletion, /ferumishop@gmail.com/);
    assert.match(deletion, /30 días/);
    assert.match(deletion, /User Data Deletion/);
});
