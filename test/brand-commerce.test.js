'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const ejs = require('ejs');
const promotions = require('../lib/promotions');
const payments = require('../lib/payments');
const brand = require('../lib/brand');
const copy = require('../lib/product-copy');
const migrate = require('../lib/migrate-payments');

const retired = ['pa', 'go', 'par'].join('');

function walk(dir, acc = []) {
    for (const name of fs.readdirSync(dir)) {
        if (name === 'node_modules' || name === '.git') continue;
        const full = path.join(dir, name);
        const stat = fs.statSync(full);
        if (stat.isDirectory()) walk(full, acc);
        else if (/\.(js|html|css|md|json|ejs)$/.test(name)) acc.push(full);
    }
    return acc;
}

test('the retired gateway name is not in the repository', () => {
    const re = new RegExp(retired, 'i');
    const hits = walk(path.join(__dirname, '..'))
        .filter((file) => re.test(fs.readFileSync(file, 'utf8')))
        .map((file) => path.relative(path.join(__dirname, '..'), file));
    assert.deepEqual(hits, []);
});

test('expired and future promotions stay off the public price', () => {
    const now = new Date('2026-11-18T12:00:00Z');
    const product = { _id: 'p1', price: 100000, isOnPromo: true, promoPrice: 90000 };
    const list = [
        { title: 'Vencida', active: true, startsAt: '2026-01-01', endsAt: '2026-02-01', productIds: ['p1'], discountType: 'percent', discountValue: 50 },
        { title: 'Futura', active: true, startsAt: '2026-12-01', endsAt: '2026-12-31', productIds: ['p1'], discountType: 'percent', discountValue: 40, featured: true },
        { title: 'Ahora', active: true, startsAt: null, endsAt: null, productIds: ['p1'], discountType: 'amount', discountValue: 15000, sortOrder: 2 },
        { title: 'Apagada', active: false, productIds: ['p1'], discountType: 'percent', discountValue: 80 },
        { title: 'Solo banner', active: true, productIds: [], discountType: 'percent', discountValue: 90, sortOrder: 0 }
    ];
    const live = promotions.liveList(list, now);
    assert.deepEqual(live.map((item) => item.title), ['Solo banner', 'Ahora']);
    const price = promotions.effectivePrice(product, list, now);
    assert.equal(price.price, 85000);
    assert.equal(price.compareAt, 100000);
    assert.equal(price.onPromo, true);
    assert.equal(promotions.effectivePrice({ _id: 'p2', price: 40000 }, list, now).price, 40000);
});

test('payment methods keep transfer and pickup cash without an online provider', () => {
    assert.equal(payments.onlineAvailable(), false);
    assert.equal(payments.chargeTotal(8000, 2000), 10000);
    assert.deepEqual(payments.methodsForShipping('motobolt').map((item) => item.id), ['transferencia']);
    assert.deepEqual(payments.methodsForShipping('retiro').map((item) => item.id), ['transferencia', 'efectivo_retiro']);
    assert.equal(payments.assertCheckoutMethod('transferencia', 'motobolt').ok, true);
    assert.equal(payments.assertCheckoutMethod('efectivo', 'retiro').method, 'efectivo_retiro');
    const blocked = payments.assertCheckoutMethod('online', 'retiro');
    assert.equal(blocked.ok, false);
    assert.match(blocked.message, /transferir/i);
});

test('brand facts stay on the provided founders when the admin list is empty', () => {
    const empty = brand.present({ founders: [] });
    assert.equal(empty.country, 'Paraguay');
    assert.equal(empty.foundedOn, '11 de enero de 2026');
    assert.equal(empty.founders[0].name, 'Luis Fernando Arce Fretes');
    assert.equal(empty.founders[1].name, 'Fadua Mahiumy Gomez Benitez');
    assert.match(empty.founders[0].role, /Dirección Ejecutiva/);
    assert.match(empty.founders[1].role, /Experiencia del Cliente/);
    const custom = brand.present({ founders: [{ name: 'Equipo FERUMI', role: 'Marca', bio: 'Hecho en Paraguay.' }] });
    assert.equal(custom.founders.length, 1);
    assert.equal(custom.founders[0].name, 'Equipo FERUMI');
});

test('product copy drops unsupported claims and refuses to invent a sheet without a name', async () => {
    const clean = copy.normalize({
        description: 'Es un serum. Certificado dermatológico. Se usa de noche.',
        benefits: ['Hidrata', 'Hipoalergénico'],
        faqs: [{ question: '¿Es vegano?', answer: 'Sí, vegano certificado.' }]
    }, ['description', 'benefits', 'faqs'], 'Serum de noche');
    assert.match(clean.description, /Se usa de noche/);
    assert.doesNotMatch(clean.description, /Certificado/);
    assert.deepEqual(clean.benefits, ['Hidrata']);
    assert.equal(clean.faqs, undefined);
    const kept = copy.normalize({
        description: 'Fórmula vegana según la ficha del proveedor.'
    }, ['description'], 'El proveedor indica fórmula vegana');
    assert.match(kept.description, /vegana/);
    try {
        await copy.generate({ name: '' });
        assert.fail('debía rechazar una ficha sin nombre');
    } catch (err) {
        assert.ok(err.status === 400 || err.status === 503);
    }
});

test('payment migration does nothing when the database is disconnected', async () => {
    const result = await migrate.run({ connection: { readyState: 0 } });
    assert.equal(result.skipped, true);
});

test('homepage, promotions and brand pages render the new stage', async () => {
    const views = path.join(__dirname, '..', 'views');
    const formatPrice = (value) => `${value} Gs`;
    const locals = {
        path: '/',
        query: {},
        formatPrice,
        baseUrl: 'https://www.ferumi.shop',
        siteConfig: {
            logoUrl: '',
            whatsappNumber: '595987301591',
            storeAddress: 'Ferumishop, Capiatá',
            bannerImages: [],
            aboutUsText: '',
            instagramUrl: 'https://instagram.com/ferumishop',
            tiktokUrl: '',
            facebookUrl: ''
        },
        brand: brand.present({}),
        livePromotions: [{ title: 'Lanzamiento diciembre', subtitle: 'Promo exclusiva', featured: true, image: '' }],
        featuredProducts: [],
        latestProducts: [],
        categories: [{ name: 'Pestañas' }]
    };
    const home = await ejs.renderFile(path.join(views, 'public/index.html'), locals);
    assert.match(home, /Tu belleza,/);
    assert.match(home, /tu esencia\./);
    assert.match(home, /Descubrí Ferumi: pestañas, cosméticos y todo para expresar tu estilo\./);
    assert.match(home, /Descubrir productos/);
    assert.match(home, /1\.000/);
    assert.match(home, /Lanzamiento diciembre/);
    assert.match(home, /Pestañas/);
    assert.doesNotMatch(home, /Luis Fernando Arce Fretes/);
    assert.match(home, /href="\/css\/brand.css"/);
    assert.match(home, /href="\/css\/pages.css"/);

    const promos = await ejs.renderFile(path.join(views, 'public/promociones.html'), {
        ...locals,
        promotions: locals.livePromotions,
        products: []
    });
    assert.match(promos, /Lanzamiento diciembre/);

    const about = await ejs.renderFile(path.join(views, 'public/sobre-nosotros.html'), locals);
    assert.match(about, /Luis Fernando Arce Fretes/);
    assert.match(about, /Fadua Mahiumy Gomez Benitez/);
    assert.match(about, /Dirección Ejecutiva/);
    assert.match(about, /Experiencia del Cliente/);
    assert.match(about, /Belleza con identidad propia/);
    assert.match(about, /11 de enero de 2026/);
    assert.match(about, /Más de 1\.000 clientes/);
    assert.match(about, /Diciembre de 2026/);
    assert.match(about, /Una nueva forma de vivir la belleza/);
});

test('legacy placeholder copy never reaches a public page', async () => {
    const views = path.join(__dirname, '..', 'views');
    const legacy = 'Escribe aquí la descripción de "Sobre Nosotros".';
    const config = {
        logoUrl: '', whatsappNumber: '595987301591', storeAddress: 'Ferumishop, Capiatá', bannerImages: [],
        aboutUsText: legacy, instagramUrl: '', tiktokUrl: '', facebookUrl: ''
    };
    const about = await ejs.renderFile(path.join(views, 'public/sobre-nosotros.html'), {
        path: '/sobre-nosotros', query: {}, formatPrice: (v) => `${v} Gs`, baseUrl: 'https://www.ferumi.shop',
        siteConfig: config, brand: brand.present(config)
    });
    assert.doesNotMatch(about, /Escribe aquí/i);
    assert.doesNotMatch(about, /quienes ya nos conocen/i);
    assert.equal(brand.cleanAbout(legacy), '');
    assert.equal(brand.cleanAbout('  <p> </p> '), '');
    assert.equal(brand.cleanAbout('<p>Texto real de la marca.</p>'), '<p>Texto real de la marca.</p>');
    const custom = { ...config, aboutUsText: '<p>Texto real de la marca.</p>' };
    const withText = await ejs.renderFile(path.join(views, 'public/sobre-nosotros.html'), {
        path: '/sobre-nosotros', query: {}, formatPrice: (v) => `${v} Gs`, baseUrl: 'https://www.ferumi.shop',
        siteConfig: custom, brand: brand.present(custom)
    });
    assert.match(withText, /Texto real de la marca\./);
});
