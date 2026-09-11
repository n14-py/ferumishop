'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const ejs = require('ejs');
const shop = require('../lib/orders');

test('paraguay day bounds cover the Asuncion calendar day', () => {
    const d = new Date('2026-09-11T06:00:00.000Z');
    const { start, end } = shop.paraguayDayBounds(d);
    assert.ok(start <= d);
    assert.ok(d < end);
    const hours = (end.getTime() - start.getTime()) / 3600000;
    assert.ok(hours >= 23 && hours <= 25, `unexpected span ${hours}`);
    const inside = new Date(d.getTime());
    const before = new Date(start.getTime() - 1000);
    const after = new Date(end.getTime());
    assert.equal(shop.formatParaguayDate(inside), shop.formatParaguayDate(d));
    assert.notEqual(shop.formatParaguayDate(before), shop.formatParaguayDate(d));
    assert.notEqual(shop.formatParaguayDate(after), shop.formatParaguayDate(d));
});

test('paraguay date time is formatted for es-PY', () => {
    const d = new Date('2026-09-11T15:30:00.000Z');
    const formatted = shop.formatParaguayDateTime(d);
    assert.match(formatted, /11\/0?9\/2026/);
    assert.match(formatted, /\d{1,2}:\d{2}/);
});

test('parseCajaSaleItems reads JSON cart and legacy single product', () => {
    const fromJson = shop.parseCajaSaleItems({
        itemsJson: JSON.stringify([
            { productId: 'a1', quantity: 2, sellPrice: '25.000', variantName: '30D' },
            { productId: 'b2', quantity: 1, sellPrice: 10000 }
        ])
    });
    assert.equal(fromJson.length, 2);
    assert.equal(fromJson[0].sellPrice, 25000);
    assert.equal(fromJson[0].quantity, 2);
    assert.equal(fromJson[0].variantName, '30D');
    assert.equal(fromJson[1].sellPrice, 10000);

    const legacy = shop.parseCajaSaleItems({
        productId: 'solo',
        quantity: '3',
        sellPrice: '15.000',
        variantName: 'Claro'
    });
    assert.equal(legacy.length, 1);
    assert.equal(legacy[0].productId, 'solo');
    assert.equal(legacy[0].quantity, 3);
    assert.equal(legacy[0].sellPrice, 15000);
});

test('caja sale description and stock decrement for several products', () => {
    const desc = shop.buildCajaSaleDescription([
        { name: 'Labial', quantity: 1 },
        { name: 'Pestañas', quantity: 2, variantName: '30D' }
    ]);
    assert.equal(desc, 'Venta: Labial (x1), Pestañas - 30D (x2)');

    const product = { hasVariants: false, stock: 5 };
    shop.applyManualSaleStock(product, 2, '');
    assert.equal(product.stock, 3);
    shop.applyManualSaleStock(product, 10, '');
    assert.equal(product.stock, 3);
});

test('caja view shows today sales, confirmation and mobile cash book cards', async () => {
    const views = path.join(__dirname, '..', 'views');
    const html = await ejs.renderFile(path.join(views, 'admin/caja.html'), {
        filename: path.join(views, 'admin/caja.html'),
        path: '/admin/caja',
        pageTitle: 'Caja',
        currentFilter: { mes: 9, anio: 2026 },
        availableMonths: [{ month: 9, year: 2026 }],
        mesActual: 'SEPTIEMBRE 2026',
        success: null,
        error: null,
        ventasHoy: 45000,
        ventasHoyFecha: '11/09/2026',
        ventasHoyHora: '20:15',
        formatPyDateTime: () => '11/09/2026 20:15',
        stats: {
            totalIngresos: 100000,
            totalCostosReposicion: 20000,
            totalReinversion: 20000,
            totalNando: 15000,
            totalMayu: 15000,
            totalEgresosExtra: 5000,
            totalCapitalMes: 0,
            gananciaNeta: 75000,
            deudaTotalNando: 15000,
            deudaTotalMayu: 15000
        },
        products: [{
            _id: 'p1',
            name: 'Labial',
            price: 25000,
            costPrice: 10000,
            stock: 4,
            photos: ['https://img/labial.jpg']
        }, {
            _id: 'p2',
            name: 'Pestañas',
            price: 20000,
            costPrice: 8000,
            stock: 6,
            photos: ['https://img/pestanas.jpg']
        }],
        transactions: [{
            _id: 't1',
            type: 'ingreso',
            description: 'Venta: Labial (x1), Pestañas (x1)',
            amount: 45000,
            cost: 18000,
            reinvestment: 18000,
            profitMayu: 4500,
            profitNando: 4500,
            date: new Date('2026-09-11T15:00:00.000Z')
        }]
    });
    assert.match(html, /Ventas de hoy/);
    assert.doesNotMatch(html, /Dinero de la Tienda \(Capital\)/);
    assert.match(html, /11\/09\/2026/);
    assert.match(html, /hora PY/);
    assert.match(html, /caja-tx-card/);
    assert.match(html, /Elegí uno o varios productos/);
    assert.match(html, /Confirmar venta/);
    assert.match(html, /ventaItemsJson/);
    assert.match(html, /d-md-none/);
});
