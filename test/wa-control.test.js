'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const ejs = require('ejs');
const { sanitizeOutgoingText, wantsHuman, guardCustomerReply, redactSecrets } = require('../lib/wa-control/text');
const { can, roleOf } = require('../lib/wa-control/permissions');
const { canTransition, FINANCIAL_TRANSITIONS, aiMayRespond, attentionAfter } = require('../lib/wa-control/states');
const { renderTemplate, validateTemplate } = require('../lib/wa-control/templates');
const { quoteShipping, resolvePlace } = require('../lib/wa-control/rates');
const { evaluateRules, discountAllowed, DEFAULT_RULES } = require('../lib/wa-control/rules');
const { orderMatchesScope, situationConflicts, situationIsLive } = require('../lib/wa-control/situations');
const { afterCutoff, eligibleForDeparture, planDispatchNotifications } = require('../lib/wa-control/departures');
const {
    paymentFingerprint, runLockedCharge, createMemoryStore, shouldSendLink, assessReceipt, isUncertainProviderError, resolveIntentTarget
} = require('../lib/wa-control/payments');
const { collapseOutgoing, createMemoryOutbound, claimOutbound } = require('../lib/wa-control/outbound');
const { validateInboundImage, matchCatalogByDescription, visionStatus } = require('../lib/wa-control/vision');
const { simulateTurn, SCENARIOS } = require('../lib/wa-control/simulator');
const { rankCatalog, catalogReply, replyDeniesCatalog } = require('../lib/wa-control/catalog');
const { transferMessage } = require('../lib/wa-control/transfer');
const { describePoint } = require('../lib/wa-control/geo');
const { parseTransferText, trashStillVisible, interpretReceiptVision } = require('../lib/wa-control/receipt-read');
const { alreadyClaimsReceipt } = require('../lib/wa-control/flow');
const { parseCoord } = require('../lib/whatsapp');
const { planTurn } = require('../lib/wa-control/flow');
const { customerSafeText } = require('../lib/wa-control/text');
const { controlModels } = require('../lib/wa-control/models');
const pagopar = require('../lib/pagopar');
const agent = require('../lib/wa-agent');
const { summarizeOperations } = require('../lib/wa-control/dashboard');
const { competeForLastUnit } = require('../lib/orders');
const wa = require('../lib/whatsapp');

const settings = { cutoffTime: '18:00', departureTime: '18:00', timezone: 'America/Asuncion', serviceDays: [1, 2, 3, 4, 5, 6] };

test('sanitize keeps ñ, accents and emoji and drops markdown asterisks', () => {
    const text = sanitizeOutgoingText('Hola ñandú, el precio es **25.000** 💖\n\n\n*oferta*');
    assert.match(text, /ñandú/);
    assert.match(text, /💖/);
    assert.equal(text.includes('**'), false);
    assert.doesNotMatch(text, /\*oferta\*/);
});

test('webhook duplicate and special characters stay one message each', () => {
    const body = {
        entry: [{ changes: [{ field: 'messages', value: { messages: [
            { id: 'w-dup', from: '595981000000', type: 'text', text: { body: 'Hola ñandú 💖' } },
            { id: 'w-dup', from: '595981000000', type: 'text', text: { body: 'Hola ñandú 💖' } }
        ] } }] }]
    };
    const messages = wa.extractMessages(body);
    const ids = new Set(messages.map((item) => item.wamid));
    assert.equal(messages.length, 2);
    assert.equal(ids.size, 1);
    assert.match(messages[0].text, /ñandú/);
});

test('business phone echo is visible and statuses do not look like customer messages', () => {
    const echoes = wa.extractEchoes({
        entry: [{ changes: [{ field: 'smb_message_echoes', value: { message_echoes: [
            { id: 'echo-1', from: '595987301591', to: '595981000000', type: 'text', text: { body: 'Te escribo desde el celular' } }
        ] } }] }]
    });
    assert.equal(echoes[0].to, '595981000000');
    const statuses = wa.extractStatuses({
        entry: [{ changes: [{ value: { statuses: [{ id: 'm1', status: 'failed', recipient_id: '595981000000', errors: [{ title: 'falló' }] }] } }] }]
    });
    assert.equal(statuses[0].status, 'failed');
    assert.equal(wa.extractMessages({ entry: [{ changes: [{ value: { statuses: [{ status: 'delivered' }] } }] }] }).length, 0);
});

test('human handoff pauses AI and does not promise an immediate person', () => {
    assert.equal(wantsHuman('quiero hablar con una persona'), true);
    const next = attentionAfter('request_human');
    assert.equal(next.attentionStatus, 'human_requested');
    assert.equal(aiMayRespond({ attentionStatus: 'human_active', aiPaused: true }), false);
    assert.equal(aiMayRespond(attentionAfter('resume')), true);
    const reply = simulateTurn({ text: 'Quiero hablar con una persona', rules: DEFAULT_RULES }).reply;
    assert.match(reply, /no te prometo/i);
});

test('payment link is created once under concurrency and reused later', async () => {
    const store = createMemoryStore();
    let calls = 0;
    const run = () => runLockedCharge(store, {
        key: 'same',
        fingerprint: 'same',
        createCharge: async () => {
            calls += 1;
            await new Promise((resolve) => setTimeout(resolve, 20));
            return { hash: 'HASH1', payUrl: 'https://www.ferumi.shop/pago', orderId: 'order-1' };
        }
    });
    const [a, b] = await Promise.all([run(), run()]);
    assert.equal(calls, 1);
    assert.equal(a.intent.hash, 'HASH1');
    assert.equal(b.intent.hash, 'HASH1');
    const again = await run();
    assert.equal(again.providerCalled, false);
    assert.equal(again.outcome, 'reuse');
    assert.equal(calls, 1);
});

test('uncertain Pagopar response does not create another charge', async () => {
    const store = createMemoryStore();
    let calls = 0;
    const run = () => runLockedCharge(store, {
        key: 'late',
        fingerprint: 'late',
        createCharge: async () => {
            calls += 1;
            const error = new Error('timeout');
            error.name = 'TimeoutError';
            throw error;
        }
    });
    const first = await run();
    const second = await run();
    assert.equal(first.outcome, 'uncertain');
    assert.equal(second.outcome, 'uncertain');
    assert.equal(second.providerCalled, false);
    assert.equal(calls, 1);
    assert.equal(isUncertainProviderError({ name: 'AbortError' }), true);
    assert.equal(isUncertainProviderError({ uncertain: false, status: 400 }), false);
});

test('expired link is not renewed automatically and a duplicate receipt is not a new payment', () => {
    const expired = shouldSendLink({ status: 'link_ready', payUrl: 'https://www.ferumi.shop/a', expiresAt: Date.now() - 1000 }, { now: Date.now() });
    assert.equal(expired.send, false);
    assert.equal(expired.reason, 'vencido');
    const sent = shouldSendLink({ status: 'sent', payUrl: 'https://www.ferumi.shop/a', linkSentAt: Date.now(), linkSendStatus: 'sent' }, { explicit: true, now: Date.now() });
    assert.equal(sent.reason, 'ya_enviado');
    const assessment = assessReceipt({ expectedAmount: 25000, declaredAmount: 10000, duplicate: false });
    assert.equal(assessment.confirm, false);
    assert.equal(assessment.status, 'diferencia');
    assert.equal(assessReceipt({ expectedAmount: 25000, declaredAmount: 25000, duplicate: true }).status, 'duplicado');
});

test('same cart fingerprint is stable and a changed total is a different operation', () => {
    const base = { waId: '595', cart: [{ productId: 'p1', variantName: 'Rosa', quantity: 1, price: 25000 }], shipping: { method: 'retiro', city: 'Capiatá' }, total: 25000, customer: { document: '123' } };
    assert.equal(paymentFingerprint(base), paymentFingerprint(base));
    assert.notEqual(paymentFingerprint(base), paymentFingerprint({ ...base, total: 30000 }));
    const target = resolveIntentTarget({ openIntent: { status: 'link_ready', fingerprint: 'abc', key: 'abc' }, fingerprint: 'abc', cartEmpty: false, mode: 'create' });
    assert.equal(target.action, 'reuse');
});

test('duplicate payment text collapses to one reply and outbound claim blocks a second send', async () => {
    const url = 'https://www.ferumi.shop/0999mariapedido';
    const replies = collapseOutgoing([
        { type: 'text', text: `Pagá acá ${url}` },
        { type: 'text', text: `De nuevo ${url}` },
        { type: 'text', text: `Pagá acá ${url}` }
    ]);
    assert.equal(replies.length, 1);
    const store = createMemoryOutbound();
    const first = await claimOutbound(store, 'pay:1');
    const second = await claimOutbound(store, 'pay:1');
    assert.equal(first.send, true);
    assert.equal(second.send, false);
});

test('zone rate wins over city rate and equal conflicts block the quote', () => {
    const now = new Date('2026-10-28T12:00:00Z');
    const specific = quoteShipping([
        { id: 'city', method: 'delivery_propio', city: 'Asunción', basePrice: 15000, priority: 1, active: true },
        { id: 'zone', method: 'delivery_propio', city: 'Asunción', zone: 'Centro', basePrice: 10000, priority: 1, active: true }
    ], { method: 'delivery_propio', city: 'Asunción', zone: 'Centro' }, now);
    assert.equal(specific.amount, 10000);
    assert.equal(specific.ruleId, 'zone');
    const conflict = quoteShipping([
        { id: 'a', method: 'delivery_propio', city: 'Luque', basePrice: 12000, priority: 5, active: true },
        { id: 'b', method: 'delivery_propio', city: 'Luque', basePrice: 18000, priority: 5, active: true }
    ], { method: 'delivery_propio', city: 'Luque' }, now);
    assert.equal(conflict.conflict, true);
    assert.equal(conflict.ok, false);
});

test('unknown or ambiguous city does not invent a delivery price', () => {
    const places = [
        { name: 'Capiatá', aliases: ['capiata'], active: true },
        { name: 'Encarnación', aliases: ['encarnacion'], active: true }
    ];
    assert.equal(resolvePlace('kapiata', places).status, 'fuzzy');
    assert.equal(resolvePlace('zzzz', places).status, 'unknown');
    const quote = quoteShipping([], { method: 'delivery_propio', city: 'Ciudad Inventada' });
    assert.equal(quote.ok, false);
    assert.equal(quote.amount, null);
    const moto = quoteShipping([], { method: 'motobolt', city: 'Asunción', far: false });
    assert.equal(moto.amount, 0);
    assert.equal(moto.policy, 'motobolt_driver_paid');
});

test('departure after cutoff and unpaid or unprepared orders stay out', () => {
    const late = new Date('2026-10-28T22:30:00Z');
    assert.equal(afterCutoff(late, settings), true);
    const departure = { zones: ['Capiatá'], cutoffAt: late, status: 'planificada', notified: [] };
    const orders = [
        { id: '1', shippingMethod: 'delivery_propio', shippingCity: 'Capiatá', paymentStatus: 'pendiente', fulfillmentStatus: 'preparado', createdAt: new Date('2026-10-28T12:00:00Z') },
        { id: '2', shippingMethod: 'delivery_propio', shippingCity: 'Capiatá', paymentStatus: 'pagado', fulfillmentStatus: 'preparando', createdAt: new Date('2026-10-28T12:00:00Z') },
        { id: '3', shippingMethod: 'motobolt', paymentStatus: 'pagado', fulfillmentStatus: 'preparado' },
        { id: '4', shippingMethod: 'delivery_propio', shippingCity: 'Capiatá', paymentStatus: 'pagado', fulfillmentStatus: 'preparado', logisticsStatus: 'listo_despacho', createdAt: new Date('2026-10-28T12:00:00Z') }
    ];
    assert.equal(eligibleForDeparture(orders[0], departure, settings).reason, 'pago_no_confirmado');
    assert.equal(eligibleForDeparture(orders[1], departure, settings).reason, 'no_preparado');
    assert.equal(eligibleForDeparture(orders[2], departure, settings).reason, 'otra_modalidad');
    const plan = planDispatchNotifications(departure, [orders[3]], settings);
    assert.equal(plan.recipients, 1);
    const second = planDispatchNotifications({ ...departure, notified: [{ orderId: '4', status: 'sent' }] }, [orders[3]], settings);
    assert.equal(second.recipients, 0);
    assert.equal(second.already.length, 1);
});

test('rain reschedule does not touch delivered orders or other methods', () => {
    const situation = {
        status: 'active',
        scope: 'not_prepared',
        methods: ['delivery_propio'],
        authorizedActions: ['reschedule_next_day'],
        startsAt: new Date('2026-10-01T00:00:00Z'),
        endsAt: new Date('2026-12-01T00:00:00Z')
    };
    assert.equal(situationIsLive(situation, new Date('2026-10-28T15:00:00Z')), true);
    assert.equal(orderMatchesScope({ shippingMethod: 'delivery_propio', fulfillmentStatus: 'preparando' }, situation), true);
    assert.equal(orderMatchesScope({ shippingMethod: 'delivery_propio', fulfillmentStatus: 'entregado' }, situation), false);
    assert.equal(orderMatchesScope({ shippingMethod: 'motobolt', fulfillmentStatus: 'preparando' }, situation), false);
    const conflicts = situationConflicts([
        { ...situation, title: 'A', priority: 1, authorizedActions: ['suspend_delivery'] },
        { ...situation, title: 'B', priority: 1, authorizedActions: ['force_dispatch'] }
    ], new Date('2026-10-28T15:00:00Z'));
    assert.equal(conflicts.length, 1);
});

test('rules block unauthorized discount, partial payment and unpaid dispatch', () => {
    const evaluated = evaluateRules(DEFAULT_RULES, {
        method: 'motobolt',
        paymentMethods: ['pagopar', 'transferencia'],
        stockOk: false,
        afterCutoff: true,
        needsHuman: true,
        requiresPayment: true,
        paymentConfirmed: false
    });
    assert.equal(evaluated.decisions.allowPartial, false);
    assert.equal(evaluated.decisions.blockDispatch, true);
    assert.equal(evaluated.decisions.requireHuman, true);
    assert.equal(discountAllowed(evaluated.decisions, 5000, 100000).ok, false);
    assert.equal(canTransition(FINANCIAL_TRANSITIONS, 'pendiente', 'confirmado'), true);
    assert.equal(canTransition(FINANCIAL_TRANSITIONS, 'confirmado', 'pendiente'), false);
});

test('permissions deny a viewer and a bad file or template', () => {
    assert.equal(roleOf({}), 'owner');
    assert.equal(can({ role: 'viewer' }, 'wa.payments.approve'), false);
    assert.equal(can({ role: 'owner' }, 'wa.payments.approve'), true);
    assert.equal(can({}, 'wa.users'), true);
    assert.equal(validateInboundImage({ mime: 'image/gif', size: 100 }).ok, false);
    assert.equal(validateInboundImage({ mime: 'image/jpeg', size: 1000 }).ok, true);
    assert.equal(validateInboundImage({ mime: 'image/png', size: 9 * 1024 * 1024 }).ok, false);
    const rendered = renderTemplate('Total {{total}}', { total: '' }, {});
    assert.equal(rendered.ok, false);
    assert.equal(validateTemplate('Hola {{password}}').ok, false);
    assert.equal(visionStatus().available, false);
});

test('similar products are not called identical and stock contention keeps one unit', () => {
    const matches = matchCatalogByDescription('labial rojo mate', [
        { id: '1', name: 'Labial rojo', description: 'mate', price: 25000, stock: 2, photos: ['https://ferumi.shop/a.jpg'] },
        { id: '2', name: 'Base', description: 'beige', price: 40000, stock: 1, photos: [] }
    ]);
    assert.notEqual(matches[0].confidence, 'exacta');
    assert.match(matches[0].photos[0], /ferumi/);
    const race = competeForLastUnit(1, [1, 1]);
    assert.equal(race[0].ok, true);
    assert.equal(race[1].ok, false);
});

test('dashboard separates registered orders from collected money', () => {
    const summary = summarizeOperations({
        orders: [
            { createdAt: '2026-10-28T12:00:00Z', totalAmount: 30000, paymentStatus: 'pendiente', status: 'pendiente', shippingMethod: 'retiro' },
            { createdAt: '2026-10-28T12:00:00Z', paidAt: '2026-10-28T13:00:00Z', totalAmount: 20000, paymentStatus: 'pagado', financialStatus: 'confirmado', shippingMethod: 'motobolt' }
        ],
        conversations: [{ createdAt: '2026-10-28T12:00:00Z', attentionStatus: 'human_requested' }],
        intents: [{ hash: 'h1', payUrl: 'https://www.ferumi.shop/x' }],
        filters: { from: '2026-10-28T00:00:00Z', to: '2026-10-28T23:59:00Z' }
    });
    assert.equal(summary.registeredSales, 50000);
    assert.equal(summary.collectedSales, 20000);
    assert.equal(summary.pendingCollection, 30000);
    assert.equal(summary.paymentLinks, 1);
    assert.notEqual(summary.collectedSales, summary.paymentLinks);
});

test('guardrails replace invented payment confirmation and secrets stay out of logs', () => {
    const text = guardCustomerReply('Tu pago ya está confirmado', { paymentConfirmed: false });
    assert.match(text, /no está confirmado/i);
    const redacted = redactSecrets({ authorization: 'Bearer abc', note: 'token=abc123' });
    assert.equal(redacted.authorization, '[redactado]');
    assert.match(redacted.note, /redactado/);
});

test('simulator covers the commercial scenarios without side effects', () => {
    const catalog = [{ name: 'Labial negro', price: 25000, stock: 0, description: 'mate' }];
    for (const scenario of SCENARIOS) {
        const result = simulateTurn({
            scenarioId: scenario.id,
            catalog,
            rules: DEFAULT_RULES,
            settings,
            order: { orderNumber: 'FER-1', totalAmount: 25000, paymentStatus: 'pendiente', shippingMethod: 'motobolt', shippingCity: 'Asunción' },
            openPayment: { payUrl: 'https://www.ferumi.shop/vigente' },
            situations: scenario.id === 'rain' ? [{
                status: 'active',
                title: 'Lluvia',
                scope: 'all_pending',
                methods: ['delivery_propio'],
                responseInstructions: 'Hoy no hay delivery propio.',
                startsAt: '2026-10-01',
                endsAt: '2026-12-01'
            }] : []
        });
        assert.equal(result.simulated, true);
        assert.equal(result.sideEffects, false);
        assert.ok(result.reply);
    }
    const partial = simulateTurn({ scenarioId: 'deposit', rules: DEFAULT_RULES });
    assert.equal(partial.orderEffect, 'parcial_bloqueado');
    const link = simulateTurn({ scenarioId: 'paylink', rules: DEFAULT_RULES, openPayment: { payUrl: 'https://www.ferumi.shop/vigente' } });
    assert.match(link.reply, /No genero otro/);
});

test('whatsapp admin sections render inside the existing shell', async () => {
    const view = path.join(__dirname, '../views/admin/whatsapp/index.html');
    const locals = {
        pageTitle: 'WhatsApp AI',
        path: '/admin/whatsapp',
        section: 'dashboard',
        nav: [['dashboard', 'Resumen', 'fa-gauge'], ['conversaciones', 'Conversaciones', 'fa-comments']],
        admin: { role: 'owner', username: 'Admin', email: 'a@b.c' },
        perms: { 'wa.reply': true, 'wa.handoff': true, 'wa.payments.approve': true, 'wa.delivery': true, 'wa.notify.bulk': true },
        labels: { ai_active: 'IA activa' },
        success: null,
        error: null,
        query: {},
        data: {
            summary: {
                conversationsNew: 1, conversationsActive: 1, waitingHuman: 0, ordersToday: 1,
                pendingPayment: 1, transfersToVerify: 0, paid: 0, preparing: 0, ready: 0,
                inNextDeparture: 0, dispatched: 0, delivered: 0, delayed: 0, cancelled: 0,
                paymentLinks: 0, messageErrors: 0, registeredSales: 1000, collectedSales: 0,
                pendingCollection: 1000, deliveryMethods: { retiro: 1 }, alerts: [], lowStock: [],
                notes: ['Los enlaces no son cobros.']
            }
        }
    };
    const html = await ejs.renderFile(view, locals);
    assert.match(html, /WhatsApp AI/);
    assert.match(html, /href="\/admin\/whatsapp"/);
    assert.match(html, /Cobros confirmados/);
    const detail = await ejs.renderFile(view, {
        ...locals,
        section: 'conversaciones',
        data: {
            items: [{ _id: 'abc', waId: '595981000000', profileName: 'Ana', attentionStatus: 'ai_active', lastOrderNumber: '' }],
            admins: [],
            detail: {
                conv: {
                    _id: 'abc', waId: '595981000000', profileName: 'Ana', attentionStatus: 'human_requested',
                    aiPaused: true, history: [{ role: 'user', content: 'Hola ñandú' }], internalNotes: []
                },
                orders: []
            }
        }
    });
    assert.match(detail, /Hola ñandú/);
    assert.match(detail, /Pausar IA/);
    const comprobantes = await ejs.renderFile(view, {
        ...locals,
        section: 'comprobantes',
        data: {
            papelera: false,
            pending: [{
                _id: 'r1',
                waId: '595981000000',
                senderName: 'Ana',
                recipientName: 'Ferumi',
                bankName: 'Ueno',
                extractedAmount: 25000,
                rawText: 'Banco Ueno Para Ferumi De Ana Gs. 25000'
            }],
            trash: []
        }
    });
    assert.match(comprobantes, /name="action" value="confirm"/);
    assert.match(comprobantes, /Banco Ueno Para Ferumi/);
    assert.doesNotMatch(comprobantes, /name="action" value="confirm" type="submit"/);
});

test('pinzas matches pinza products and a denial is replaced', () => {
    const found = rankCatalog([
        { name: 'Pinzas para cejas', description: 'acero', price: 15000, stock: 4 },
        { name: 'Labial', description: 'rojo', price: 25000, stock: 2 }
    ], 'tienen pinzas?');
    assert.equal(found[0].name, 'Pinzas para cejas');
    assert.equal(replyDeniesCatalog('No tenemos pinzas'), true);
    assert.match(catalogReply(found), /Pinzas para cejas/);
});

test('Capiatá ruta 2 uses that price and a general Capiatá does not override it', () => {
    const rates = [
        { id: 'general', method: 'delivery_propio', name: 'Capiatá', city: 'Capiatá', basePrice: 15000, priority: 1, active: true },
        { id: 'ruta', method: 'delivery_propio', name: 'Capiatá ruta 2', city: 'Capiatá ruta 2', basePrice: 20000, priority: 1, active: true }
    ];
    const specific = quoteShipping(rates, { method: 'delivery_propio', city: 'Capiatá', address: 'ruta 2 km 25' });
    assert.equal(specific.amount, 20000);
    assert.equal(specific.ruleId, 'ruta');
    const general = quoteShipping(rates, { method: 'delivery_propio', city: 'Capiatá', address: 'centro' });
    assert.equal(general.amount, 15000);
});

test('PagoPar has no 5000 minimum and shipping is included in the charge', () => {
    const order = agent.canCreateOrder({
        cart: [{ name: 'Pinza', price: 5000, quantity: 1 }],
        customer: { name: 'Ana', document: '123', email: 'a@b.c', phone: '0981' },
        shipping: { method: 'retiro', address: 'Local' }
    });
    assert.equal(order.ok, true);
    assert.equal(order.total, 5000);
    const aligned = pagopar.alignCompraItems([
        { precio_total: 5000, public_key: 'pub', url_imagen: 'https://ferumi.shop/ferumi.logo.png' }
    ], 7000);
    assert.equal(aligned.reduce((sum, item) => sum + item.precio_total, 0), 7000);
    assert.equal(aligned[1].nombre, 'Envio');
});

test('transfer message uses the configured alias and human words are recognized', () => {
    const message = transferMessage({ alias: 'ferumi.ueno', bank: 'Ueno', holderName: 'Ferumi Shop' }, { total: '5.000 Gs.' });
    assert.match(message.text, /ferumi\.ueno/);
    assert.match(message.text, /Ueno/);
    assert.match(message.text, /Ferumi Shop/);
    assert.match(message.text, /comprobante/);
    assert.equal(transferMessage({}).ok, false);
    assert.equal(wantsHuman('humano'), true);
    assert.equal(wantsHuman('quiero hablar con alguien del local'), true);
});

test('a San Lorenzo pin keeps exact coordinates and the city price step comes before payment data', () => {
    const place = describePoint({
        lat: -25.3397,
        lng: -57.5076,
        store: { lat: -25.28646, lng: -57.647 }
    });
    assert.equal(place.city, 'San Lorenzo');
    assert.equal(place.inZone, true);
    assert.match(place.label, /^-25\.3397/);
    const shown = planTurn({
        text: 'tienen pinzas',
        stage: 'browsing',
        products: [{ _id: 'p1', name: 'Pinzas para cejas', price: 15000 }]
    });
    assert.match(shown.replies[0], /Pinzas para cejas/);
    assert.equal(shown.stage, 'browsing');
    const shipping = planTurn({
        text: 'solo eso',
        stage: 'browsing',
        cart: [{ name: 'Pinzas para cejas', price: 15000, quantity: 1 }],
        departureTime: '18:00'
    });
    assert.equal(shipping.stage, 'shipping');
    assert.match(shipping.replies[0], /18:00/);
    assert.match(shipping.replies[0], /Motobolt/);
    assert.match(shipping.replies[0], /Transportadora/);
    const pay = planTurn({
        text: 'delivery propio',
        stage: 'shipping',
        cart: [{ name: 'Pinzas' }],
        place,
        quote: { ok: true, amount: 20000 },
        transfer: { alias: 'ferumi.ueno', bank: 'Ueno', holderName: 'Ferumi' },
        departureTime: '18:00'
    });
    assert.equal(pay.stage, 'payment');
    assert.match(pay.replies.join('\n'), /20\.000/);
    assert.match(pay.replies.join('\n'), /ferumi\.ueno/);
    assert.match(pay.replies.join('\n'), /PagoPar/);
    const cash = planTurn({ text: 'puedo pagar en efectivo?', stage: 'payment', place, departureTime: '18:00' });
    assert.match(cash.replies[0], /día siguiente/);
    const interior = planTurn({
        text: 'efectivo',
        stage: 'payment',
        place: { ...place, inZone: false, interior: true, city: '' }
    });
    assert.match(interior.replies[0], /interior/);
    assert.equal(customerSafeText('PagoPar rechazó la transacción'), 'Seguimos desde acá. Decime si seguís con el producto, el envío o el pago.');
    assert.ok(controlModels().WaSettings.schema.path('transfer.alias'));
    const question = planTurn({
        text: 'Delivery propio sale a las 6?',
        stage: 'shipping',
        cart: [{ name: 'Pinzas para cejas' }],
        products: [{ _id: 'p1', name: 'Pinzas para cejas', price: 15000 }],
        place,
        quote: { ok: true, amount: 20000 },
        chosenMethod: 'delivery_propio',
        departureTime: '18:00'
    });
    assert.equal(question.showProduct, undefined);
    assert.equal(question.handled, true);
    assert.match(question.replies[0], /18:00/);
    assert.match(question.replies[0], /20\.000/);
    assert.doesNotMatch(question.replies.join('\n'), /Pinzas/);
    const complaint = planTurn({
        text: 'no te pedí nada',
        stage: 'browsing',
        products: [{ _id: 'p1', name: 'Pinzas para cejas', price: 15000 }]
    });
    assert.equal(complaint.showProduct, undefined);
    assert.equal(complaint.handled, true);
    assert.doesNotMatch(complaint.replies.join('\n'), /Pinzas/);
    const located = planTurn({
        text: '',
        hasLocation: true,
        stage: 'shipping',
        chosenMethod: 'delivery_propio',
        place,
        quote: { ok: true, amount: 20000 },
        departureTime: '18:00'
    });
    assert.match(located.replies[0], /20\.000/);
    assert.equal(located.stage, 'payment');
    assert.doesNotMatch(located.replies.join('\n'), /maps\.google|google\.com\/maps|-25\.3397|km de/);
});

test('the customer pin is stored exactly and a receipt photo is not another alias', () => {
    const place = describePoint({
        lat: -25.3012345,
        lng: -57.6012345,
        store: { lat: -25.28646, lng: -57.647 }
    });
    assert.equal(place.lat, -25.3012345);
    assert.equal(place.lng, -57.6012345);
    assert.match(place.pinUrl, /q=-25\.3012345,-57\.6012345/);
    assert.equal(parseCoord('-25,3012345'), -25.3012345);
    assert.equal(alreadyClaimsReceipt('ya te mandé el comprobante'), true);
    const parsed = parseTransferText('Banco Ueno. Ordenante: Ana Gomez. Destinatario: Ferumi Shop. Monto Gs. 25000');
    assert.equal(parsed.amount, 25000);
    assert.match(parsed.bank, /Ueno/i);
    assert.match(parsed.recipientName, /Ferumi/);
    assert.match(parsed.senderName, /Ana/);
    const now = new Date('2026-10-29T12:00:00Z');
    assert.equal(trashStillVisible(new Date('2026-10-20T12:00:00Z'), now), true);
    assert.equal(trashStillVisible(new Date('2026-09-01T12:00:00Z'), now), false);
    const read = interpretReceiptVision(`Banco Ueno
Para Ferumi Shop
De Ana Gomez
Gs. 25.000
JSON: {"es_transferencia":true,"monto":25,"banco":"","destinatario":"","emisor":""}`);
    assert.match(read.rawText, /Ferumi Shop/);
    assert.match(read.rawText, /Ana Gomez/);
    assert.equal(read.parsed.amount, 25000);
    assert.match(read.parsed.bank, /Ueno/i);
    assert.match(read.parsed.recipientName, /Ferumi/);
    assert.match(read.parsed.senderName, /Ana/);
    const kept = guardCustomerReply('Tu pago ya está confirmado', { paymentConfirmed: true });
    assert.match(kept, /ya está confirmado/i);
    const corrected = guardCustomerReply('Todavía no está confirmado el pago', { paymentConfirmed: true });
    assert.match(corrected, /ya está confirmada/i);
});
