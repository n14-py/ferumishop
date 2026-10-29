'use strict';

const shop = require('../orders');
const pagopar = require('../pagopar');
const slug = require('../wa-slug');
const { controlModels } = require('./models');
const { recordAudit } = require('./audit');
const {
    paymentFingerprint,
    resolveIntentTarget,
    runLockedCharge,
    shouldSendLink,
    isUncertainProviderError
} = require('./payments');
const { quoteShipping } = require('./rates');
const { renderTemplate, DEFAULT_TEMPLATES, templateByKey } = require('./templates');
const { evaluateRules } = require('./rules');

function formatGs(value) {
    return `${new Intl.NumberFormat('es-PY').format(Math.round(Number(value) || 0))} Gs.`;
}

function mongoIntentStore() {
    const { WaPaymentIntent } = controlModels();
    return {
        async insertIfAbsent(doc) {
            return WaPaymentIntent.create(doc);
        },
        async findByKey(key) {
            return WaPaymentIntent.findOne({ key });
        },
        async updateIfStatus(key, statuses, patch) {
            return WaPaymentIntent.findOneAndUpdate(
                { key, status: { $in: statuses } },
                { $set: { ...patch, updatedAt: new Date() }, $push: { events: { type: patch.status || 'update', at: new Date(), detail: patch.error || '' } } },
                { new: true }
            );
        }
    };
}

function textFromTemplate(templates, key, data, required = []) {
    const found = templateByKey(templates, key) || DEFAULT_TEMPLATES.find((item) => item.key === key);
    if (!found) return '';
    const rendered = renderTemplate(found.body, data, { required });
    return rendered.ok ? rendered.text : '';
}

async function openIntentFor(waId) {
    const { WaPaymentIntent } = controlModels();
    return WaPaymentIntent.findOne({
        waId,
        status: { $in: ['reserved', 'calling', 'uncertain', 'link_ready', 'sent', 'retry_authorized'] }
    }).sort({ updatedAt: -1 });
}

async function loadRuntime() {
    const models = controlModels();
    const [settings, rules, rates, templates] = await Promise.all([
        models.WaSettings.findOne({ key: 'main' }).lean(),
        models.WaRule.find({ active: true }).lean(),
        models.WaRate.find({ active: true }).lean(),
        models.WaTemplate.find({ active: true }).lean()
    ]);
    return { settings, rules, rates, templates };
}

function shippingAmount(quote) {
    if (!quote?.ok || quote.includedInOrder === false || quote.amount == null) return 0;
    return Number(quote.amount) || 0;
}

async function startPagopar(order, deps) {
    if (order.pagoparHash) {
        return { hash: order.pagoparHash, payUrl: slug.publicPayUrl(order.checkoutSlug), orderId: String(order._id) };
    }
    if (order.pagoparAttemptStatus === 'uncertain') {
        return { uncertain: true, orderId: String(order._id), error: 'Hay un intento anterior sin confirmación de PagoPar.' };
    }
    order.pagoparAttemptStatus = 'calling';
    order.pagoparAttemptAt = new Date();
    await order.save();
    try {
        const { result } = await pagopar.iniciarTransaccion({
            orderId: String(order._id),
            montoTotal: order.totalAmount,
            customer: {
                name: order.customerName,
                email: order.customerEmail,
                document: order.customerDocument,
                phone: order.customerPhone,
                address: order.shippingAddress || '',
                reference: order.shippingReference || '',
                coords: order.shippingCoords?.lat != null ? `${order.shippingCoords.lat},${order.shippingCoords.lng}` : ''
            },
            items: order.items,
            descripcion: `FERUMI WA ${order.orderNumber}`,
            timeoutMs: 20000
        });
        if (result?.respuesta === true && result?.resultado?.[0]?.data) {
            order.pagoparHash = result.resultado[0].data;
            order.pagoparAttemptStatus = 'ready';
            order.pagoparAttemptError = '';
            await order.save();
            await recordAudit({
                action: 'pagopar_enlace_creado',
                actor: 'sistema',
                orderId: order._id,
                waId: order.waFrom,
                operationId: order.paymentIntentKey,
                result: 'enlace_listo'
            });
            const expires = new Date(Date.now() + (3 * 24 * 60 * 60 * 1000));
            return {
                hash: order.pagoparHash,
                payUrl: slug.publicPayUrl(order.checkoutSlug),
                orderId: String(order._id),
                expiresAt: expires
            };
        }
        order.pagoparAttemptStatus = 'failed';
        const detail = Array.isArray(result?.resultado) ? JSON.stringify(result.resultado).slice(0, 240) : String(result?.resultado || 'sin detalle').slice(0, 240);
        order.pagoparAttemptError = detail;
        await order.save();
        const error = new Error(`No se pudo generar el enlace de PagoPar. ${detail}`);
        error.uncertain = false;
        throw error;
    } catch (err) {
        if (order.pagoparHash) {
            return { hash: order.pagoparHash, payUrl: slug.publicPayUrl(order.checkoutSlug), orderId: String(order._id) };
        }
        if (isUncertainProviderError(err) || err.uncertain) {
            order.pagoparAttemptStatus = 'uncertain';
            order.pagoparAttemptError = String(err.message || 'sin confirmación').slice(0, 240);
            await order.save();
            await recordAudit({
                action: 'pagopar_incierto',
                status: 'uncertain',
                actor: 'sistema',
                orderId: order._id,
                waId: order.waFrom,
                error: order.pagoparAttemptError
            });
            return { uncertain: true, orderId: String(order._id), error: order.pagoparAttemptError };
        }
        if (order.pagoparAttemptStatus === 'calling') {
            order.pagoparAttemptStatus = 'failed';
            order.pagoparAttemptError = String(err.message || 'error').slice(0, 240);
            await order.save();
        }
        throw err;
    }
}

async function buildWhatsAppOrder({ conv, deps, quote, key, siteConfig }) {
    const { Product, WebOrder } = deps;
    const existing = await WebOrder.findOne({ idempotencyKey: `wapay-${key}`, deletedAt: { $exists: false } });
    if (existing) return existing;
    const customer = conv.customer || {};
    const shipping = conv.shipping || {};
    const normalizedItems = (conv.cart || []).map((item) => ({
        productId: item.productId,
        variantName: item.variantName || '',
        name: item.name,
        quantity: parseInt(item.quantity, 10) || 1,
        price: shop.parsePrice(item.price),
        image: item.image || ''
    }));
    await shop.ensureStockAvailable(Product, normalizedItems);
    let subtotal = 0;
    for (const item of normalizedItems) subtotal += item.price * item.quantity;
    const shipCost = shippingAmount(quote);
    const total = subtotal + shipCost;
    if (total <= 0) {
        const error = new Error('El total del pedido no es válido.');
        error.uncertain = false;
        throw error;
    }
    const phone = customer.phone || conv.waId;
    const name = customer.name;
    let checkoutSlug = slug.makeCheckoutSlug({ phone, name });
    if (await WebOrder.exists({ checkoutSlug })) {
        for (let i = 2; i < 30; i += 1) {
            const candidate = slug.makeCheckoutSlug({ phone, name, suffix: String(i) });
            if (!await WebOrder.exists({ checkoutSlug: candidate })) {
                checkoutSlug = candidate;
                break;
            }
        }
    }
    const order = new WebOrder({
        orderNumber: shop.makeOrderNumber(),
        ticketCode: shop.makeTicketCode(),
        idempotencyKey: `wapay-${key}`,
        paymentIntentKey: key,
        source: 'whatsapp',
        checkoutSlug,
        waFrom: conv.waId,
        customerName: name,
        customerEmail: String(customer.email).toLowerCase().trim(),
        customerDocument: String(customer.document).replace(/\D/g, ''),
        customerPhone: phone,
        items: normalizedItems,
        subtotal,
        shippingCost: shipCost,
        shippingQuote: quote,
        totalAmount: total,
        status: 'pendiente',
        commercialStatus: 'confirmado',
        financialStatus: 'pendiente',
        logisticsStatus: 'pendiente_preparacion',
        paymentMethod: 'pagopar',
        paymentStatus: 'pendiente',
        shippingMethod: shipping.method,
        shippingAddress: shipping.address || '',
        shippingCity: shipping.city || '',
        shippingZone: shipping.zone || '',
        shippingReference: shipping.reference || '',
        shippingCoords: (shipping.lat != null && shipping.lng != null) ? { lat: shipping.lat, lng: shipping.lng } : undefined,
        shippingDistanceKm: shipping.distanceKm,
        housePhotoUrl: conv.housePhotoUrl || '',
        fulfillmentStatus: shop.FULFILLMENT.PENDIENTE_PAGO,
        amountPaid: 0,
        statusLog: [{ domain: 'comercial', to: 'confirmado', by: 'whatsapp', reason: 'Confirmado por el cliente', at: new Date() }]
    });
    shop.appendEvent(order, shop.FULFILLMENT.PENDIENTE_PAGO, 'Pedido de WhatsApp creado. El pago todavía no está confirmado.');
    try {
        await order.save();
    } catch (err) {
        if (err?.code === 11000) {
            const again = await WebOrder.findOne({ idempotencyKey: `wapay-${key}` });
            if (again) return again;
        }
        throw err;
    }
    await recordAudit({
        action: 'pedido_creado',
        actor: 'whatsapp',
        orderId: order._id,
        waId: conv.waId,
        operationId: key,
        result: order.orderNumber
    });
    return order;
}

function customerPayload(order, quote) {
    return {
        customerName: order.customerName,
        orderNumber: order.orderNumber,
        items: (order.items || []).map((item) => `${item.quantity}x ${item.name}`).join('\n'),
        total: formatGs(order.totalAmount),
        shippingCost: quote?.priced === false ? 'a coordinar' : formatGs(order.shippingCost || 0),
        method: order.shippingMethod,
        payUrl: slug.publicPayUrl(order.checkoutSlug),
        status: order.financialStatus || order.paymentStatus,
        ticketCode: order.ticketCode
    };
}

async function ensureConversationPayment(conv, deps, { mode = 'create', explicit = false, admin = false, siteConfig } = {}) {
    const runtime = await loadRuntime().catch(() => ({ settings: null, rules: [], rates: [], templates: [] }));
    const shipping = conv.shipping || {};
    const cart = conv.cart || [];
    const subtotal = cart.reduce((sum, item) => sum + (Number(item.price) || 0) * (Number(item.quantity) || 0), 0);
    const quote = quoteShipping(runtime.rates, {
        method: shipping.method,
        city: shipping.city,
        zone: shipping.zone,
        neighborhood: shipping.neighborhood,
        address: shipping.address,
        subtotal,
        far: Boolean(shipping.far)
    });
    const decisions = evaluateRules(runtime.rules, {
        method: shipping.method,
        paymentMethods: runtime.settings?.paymentMatrix?.[shipping.method] || [],
        stockOk: true,
        afterCutoff: false,
        needsHuman: false,
        requiresPayment: true,
        paymentConfirmed: false
    }).decisions;
    if (shipping.method === 'delivery_propio' && !quote.ok) {
        return { ok: false, code: quote.conflict ? 'conflicto_tarifa' : 'sin_tarifa', message: quote.conflict
            ? 'Hay dos tarifas en conflicto para ese destino. No calculo el envío hasta que un administrador lo resuelva.'
            : 'No tengo una tarifa cargada para ese destino. No invento el precio del delivery.' };
    }
    if (decisions.blockConfirm) {
        return { ok: false, code: 'regla', message: 'Una regla comercial impide confirmar este pedido.' };
    }
    const totalForFingerprint = subtotal + shippingAmount(quote);
    const fingerprint = paymentFingerprint({
        waId: conv.waId,
        cart,
        shipping,
        total: totalForFingerprint,
        customer: conv.customer
    });
    const open = await openIntentFor(conv.waId);
    const target = resolveIntentTarget({
        openIntent: open,
        fingerprint,
        cartEmpty: cart.length === 0,
        mode
    });
    const templates = runtime.templates?.length ? runtime.templates : DEFAULT_TEMPLATES;
    if (target.action === 'blocked') {
        const message = target.reason === 'uncertain'
            ? 'El enlace anterior quedó sin confirmación de PagoPar. No genero otro hasta que se revise.'
            : 'Ya hay un enlace de pago en proceso. No genero otro.';
        return { ok: false, code: target.reason, message, intent: target.intent };
    }
    if (target.action === 'paid') {
        return { ok: true, code: 'pagado', send: false, message: 'Ese pedido ya figura con el pago confirmado.', intent: target.intent };
    }
    if (target.action === 'reuse' && target.intent) {
        const intent = target.intent;
        if (intent.expiresAt && new Date(intent.expiresAt).getTime() < Date.now()) {
            return { ok: false, code: 'vencido', message: 'El enlace venció. Un administrador tiene que autorizar uno nuevo. No lo regenero solo.' };
        }
        const decision = shouldSendLink(intent, {
            explicit,
            admin,
            cooldownMs: Number(process.env.WA_PAYMENT_LINK_RESEND_COOLDOWN_MS || 120000)
        });
        const order = intent.orderId ? await deps.WebOrder.findById(intent.orderId) : null;
        const data = order ? customerPayload(order, order.shippingQuote) : { payUrl: intent.payUrl, orderNumber: '' };
        if (!decision.send) {
            const reminder = textFromTemplate(templates, 'payment_link_sent', data) || 'El enlace de pago ya fue enviado y sigue siendo el mismo. No generé otro.';
            return { ok: true, reused: true, send: decision.reason !== 'ya_enviado', message: decision.reason === 'ya_enviado' ? reminder : '', silent: decision.reason === 'ya_enviado', intent, order };
        }
        const message = textFromTemplate(templates, 'payment_link', data, ['orderNumber', 'total', 'payUrl'])
            || `Tu enlace de pago sigue vigente:\n${data.payUrl}`;
        return { ok: true, reused: true, send: true, message, intent, order, payUrl: data.payUrl };
    }

    const key = target.key || fingerprint;
    const store = mongoIntentStore();
    const result = await runLockedCharge(store, {
        key,
        fingerprint,
        extra: { waId: conv.waId },
        createCharge: async () => {
            const order = await buildWhatsAppOrder({ conv, deps, quote, key, siteConfig });
            await controlModels().WaPaymentIntent.updateOne({ key }, { $set: { waId: conv.waId, orderId: String(order._id) } });
            return startPagopar(order, deps);
        }
    });
    if (result.outcome === 'uncertain' || result.outcome === 'in_progress') {
        return {
            ok: false,
            code: result.outcome,
            message: 'PagoPar no confirmó el enlace. Dejé la operación en revisión y no generé otro.',
            intent: result.intent
        };
    }
    if (result.outcome === 'expired') {
        return { ok: false, code: 'vencido', message: 'El enlace venció. Hace falta una autorización para generar otro.', intent: result.intent };
    }
    if (result.outcome === 'failed') {
        return {
            ok: false,
            code: 'failed',
            message: 'No pude generar el enlace de PagoPar en este intento. No digas que el pago fue rechazado. Ofrecé intentar de nuevo o pagar por transferencia si hay alias cargado.',
            detail: result.intent?.error || '',
            intent: result.intent
        };
    }
    const intent = result.intent;
    const order = intent?.orderId ? await deps.WebOrder.findById(intent.orderId) : null;
    if (result.outcome === 'created' && target.action === 'supersede' && target.intent?.orderId) {
        const previous = await deps.WebOrder.findById(target.intent.orderId);
        if (previous && previous.paymentStatus !== 'pagado' && String(previous._id) !== String(order?._id)) {
            shop.appendEvent(previous, shop.FULFILLMENT.CANCELADO, 'Reemplazado por un pedido nuevo confirmado.');
            previous.status = 'cancelado';
            previous.paymentStatus = 'cancelado';
            previous.commercialStatus = 'cancelado';
            await previous.save();
            await controlModels().WaPaymentIntent.updateOne({ key: target.intent.key }, { $set: { status: 'failed', error: 'reemplazado' } });
        }
    }
    if (result.outcome === 'reuse') {
        const decision = shouldSendLink(intent, { explicit, admin, queuedInTurn: false });
        const data = order ? customerPayload(order, order.shippingQuote) : { payUrl: intent.payUrl, orderNumber: '', total: '' };
        if (!decision.send) {
            return { ok: true, reused: true, send: false, silent: true, message: 'El enlace de pago ya fue enviado y sigue siendo el mismo. No generé otro.', intent, order };
        }
    }
    const data = order ? customerPayload(order, quote) : { payUrl: intent?.payUrl || '', orderNumber: '', total: '' };
    const message = textFromTemplate(templates, 'payment_link', data, ['orderNumber', 'total', 'payUrl'])
        || `Listo. Pedido ${data.orderNumber}. Total ${data.total}. Enlace: ${data.payUrl}`;
    if (order) {
        conv.lastOrderId = order._id;
        conv.lastOrderNumber = order.orderNumber;
        conv.lastCheckoutSlug = order.checkoutSlug;
        conv.awaitingConfirm = false;
        if (result.outcome === 'created') conv.cart = [];
    }
    return {
        ok: true,
        created: result.outcome === 'created',
        reused: result.outcome !== 'created',
        send: true,
        message,
        payUrl: data.payUrl,
        order,
        intent
    };
}

async function ensurePagoparHash(order) {
    if (!order) return { ok: false, message: 'Pedido inexistente.' };
    if (order.pagoparHash) return { ok: true, hash: order.pagoparHash, reused: true };
    if (order.pagoparAttemptStatus === 'uncertain') {
        return { ok: false, uncertain: true, message: 'Este pedido tiene un intento de PagoPar sin confirmación. No genero otro enlace.' };
    }
    const key = order.paymentIntentKey || `order-${order._id}`;
    const store = mongoIntentStore();
    const result = await runLockedCharge(store, {
        key,
        fingerprint: key,
        createCharge: async () => {
            await controlModels().WaPaymentIntent.updateOne({ key }, { $set: { waId: order.waFrom || '', orderId: String(order._id) } });
            if (!order.paymentIntentKey) {
                order.paymentIntentKey = key;
                await order.save();
            }
            return startPagopar(order);
        }
    });
    if (result.outcome === 'created' || result.outcome === 'reuse') {
        return { ok: true, hash: result.intent?.hash || order.pagoparHash, reused: result.outcome === 'reuse', payUrl: result.intent?.payUrl };
    }
    return { ok: false, uncertain: result.outcome === 'uncertain' || result.outcome === 'in_progress', message: 'No pude confirmar el enlace con PagoPar.' };
}

async function markPaymentLinkSent(intentKey) {
    if (!intentKey) return null;
    const { WaPaymentIntent } = controlModels();
    return WaPaymentIntent.findOneAndUpdate(
        { key: intentKey, status: { $in: ['link_ready', 'sent'] } },
        { $set: { status: 'sent', linkSendStatus: 'sent', linkSentAt: new Date(), updatedAt: new Date() } },
        { new: true }
    );
}

module.exports = {
    formatGs,
    ensureConversationPayment,
    ensurePagoparHash,
    markPaymentLinkSent,
    mongoIntentStore,
    shippingAmount
};
