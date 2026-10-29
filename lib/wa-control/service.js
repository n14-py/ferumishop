'use strict';

const crypto = require('crypto');
const mongoose = require('mongoose');
const shop = require('../orders');
const wa = require('../whatsapp');
const deepinfra = require('../deepinfra');
const pagopar = require('../pagopar');
const { controlModels } = require('./models');
const { recordAudit } = require('./audit');
const { DEFAULT_AI, diffSnapshots } = require('./prompt');
const { DEFAULT_TEMPLATES, validateTemplate } = require('./templates');
const { DEFAULT_RULES } = require('./rules');
const { quoteShipping, resolvePlace } = require('./rates');
const { summarizeOperations } = require('./dashboard');
const { simulateTurn, SCENARIOS } = require('./simulator');
const {
    situationIsLive, orderMatchesScope, situationConflicts, proposedDate, CATEGORIES
} = require('./situations');
const {
    planDispatchNotifications, canDispatch, afterCutoff, zonedParts
} = require('./departures');
const { ATTENTION_LABELS, canTransition, FINANCIAL_TRANSITIONS, LOGISTICS_TRANSITIONS, legacyFulfillmentForLogistics, attentionAfter } = require('./states');
const { assessReceipt, receiptFingerprint } = require('./payments');
const { visionStatus } = require('./vision');
const { ensurePagoparHash } = require('./checkout');
const { redactSecrets } = require('./text');

const DEFAULT_SETTINGS = {
    timezone: 'America/Asuncion',
    departureTime: '18:00',
    cutoffTime: '17:30',
    serviceDays: [1, 2, 3, 4, 5, 6],
    requirePaidBeforeDispatch: true,
    paymentMatrix: {
        motobolt: ['pagopar', 'transferencia'],
        transportadora: ['pagopar', 'transferencia'],
        retiro: ['pagopar', 'efectivo'],
        delivery_propio: ['pagopar', 'transferencia']
    },
    partialPayments: { enabled: false, minAmount: 0, maxDays: 0, reserveHours: 0 },
    transfer: { alias: '', bank: '', holderName: '', note: '' },
    pickup: { available: true, hours: '09:00 a 20:00', requirements: 'El efectivo solo aplica si el retiro está habilitado.' },
    followup: { enabled: false, maxPerConversation: 1, minHours: 20 }
};

const DEFAULT_CARRIERS = [
    {
        key: 'tsi',
        name: 'Transportadora TSI',
        active: true,
        tariffMode: 'unknown',
        notes: 'Mencionada en la operación actual. No hay tarifa ni horario cargados: no se inventan.'
    },
    {
        key: 'jaraha',
        name: 'Transportadora Jaraha',
        active: true,
        tariffMode: 'unknown',
        notes: 'Mencionada en la operación actual. No hay tarifa ni horario cargados: no se inventan.'
    }
];

const DEFAULT_AUTOMATIONS = [
    { key: 'expire_situations', name: 'Vencer situaciones extraordinarias', enabled: true, intervalMinutes: 5, external: false },
    { key: 'stale_payments', name: 'Marcar pagos inciertos', enabled: true, intervalMinutes: 5, external: false },
    { key: 'stuck_inbound', name: 'Detectar mensajes trabados', enabled: true, intervalMinutes: 5, external: false },
    { key: 'expire_reservations', name: 'Liberar reservas vencidas', enabled: true, intervalMinutes: 10, external: false },
    { key: 'departure_prepare', name: 'Revisar salida del día', enabled: true, intervalMinutes: 15, external: false },
    { key: 'payment_reminder', name: 'Recordar pagos pendientes', enabled: false, intervalMinutes: 360, external: true },
    { key: 'followup', name: 'Seguimientos comerciales', enabled: false, intervalMinutes: 360, external: true },
    { key: 'failed_message_retry', name: 'Reintentar mensajes fallidos', enabled: false, intervalMinutes: 15, external: true }
];

function actorOf(user) {
    return user?.username || user?.email || 'admin';
}

function conversationsModel() {
    return mongoose.model('WaConversation');
}

function clean(value, max = 4000) {
    return String(value || '').replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F]/g, '').trim().slice(0, max);
}

async function ensureDefaults() {
    const models = controlModels();
    if (!await models.WaSettings.exists({ key: 'main' })) {
        await models.WaSettings.create({ key: 'main', ...DEFAULT_SETTINGS });
    }
    if (!await models.WaAiProfile.exists({ key: 'published' })) {
        await models.WaAiProfile.create({ key: 'published', snapshot: DEFAULT_AI, version: 1, updatedBy: 'sistema' });
        await models.WaAiRevision.create({ version: 1, status: 'published', snapshot: DEFAULT_AI, diff: [], author: 'sistema' });
    }
    if (!await models.WaTemplate.exists({})) {
        await models.WaTemplate.insertMany(DEFAULT_TEMPLATES.map((item) => ({ ...item, author: 'sistema' })));
    }
    if (!await models.WaRule.exists({})) {
        await models.WaRule.insertMany(DEFAULT_RULES.map((item) => ({ ...item, author: 'sistema' })));
    }
    for (const carrier of DEFAULT_CARRIERS) {
        await models.WaCarrier.updateOne({ key: carrier.key }, { $setOnInsert: carrier }, { upsert: true });
    }
    for (const job of DEFAULT_AUTOMATIONS) {
        await models.WaAutomation.updateOne({ key: job.key }, { $setOnInsert: { ...job, timezone: 'America/Asuncion' } }, { upsert: true });
    }
}

async function publishedAi() {
    const doc = await controlModels().WaAiProfile.findOne({ key: 'published' }).lean();
    return { ...DEFAULT_AI, ...(doc?.snapshot || {}) };
}

async function saveAiDraft(snapshot, user) {
    const models = controlModels();
    const published = await models.WaAiProfile.findOne({ key: 'published' }).lean();
    const version = (published?.version || 0) + 1;
    const diff = diffSnapshots(published?.snapshot || {}, snapshot);
    await models.WaAiProfile.updateOne(
        { key: 'draft' },
        { $set: { snapshot, version, updatedAt: new Date(), updatedBy: actorOf(user) } },
        { upsert: true }
    );
    const revision = await models.WaAiRevision.create({
        version, status: 'draft', snapshot, diff, author: actorOf(user)
    });
    await recordAudit({ action: 'ia_borrador', actor: actorOf(user), result: `version ${version}` });
    return revision;
}

async function publishAi(version, user) {
    const models = controlModels();
    const revision = await models.WaAiRevision.findOne({ version: Number(version) });
    if (!revision) return { ok: false, message: 'No encontré esa versión.' };
    const published = await models.WaAiProfile.findOne({ key: 'published' }).lean();
    revision.status = 'published';
    await revision.save();
    await models.WaAiProfile.updateOne(
        { key: 'published' },
        { $set: { snapshot: revision.snapshot, version: revision.version, updatedAt: new Date(), updatedBy: actorOf(user) } },
        { upsert: true }
    );
    await recordAudit({
        action: 'ia_publicada',
        actor: actorOf(user),
        before: { version: published?.version || 0 },
        after: { version: revision.version },
        result: 'publicada'
    });
    return { ok: true, version: revision.version };
}

async function dashboardData(filters = {}) {
    const WebOrder = mongoose.model('WebOrder');
    const Product = mongoose.model('Product');
    const models = controlModels();
    const from = filters.from ? new Date(filters.from) : new Date(new Date().setHours(0, 0, 0, 0));
    const to = filters.to ? new Date(filters.to) : new Date();
    const [orders, conversations, intents, outbounds, products, receipts, departures] = await Promise.all([
        WebOrder.find({ deletedAt: { $exists: false } }).sort({ createdAt: -1 }).limit(400).lean(),
        conversationsModel().find({}).sort({ updatedAt: -1 }).limit(400).lean(),
        models.WaPaymentIntent.find({}).sort({ updatedAt: -1 }).limit(200).lean(),
        models.WaOutbound.find({}).sort({ createdAt: -1 }).limit(200).lean(),
        Product.find({ isForSale: true }).select('name stock hasVariants variants aiVisible').limit(300).lean(),
        models.WaReceipt.find({}).sort({ createdAt: -1 }).limit(200).lean(),
        models.WaDeparture.find({ status: { $nin: ['finalizada', 'cancelada'] } }).lean()
    ]);
    const summary = summarizeOperations({
        orders, conversations, intents, outbounds, products, receipts,
        departures: departures.map((item) => ({ ...item, unprepared: 0 })),
        filters: { ...filters, from, to }
    });
    return { summary, filters: { ...filters, from, to } };
}

function escapeRegex(value) {
    return String(value || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

async function listConversations({ q, status, page = 1 }) {
    const query = {};
    if (status === 'humanos') {
        query.attentionStatus = { $in: ['human_requested', 'human_active', 'pending_resolution'] };
    } else if (status) query.attentionStatus = status;
    if (q) {
        const rx = new RegExp(escapeRegex(q), 'i');
        query.$or = [{ waId: rx }, { profileName: rx }, { lastOrderNumber: rx }, { 'customer.name': rx }];
    }
    const limit = 30;
    const skip = (Math.max(1, Number(page)) - 1) * limit;
    const [items, total] = await Promise.all([
        conversationsModel().find(query).sort({ updatedAt: -1 }).skip(skip).limit(limit).lean(),
        conversationsModel().countDocuments(query)
    ]);
    return { items, total, page: Number(page) || 1, pages: Math.max(1, Math.ceil(total / limit)) };
}

async function getConversation(id) {
    const conv = await conversationsModel().findById(id).lean();
    if (!conv) return null;
    const WebOrder = mongoose.model('WebOrder');
    const orders = await WebOrder.find({
        deletedAt: { $exists: false },
        $or: [{ waFrom: conv.waId }, { customerPhone: conv.waId }]
    }).sort({ createdAt: -1 }).limit(20).lean();
    const models = controlModels();
    const [receipts, audits, intents] = await Promise.all([
        models.WaReceipt.find({ waId: conv.waId }).sort({ createdAt: -1 }).limit(20).lean(),
        models.WaAudit.find({ waId: conv.waId }).sort({ at: -1 }).limit(30).lean(),
        models.WaPaymentIntent.find({ waId: conv.waId }).sort({ updatedAt: -1 }).limit(10).lean()
    ]);
    return { conv, orders, receipts, audits, intents, attentionLabels: ATTENTION_LABELS };
}

async function setAttention(id, action, user, target) {
    const conv = await conversationsModel().findById(id);
    if (!conv) return { ok: false, message: 'Conversación no encontrada.' };
    const before = { attentionStatus: conv.attentionStatus, aiPaused: conv.aiPaused };
    const next = attentionAfter(action, conv);
    conv.attentionStatus = next.attentionStatus;
    conv.aiPaused = next.aiPaused;
    if (action === 'takeover' || action === 'transfer') {
        conv.humanOwnerId = target?.id || String(user?._id || '');
        conv.humanOwnerName = target?.name || actorOf(user);
        conv.aiPaused = true;
        conv.attentionStatus = 'human_active';
    }
    if (action === 'release' || action === 'resume') {
        conv.humanOwnerId = '';
        conv.humanOwnerName = '';
    }
    conv.updatedAt = new Date();
    await conv.save();
    await recordAudit({
        action: `atencion_${action}`,
        actor: actorOf(user),
        waId: conv.waId,
        before,
        after: { attentionStatus: conv.attentionStatus, aiPaused: conv.aiPaused }
    });
    return { ok: true, conv };
}

async function addInternalNote(id, text, user) {
    const conv = await conversationsModel().findById(id);
    if (!conv) return { ok: false, message: 'Conversación no encontrada.' };
    conv.internalNotes = conv.internalNotes || [];
    conv.internalNotes.push({ text: clean(text, 2000), author: actorOf(user), at: new Date() });
    await conv.save();
    await recordAudit({ action: 'nota_interna', actor: actorOf(user), waId: conv.waId, result: 'guardada' });
    return { ok: true };
}

async function sendManualMessage(id, text, user) {
    const conv = await conversationsModel().findById(id);
    if (!conv) return { ok: false, message: 'Conversación no encontrada.' };
    const body = clean(text, 3500);
    if (!body) return { ok: false, message: 'El mensaje está vacío.' };
    if (!wa.config().ok) return { ok: false, message: 'WhatsApp no está configurado en el servidor. No envié el mensaje.' };
    const next = attentionAfter('takeover', conv);
    conv.aiPaused = true;
    conv.attentionStatus = next.attentionStatus === 'ai_paused' ? 'human_active' : 'human_active';
    conv.humanOwnerId = String(user?._id || '');
    conv.humanOwnerName = actorOf(user);
    const key = `manual:${conv.waId}:${crypto.createHash('sha1').update(body).digest('hex').slice(0, 12)}:${Date.now()}`;
    const { WaOutbound } = controlModels();
    const outbound = await WaOutbound.create({ key, waId: conv.waId, purpose: 'manual', status: 'sending' });
    try {
        const result = await wa.sendText(conv.waId, body);
        outbound.status = 'sent';
        outbound.sentAt = new Date();
        outbound.providerId = result?.messages?.[0]?.id || '';
        await outbound.save();
        conv.history = conv.history || [];
        conv.history.push({ role: 'assistant', content: body, at: new Date() });
        conv.updatedAt = new Date();
        await conv.save();
        await recordAudit({ action: 'mensaje_manual', actor: actorOf(user), waId: conv.waId, result: 'enviado' });
        return { ok: true };
    } catch (err) {
        outbound.status = 'failed';
        outbound.error = String(err.message || '').slice(0, 240);
        await outbound.save();
        await recordAudit({ action: 'mensaje_manual', status: 'error', actor: actorOf(user), waId: conv.waId, error: outbound.error });
        return { ok: false, message: 'WhatsApp rechazó el envío. Quedó registrado el fallo.' };
    }
}

async function listOrders(filters = {}) {
    const WebOrder = mongoose.model('WebOrder');
    const query = { deletedAt: { $exists: false } };
    if (filters.q) {
        const rx = new RegExp(escapeRegex(filters.q), 'i');
        query.$or = [{ orderNumber: rx }, { customerName: rx }, { customerPhone: rx }, { ticketCode: rx }];
    }
    if (filters.shippingMethod) query.shippingMethod = filters.shippingMethod;
    if (filters.paymentStatus) query.paymentStatus = filters.paymentStatus;
    const page = Math.max(1, Number(filters.page) || 1);
    const limit = 25;
    const [items, total] = await Promise.all([
        WebOrder.find(query).sort({ createdAt: -1 }).skip((page - 1) * limit).limit(limit).lean(),
        WebOrder.countDocuments(query)
    ]);
    return { items, total, page, pages: Math.max(1, Math.ceil(total / limit)) };
}

async function getOrder(id) {
    const WebOrder = mongoose.model('WebOrder');
    const order = await WebOrder.findById(id).lean();
    if (!order) return null;
    const receipts = await controlModels().WaReceipt.find({ orderId: String(order._id) }).lean();
    return { order, receipts };
}

async function changeOrder(id, patch, user) {
    const WebOrder = mongoose.model('WebOrder');
    const order = await WebOrder.findById(id);
    if (!order) return { ok: false, message: 'Pedido no encontrado.' };
    const reason = clean(patch.reason, 500);
    if (!reason) return { ok: false, message: 'Indicá el motivo del cambio.' };
    const before = {
        financialStatus: order.financialStatus || order.paymentStatus,
        logisticsStatus: order.logisticsStatus || order.fulfillmentStatus,
        shippingCost: order.shippingCost
    };
    if (patch.financialStatus && patch.financialStatus !== before.financialStatus) {
        const from = before.financialStatus || 'pendiente';
        if (!canTransition(FINANCIAL_TRANSITIONS, from, patch.financialStatus) && from !== patch.financialStatus) {
            return { ok: false, message: `No se puede pasar el pago de ${from} a ${patch.financialStatus}.` };
        }
        if (patch.financialStatus === 'confirmado' && order.paymentStatus !== 'pagado') {
            return { ok: false, message: 'Para confirmar el pago usá la verificación de comprobantes o PagoPar, no un cambio suelto.' };
        }
        order.financialStatus = patch.financialStatus;
    }
    if (patch.logisticsStatus && patch.logisticsStatus !== (order.logisticsStatus || '')) {
        const from = order.logisticsStatus || 'pendiente_preparacion';
        if (order.logisticsStatus && !canTransition(LOGISTICS_TRANSITIONS, from, patch.logisticsStatus)) {
            return { ok: false, message: `Transición logística no permitida: ${from} → ${patch.logisticsStatus}.` };
        }
        order.logisticsStatus = patch.logisticsStatus;
        order.fulfillmentStatus = legacyFulfillmentForLogistics(patch.logisticsStatus, order.shippingMethod);
    }
    if (patch.shippingMethod && ['motobolt', 'transportadora', 'retiro', 'delivery_propio'].includes(patch.shippingMethod)) {
        order.shippingMethod = patch.shippingMethod;
    }
    if (patch.shippingAddress != null) order.shippingAddress = clean(patch.shippingAddress, 400);
    if (patch.shippingCity != null) order.shippingCity = clean(patch.shippingCity, 120);
    if (patch.scheduledFor) order.scheduledFor = new Date(patch.scheduledFor);
    if (patch.note) {
        order.internalNotes = order.internalNotes || [];
        order.internalNotes.push({ text: clean(patch.note, 2000), by: actorOf(user), at: new Date() });
    }
    order.statusLog = order.statusLog || [];
    order.statusLog.push({
        domain: 'admin',
        from: JSON.stringify(before),
        to: patch.financialStatus || patch.logisticsStatus || 'datos',
        by: actorOf(user),
        reason,
        at: new Date()
    });
    await order.save();
    await recordAudit({ action: 'pedido_modificado', actor: actorOf(user), orderId: order._id, before, after: patch, result: reason });
    return { ok: true, order };
}

async function quote(input) {
    const rates = await controlModels().WaRate.find({ active: true }).lean();
    const places = await controlModels().WaPlace.find({ active: true }).lean();
    const place = input.city ? resolvePlace(input.city, places) : { status: 'missing' };
    if (place.status === 'ambiguous') {
        return { ok: false, reason: 'destino_ambiguo', candidates: place.candidates.map((item) => item.name) };
    }
    const city = place.place?.name || input.city;
    const result = quoteShipping(rates, { ...input, city }, input.date ? new Date(input.date) : new Date());
    return { ...result, city, placeStatus: place.status || 'sin_catalogo' };
}

async function saveRate(body, user, id) {
    const payload = {
        name: clean(body.name, 120),
        method: clean(body.method, 40),
        city: clean(body.city, 120),
        zone: clean(body.zone, 120),
        neighborhood: clean(body.neighborhood, 120),
        department: clean(body.department, 120),
        basePrice: body.basePrice === '' || body.basePrice == null ? null : Number(body.basePrice),
        eta: clean(body.eta, 160),
        priority: Number(body.priority) || 0,
        active: body.active !== 'false' && body.active !== false,
        notes: clean(body.notes, 1000),
        author: actorOf(user),
        freeFrom: body.freeFrom === '' || body.freeFrom == null ? null : Number(body.freeFrom)
    };
    if (!payload.city && payload.name) payload.city = payload.name;
    payload.matchText = [payload.neighborhood, payload.zone, payload.city, payload.name].filter(Boolean).join(' ');
    if (!payload.method || payload.basePrice == null || Number.isNaN(payload.basePrice)) {
        return { ok: false, message: 'La tarifa necesita modalidad y precio. No guardo un precio vacío.' };
    }
    const models = controlModels();
    const doc = id ? await models.WaRate.findByIdAndUpdate(id, payload, { new: true }) : await models.WaRate.create(payload);
    await recordAudit({ action: id ? 'tarifa_editada' : 'tarifa_creada', actor: actorOf(user), result: payload.name || payload.city });
    return { ok: true, doc };
}

async function dispatchDeparture(id, user, confirm) {
    if (confirm !== 'SALIO') return { ok: false, message: 'Confirmá escribiendo SALIO. Todavía no notifiqué a nadie.' };
    const models = controlModels();
    const departure = await models.WaDeparture.findById(id);
    if (!departure) return { ok: false, message: 'Salida no encontrada.' };
    if (!canDispatch(departure)) return { ok: false, message: 'Esa salida ya fue despachada, finalizada o cancelada.' };
    const WebOrder = mongoose.model('WebOrder');
    const orders = await WebOrder.find({ _id: { $in: departure.orderIds || [] }, deletedAt: { $exists: false } }).lean();
    const settings = await models.WaSettings.findOne({ key: 'main' }).lean();
    const plan = planDispatchNotifications(departure.toObject(), orders, settings || DEFAULT_SETTINGS);
    const sent = [];
    const failed = [];
    for (const item of plan.pending) {
        const order = orders.find((row) => String(row._id) === item.id);
        if (!order?.waFrom) {
            failed.push({ orderId: item.id, error: 'sin WhatsApp' });
            continue;
        }
        if (!wa.config().ok) {
            failed.push({ orderId: item.id, error: 'WhatsApp no configurado' });
            continue;
        }
        const claimKey = `departure:${departure._id}:${item.id}`;
        try {
            await models.WaOutbound.create({ key: claimKey, waId: order.waFrom, purpose: 'departure', status: 'sending' });
        } catch (err) {
            if (err?.code === 11000) continue;
            throw err;
        }
        try {
            await wa.sendText(order.waFrom, `El delivery de Ferumi ya salió con tu pedido ${order.orderNumber}.`);
            await models.WaOutbound.updateOne({ key: claimKey }, { $set: { status: 'sent', sentAt: new Date() } });
            sent.push(item.id);
        } catch (err) {
            await models.WaOutbound.updateOne({ key: claimKey }, { $set: { status: 'failed', error: String(err.message || '').slice(0, 200) } });
            failed.push({ orderId: item.id, error: 'falló el envío' });
        }
    }
    departure.status = 'despachada';
    departure.dispatchedAt = new Date();
    departure.responsible = actorOf(user);
    departure.notified = [
        ...(departure.notified || []),
        ...sent.map((orderId) => ({ orderId, status: 'sent', at: new Date(), error: '' })),
        ...failed.map((item) => ({ orderId: item.orderId, status: 'failed', at: new Date(), error: item.error }))
    ];
    await departure.save();
    if (sent.length) {
        await WebOrder.updateMany({ _id: { $in: sent } }, { $set: { logisticsStatus: 'despachado', fulfillmentStatus: 'enviando' } });
    }
    await recordAudit({
        action: 'salida_despachada',
        actor: actorOf(user),
        operationId: String(departure._id),
        result: `avisados ${sent.length}, fallidos ${failed.length}`
    });
    return { ok: true, plan, sent: sent.length, failed };
}

async function previewBulk(filters, text, user) {
    const WebOrder = mongoose.model('WebOrder');
    const query = { deletedAt: { $exists: false }, status: { $ne: 'cancelado' } };
    if (filters.shippingMethod) query.shippingMethod = filters.shippingMethod;
    if (filters.city) query.shippingCity = filters.city;
    if (filters.fulfillmentStatus) query.fulfillmentStatus = filters.fulfillmentStatus;
    let orders = await WebOrder.find(query).limit(300).lean();
    if (filters.situationId) {
        const situation = await controlModels().WaSituation.findById(filters.situationId).lean();
        orders = orders.filter((order) => situation && orderMatchesScope(order, situation));
    }
    const token = crypto.randomBytes(16).toString('hex');
    const preview = {
        recipients: orders.length,
        text: clean(text, 2000),
        orders: orders.map((order) => ({ id: String(order._id), orderNumber: order.orderNumber, waFrom: order.waFrom || '' })),
        alreadySent: 0
    };
    if (!preview.text) return { ok: false, message: 'Escribí el texto exacto del aviso.' };
    if (!preview.recipients) return { ok: false, message: 'No hay destinatarios con ese filtro.' };
    await controlModels().WaBulkPreview.create({
        token,
        actor: actorOf(user),
        payload: filters,
        preview,
        expiresAt: new Date(Date.now() + 10 * 60 * 1000)
    });
    return { ok: true, token, preview };
}

async function confirmBulk(token, user) {
    const models = controlModels();
    const preview = await models.WaBulkPreview.findOne({ token, consumedAt: { $exists: false } });
    if (!preview || preview.expiresAt < new Date()) return { ok: false, message: 'La vista previa venció. Volvé a generarla.' };
    if (!wa.config().ok) return { ok: false, message: 'WhatsApp no está configurado. No envié nada.' };
    preview.consumedAt = new Date();
    await preview.save();
    const sent = [];
    const failed = [];
    for (const item of preview.preview.orders || []) {
        if (!item.waFrom) {
            failed.push({ ...item, error: 'sin WhatsApp' });
            continue;
        }
        const key = `bulk:${token}:${item.id}`;
        try {
            await models.WaOutbound.create({ key, waId: item.waFrom, purpose: 'bulk', status: 'sending' });
        } catch (err) {
            if (err?.code === 11000) continue;
            throw err;
        }
        try {
            await wa.sendText(item.waFrom, preview.preview.text);
            await models.WaOutbound.updateOne({ key }, { $set: { status: 'sent', sentAt: new Date() } });
            sent.push(item.id);
        } catch (err) {
            await models.WaOutbound.updateOne({ key }, { $set: { status: 'failed', error: String(err.message || '').slice(0, 180) } });
            failed.push({ ...item, error: 'falló el envío' });
        }
    }
    await recordAudit({ action: 'aviso_masivo', actor: actorOf(user), operationId: token, result: `enviados ${sent.length}, fallidos ${failed.length}` });
    return { ok: true, sent: sent.length, failed };
}

async function tellCustomer(waId, text) {
    if (!waId || !wa.config().ok) return { skipped: true };
    try {
        await wa.sendText(waId, text);
        return { ok: true };
    } catch (err) {
        console.error('[whatsapp] aviso de comprobante', err.message);
        return { ok: false };
    }
}

async function reviewReceipt(id, action, user, extra = {}) {
    const models = controlModels();
    const receipt = await models.WaReceipt.findById(id);
    if (!receipt) return { ok: false, message: 'Comprobante no encontrado.' };
    const WebOrder = mongoose.model('WebOrder');
    const order = receipt.orderId ? await WebOrder.findById(receipt.orderId) : null;
    const note = clean(extra.note, 500);
    receipt.review = receipt.review || [];
    receipt.review.push({ at: new Date(), by: actorOf(user), action, note });
    if (action === 'confirm') {
        const extracted = Number(receipt.extractedAmount);
        const declared = Number(extra.confirmedAmount ?? receipt.declaredAmount);
        const expected = Number(order?.totalAmount) || 0;
        const amount = (Number.isFinite(extracted) && extracted > 0)
            ? extracted
            : (Number.isFinite(declared) && declared > 0 ? declared : expected);
        receipt.status = 'confirmado';
        receipt.confirmedAmount = amount || 0;
        receipt.rejectedAt = null;
        await receipt.save();
        let orderWarning = '';
        if (order && order.paymentStatus !== 'pagado') {
            try {
                const paid = amount || expected;
                order.payments = order.payments || [];
                order.payments.push({ amount: paid, method: receipt.method || 'transferencia', status: 'confirmado', receiptId: String(receipt._id), at: new Date(), by: actorOf(user), note });
                order.amountPaid = (Number(order.amountPaid) || 0) + paid;
                order.financialStatus = 'confirmado';
                order.paymentStatus = 'pagado';
                order.status = 'pagado';
                order.paidAt = order.paidAt || new Date();
                if (order.fulfillmentStatus === 'pendiente_pago') {
                    shop.appendEvent(order, shop.FULFILLMENT.PAGADO, 'Transferencia confirmada por un administrador.');
                    shop.appendEvent(order, shop.FULFILLMENT.PREPARANDO, 'El equipo puede preparar el pedido.');
                }
                try {
                    await shop.deductStock(mongoose.model('Product'), order);
                } catch (err) {
                    console.error('[whatsapp] stock al confirmar transferencia', err.message);
                }
                await order.save();
            } catch (err) {
                orderWarning = String(err.message || 'no se pudo actualizar el pedido').slice(0, 180);
                console.error('[whatsapp] pedido al confirmar transferencia', orderWarning);
            }
        }
        if (mongoose.models.WaConversation && receipt.waId) {
            await mongoose.models.WaConversation.updateOne(
                { waId: receipt.waId },
                { $set: { paymentState: 'confirmado', saleStage: 'done', paymentPreference: 'transferencia' } }
            );
        }
        await tellCustomer(receipt.waId, amount
            ? `Listo, confirmé tu transferencia de ${Number(amount).toLocaleString('es-PY')} Gs. Seguimos con tu pedido.`
            : 'Listo, confirmé tu transferencia. Seguimos con tu pedido.');
        await recordAudit({ action: `comprobante_${action}`, actor: actorOf(user), orderId: receipt.orderId, result: receipt.status });
        return {
            ok: true,
            receipt,
            message: orderWarning
                ? `Transferencia confirmada. Le avisé al cliente. El pedido no se actualizó: ${orderWarning}`
                : 'Transferencia confirmada. Le avisé al cliente.'
        };
    } else if (action === 'reject') {
        receipt.status = 'rechazado';
        receipt.rejectedAt = new Date();
        if (order && order.paymentStatus !== 'pagado') order.financialStatus = 'rechazado';
        await tellCustomer(receipt.waId, 'No pude dar por válida esa captura. Si querés, mandame otra foto del comprobante.');
    } else if (action === 'restore') {
        receipt.status = 'en_verificacion';
        receipt.rejectedAt = null;
    } else if (action === 'duplicate') {
        receipt.status = 'duplicado';
    } else if (action === 'difference') {
        receipt.status = 'diferencia';
        receipt.difference = Number(extra.declaredAmount || receipt.declaredAmount || 0) - Number(order?.totalAmount || receipt.expectedAmount || 0);
        if (order && order.paymentStatus !== 'pagado') order.financialStatus = 'en_verificacion';
    } else if (action === 'reassign' && extra.orderId) {
        receipt.orderId = String(extra.orderId);
        receipt.status = 'en_verificacion';
    } else if (action === 'pending') {
        receipt.status = 'en_verificacion';
        if (order && order.paymentStatus !== 'pagado') order.financialStatus = 'en_verificacion';
    } else {
        return { ok: false, message: 'Acción de verificación no reconocida.' };
    }
    await receipt.save();
    if (order && action !== 'confirm') await order.save();
    await recordAudit({ action: `comprobante_${action}`, actor: actorOf(user), orderId: receipt.orderId, result: receipt.status });
    return { ok: true, receipt };
}

async function registerIncomingReceipt({ waId, orderId, declaredAmount, mediaId, reference, mediaUrl, imageData, senderName, recipientName, bankName, extractedAmount, isTransfer, rawText }) {
    const fingerprint = receiptFingerprint({ orderId, declaredAmount, mediaId, reference });
    const models = controlModels();
    const existing = await models.WaReceipt.findOne({ fingerprint });
    if (existing) {
        return { ok: true, duplicate: true, receipt: existing, assessment: assessReceipt({ expectedAmount: existing.expectedAmount, declaredAmount, duplicate: true }) };
    }
    const WebOrder = mongoose.model('WebOrder');
    const order = orderId ? await WebOrder.findById(orderId) : await WebOrder.findOne({ waFrom: waId, paymentStatus: 'pendiente', deletedAt: { $exists: false } }).sort({ createdAt: -1 });
    const expected = Number(order?.totalAmount) || 0;
    const assessment = assessReceipt({ expectedAmount: expected, declaredAmount, duplicate: false });
    const looksReal = Boolean(isTransfer && (extractedAmount || senderName || recipientName || bankName));
    let status = assessment.status;
    if (!expected && looksReal) status = 'parcial';
    else if (looksReal && status === 'en_verificacion') status = 'parcial';
    const receipt = await models.WaReceipt.create({
        fingerprint,
        waId,
        orderId: order ? String(order._id) : '',
        expectedAmount: expected,
        declaredAmount: Number(declaredAmount) || null,
        method: 'transferencia',
        reference: clean(reference, 120),
        mediaUrl: mediaUrl || '',
        imageData: imageData || '',
        senderName: senderName || '',
        recipientName: recipientName || '',
        bankName: bankName || '',
        extractedAmount: extractedAmount || declaredAmount || null,
        isTransfer: Boolean(isTransfer),
        rawText: clean(rawText, 8000),
        status,
        difference: assessment.difference
    });
    if (order && order.paymentStatus !== 'pagado') {
        order.financialStatus = 'en_verificacion';
        await order.save();
    }
    await recordAudit({ action: 'comprobante_recibido', actor: 'whatsapp', waId, orderId: order?._id, result: assessment.status });
    return { ok: true, duplicate: false, receipt, assessment, order };
}

async function integrationStatus() {
    const models = controlModels();
    const [lastInbound, lastOutbound, lastIntent, lastAudit] = await Promise.all([
        models.WaInbound.findOne({}).sort({ createdAt: -1 }).lean(),
        models.WaOutbound.findOne({ status: 'sent' }).sort({ sentAt: -1 }).lean(),
        models.WaPaymentIntent.findOne({ status: 'failed' }).sort({ updatedAt: -1 }).lean(),
        models.WaAudit.findOne({ status: 'error' }).sort({ at: -1 }).lean()
    ]);
    const mongoState = mongoose.connection.readyState;
    return {
        whatsapp: { configured: wa.config().ok, verifyToken: Boolean(wa.config().verifyToken), appSecret: Boolean(wa.config().appSecret) },
        deepinfra: { configured: deepinfra.config().ok, model: deepinfra.config().model },
        pagopar: { configured: Boolean(pagopar.getKeys().publicKey && pagopar.getKeys().privateKey) },
        vision: visionStatus(),
        mongo: { readyState: mongoState, connected: mongoState === 1 },
        cloudinary: { configured: Boolean(process.env.CLOUDINARY_CLOUD_NAME && process.env.CLOUDINARY_API_KEY) },
        lastInboundAt: lastInbound?.createdAt || null,
        lastOutboundAt: lastOutbound?.sentAt || null,
        lastPaymentError: lastIntent?.error || '',
        lastErrorAt: lastAudit?.at || null,
        phoneEcho: 'La API solo informa la intervención desde el celular si Meta envía smb_message_echoes. Si ese campo no está suscripto, el control seguro es pausar la IA en el panel.'
    };
}

async function runMaintenance() {
    const models = controlModels();
    const now = new Date();
    const expired = await models.WaSituation.updateMany(
        { status: 'active', endsAt: { $lt: now } },
        { $set: { status: 'expired' } }
    );
    const stale = await models.WaPaymentIntent.updateMany(
        { status: 'calling', callingAt: { $lt: new Date(now.getTime() - 3 * 60 * 1000) } },
        { $set: { status: 'uncertain', error: 'El proceso se interrumpió durante la llamada a PagoPar.', updatedAt: now } }
    );
    const stuck = await models.WaInbound.updateMany(
        { status: 'processing', createdAt: { $lt: new Date(now.getTime() - 5 * 60 * 1000) } },
        { $set: { status: 'error', error: 'El procesamiento quedó trabado.' } }
    );
    await models.WaAutomation.updateMany(
        { key: { $in: ['expire_situations', 'stale_payments', 'stuck_inbound'] } },
        { $set: { lastRunAt: now, lastResult: 'ok', lastError: '' } }
    );
    return {
        situations: expired.modifiedCount || 0,
        payments: stale.modifiedCount || 0,
        inbound: stuck.modifiedCount || 0
    };
}

function opsSnapshot(settings) {
    const value = settings || DEFAULT_SETTINGS;
    return {
        ...value,
        afterCutoff: afterCutoff(new Date(), value),
        clock: zonedParts(new Date(), value.timezone || 'America/Asuncion')
    };
}

module.exports = {
    DEFAULT_SETTINGS,
    DEFAULT_CARRIERS,
    DEFAULT_AUTOMATIONS,
    CATEGORIES,
    SCENARIOS,
    ensureDefaults,
    publishedAi,
    saveAiDraft,
    publishAi,
    dashboardData,
    listConversations,
    getConversation,
    setAttention,
    addInternalNote,
    sendManualMessage,
    listOrders,
    getOrder,
    changeOrder,
    quote,
    saveRate,
    dispatchDeparture,
    previewBulk,
    confirmBulk,
    reviewReceipt,
    registerIncomingReceipt,
    integrationStatus,
    runMaintenance,
    opsSnapshot,
    simulateTurn,
    situationConflicts,
    situationIsLive,
    orderMatchesScope,
    proposedDate,
    ATTENTION_LABELS,
    redactSecrets,
    ensurePagoparHash
};
