'use strict';

const crypto = require('crypto');

const OPEN_STATUSES = ['reserved', 'calling', 'uncertain', 'link_ready', 'sent', 'retry_authorized'];

function paymentFingerprint({ waId, cart, shipping, total, customer }) {
    const items = (cart || []).map((item) => ({
        id: String(item.productId || ''),
        v: String(item.variantName || ''),
        q: Number(item.quantity) || 0,
        p: Number(item.price) || 0
    })).sort((a, b) => `${a.id}${a.v}`.localeCompare(`${b.id}${b.v}`));
    const body = JSON.stringify({
        waId: String(waId || ''),
        items,
        total: Number(total) || 0,
        method: shipping?.method || '',
        city: String(shipping?.city || '').trim().toLowerCase(),
        address: String(shipping?.address || '').trim().toLowerCase(),
        doc: String(customer?.document || '').replace(/\D/g, '')
    });
    return crypto.createHash('sha256').update(body).digest('hex').slice(0, 32);
}

function isUncertainProviderError(err) {
    if (!err) return false;
    if (err.uncertain === true) return true;
    const name = String(err.name || '');
    if (name === 'TimeoutError' || name === 'AbortError') return true;
    const code = err.code || err.cause?.code;
    if (['ECONNRESET', 'ECONNREFUSED', 'ETIMEDOUT', 'EAI_AGAIN', 'UND_ERR_CONNECT_TIMEOUT'].includes(code)) return true;
    if (Number(err.status) >= 500) return true;
    return false;
}

function resolveIntentTarget({ openIntent, fingerprint, cartEmpty, mode }) {
    if (openIntent && ['calling', 'uncertain'].includes(openIntent.status)) {
        return { action: 'blocked', intent: openIntent, reason: openIntent.status };
    }
    if (openIntent && openIntent.status === 'confirmed') {
        return { action: 'paid', intent: openIntent };
    }
    if (!openIntent) return { action: 'new', key: fingerprint };
    if (mode === 'resend' || cartEmpty) return { action: 'reuse', intent: openIntent };
    if (openIntent.fingerprint === fingerprint || openIntent.key === fingerprint) {
        return { action: 'reuse', intent: openIntent };
    }
    if (mode === 'create' || mode === 'confirm') {
        return { action: 'supersede', intent: openIntent, key: fingerprint };
    }
    return { action: 'reuse', intent: openIntent };
}

function shouldSendLink(intent, { now = Date.now(), explicit = false, admin = false, cooldownMs = 120000, queuedInTurn = false } = {}) {
    if (!intent) return { send: false, reason: 'sin_intencion' };
    if (queuedInTurn) return { send: false, reason: 'ya_en_este_turno' };
    if (intent.status === 'uncertain' || intent.status === 'calling') return { send: false, reason: intent.status };
    if (intent.status === 'expired') return { send: false, reason: 'vencido' };
    if (!intent.payUrl && !intent.hash) return { send: false, reason: 'sin_enlace' };
    if (intent.expiresAt && new Date(intent.expiresAt).getTime() < now) return { send: false, reason: 'vencido' };
    const sentAt = intent.linkSentAt ? new Date(intent.linkSentAt).getTime() : 0;
    if (!sentAt || intent.linkSendStatus !== 'sent') return { send: true, reason: 'pendiente_de_envio' };
    if (admin) return { send: true, reason: 'reenvio_admin' };
    if (explicit && (now - sentAt) >= cooldownMs) return { send: true, reason: 'reenvio_explicito' };
    return { send: false, reason: 'ya_enviado' };
}

function createMemoryStore() {
    const rows = new Map();
    return {
        rows,
        async insertIfAbsent(doc) {
            if (rows.has(doc.key)) {
                const error = new Error('duplicate');
                error.code = 11000;
                throw error;
            }
            const row = { ...doc, events: [] };
            rows.set(doc.key, row);
            return row;
        },
        async findByKey(key) {
            return rows.get(key) || null;
        },
        async updateIfStatus(key, statuses, patch) {
            const row = rows.get(key);
            if (!row || !statuses.includes(row.status)) return null;
            Object.assign(row, patch);
            return row;
        }
    };
}

async function waitForIntent(store, key, timeoutMs = 4000) {
    const start = Date.now();
    let current = await store.findByKey(key);
    while (current && current.status === 'calling' && (Date.now() - start) < timeoutMs) {
        await new Promise((resolve) => setTimeout(resolve, 15));
        current = await store.findByKey(key);
    }
    return current;
}

async function runLockedCharge(store, { key, fingerprint, createCharge, now = new Date(), isUncertain = isUncertainProviderError, extra = {} }) {
    let existing = await store.findByKey(key);
    if (existing && existing.status === 'calling') existing = await waitForIntent(store, key);
    if (existing && ['calling', 'uncertain', 'link_ready', 'sent', 'confirmed'].includes(existing.status)) {
        if (existing.expiresAt && new Date(existing.expiresAt).getTime() < new Date(now).getTime() && existing.status !== 'confirmed') {
            return { outcome: 'expired', intent: existing, providerCalled: false };
        }
        return {
            outcome: existing.status === 'calling' ? 'in_progress' : (existing.status === 'uncertain' ? 'uncertain' : 'reuse'),
            intent: existing,
            providerCalled: false
        };
    }
    try {
        await store.insertIfAbsent({
            key,
            fingerprint,
            status: 'reserved',
            createdAt: now,
            providerCalls: 0,
            ...extra
        });
    } catch (err) {
        if (err.code !== 11000) throw err;
    }
    const locked = await store.updateIfStatus(key, ['reserved', 'failed', 'retry_authorized'], {
        status: 'calling',
        callingAt: now
    });
    if (!locked) {
        let current = await store.findByKey(key);
        if (current?.status === 'calling') current = await waitForIntent(store, key);
        return {
            outcome: current?.status === 'uncertain' ? 'uncertain' : (current?.status === 'calling' ? 'in_progress' : 'reuse'),
            intent: current,
            providerCalled: false
        };
    }
    try {
        const created = await createCharge();
        if (created?.uncertain) {
            const intent = await store.updateIfStatus(key, ['calling'], {
                status: 'uncertain',
                orderId: created.orderId || '',
                error: created.error || 'respuesta incierta del proveedor',
                providerCalls: (locked.providerCalls || 0) + 1
            });
            return { outcome: 'uncertain', intent, providerCalled: true };
        }
        const intent = await store.updateIfStatus(key, ['calling'], {
            status: 'link_ready',
            hash: created.hash,
            payUrl: created.payUrl,
            orderId: created.orderId,
            expiresAt: created.expiresAt || null,
            providerCalls: (locked.providerCalls || 0) + 1
        });
        return { outcome: 'created', intent, providerCalled: true };
    } catch (err) {
        const uncertain = isUncertain(err);
        const intent = await store.updateIfStatus(key, ['calling'], {
            status: uncertain ? 'uncertain' : 'failed',
            error: String(err.message || 'error').slice(0, 300),
            providerCalls: (locked.providerCalls || 0) + 1
        });
        return { outcome: uncertain ? 'uncertain' : 'failed', intent, providerCalled: true };
    }
}

function receiptFingerprint(input = {}) {
    const body = JSON.stringify({
        orderId: String(input.orderId || ''),
        amount: Number(input.declaredAmount) || 0,
        mediaId: String(input.mediaId || ''),
        reference: String(input.reference || '').trim().toLowerCase()
    });
    return crypto.createHash('sha256').update(body).digest('hex').slice(0, 32);
}

function assessReceipt({ expectedAmount, declaredAmount, duplicate }) {
    if (duplicate) return { status: 'duplicado', difference: 0, confirm: false };
    const expected = Number(expectedAmount);
    const declared = Number(declaredAmount);
    if (!Number.isFinite(declared)) return { status: 'en_verificacion', difference: null, confirm: false };
    const difference = declared - expected;
    if (difference === 0) return { status: 'en_verificacion', difference: 0, confirm: false };
    return { status: 'diferencia', difference, confirm: false };
}

module.exports = {
    OPEN_STATUSES,
    paymentFingerprint,
    isUncertainProviderError,
    resolveIntentTarget,
    shouldSendLink,
    createMemoryStore,
    runLockedCharge,
    receiptFingerprint,
    assessReceipt
};
