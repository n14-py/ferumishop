'use strict';

const crypto = require('crypto');
const { sanitizeOutgoingText } = require('./text');

function replyText(reply) {
    if (!reply) return '';
    if (typeof reply === 'string') return reply;
    return String(reply.text || reply.caption || '');
}

function payUrlsIn(text) {
    return (String(text || '').match(/https?:\/\/\S+/g) || [])
        .map((url) => url.replace(/[),.;]+$/, ''))
        .filter((url) => /ferumi\.shop|pagopar\.com|\/api\/whatsapp\/ir-a-pagar\//i.test(url) || /pedido/i.test(url));
}

function collapseOutgoing(replies) {
    const out = [];
    const seen = new Set();
    const urls = new Set();
    for (const reply of replies || []) {
        if (!reply) continue;
        const normalized = typeof reply === 'string'
            ? { type: 'text', text: sanitizeOutgoingText(reply) }
            : { ...reply, text: reply.text ? sanitizeOutgoingText(reply.text) : reply.text, caption: reply.caption ? sanitizeOutgoingText(reply.caption) : reply.caption };
        const text = replyText(normalized);
        const urlsHere = payUrlsIn(text);
        const type = normalized.type || 'text';
        if ((type === 'text' || type === 'buttons') && urlsHere.length && urlsHere.every((url) => urls.has(url))) {
            continue;
        }
        const fingerprint = `${type}:${text}:${normalized.link || ''}:${(normalized.buttons || []).map((button) => button.id).join(',')}`;
        if (seen.has(fingerprint)) continue;
        seen.add(fingerprint);
        urlsHere.forEach((url) => urls.add(url));
        out.push(normalized);
    }
    return out;
}

function bodyHash(payload) {
    return crypto.createHash('sha256').update(String(payload || '')).digest('hex').slice(0, 40);
}

function createMemoryOutbound() {
    const rows = new Map();
    return {
        rows,
        async claim({ key }) {
            const current = rows.get(key);
            if (!current) {
                rows.set(key, { key, status: 'sending' });
                return { send: true, status: 'sending' };
            }
            if (current.status === 'sent') return { send: false, reason: 'ya_enviado' };
            if (current.status === 'sending') return { send: false, reason: 'en_curso' };
            current.status = 'sending';
            return { send: true, status: 'retry' };
        },
        async mark(key, status) {
            const current = rows.get(key);
            if (current) current.status = status;
            return current;
        }
    };
}

async function claimOutbound(store, key) {
    return store.claim({ key });
}

module.exports = {
    collapseOutgoing,
    payUrlsIn,
    bodyHash,
    createMemoryOutbound,
    claimOutbound
};
