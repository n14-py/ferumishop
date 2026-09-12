'use strict';

const crypto = require('crypto');

function graphVersion() {
    return String(process.env.WHATSAPP_API_VERSION || 'v21.0').trim() || 'v21.0';
}

function config() {
    const token = String(process.env.WHATSAPP_TOKEN || '').trim();
    const phoneNumberId = String(process.env.WHATSAPP_PHONE_NUMBER_ID || '').trim();
    const verifyToken = String(process.env.WHATSAPP_VERIFY_TOKEN || '').trim();
    const appSecret = String(process.env.WHATSAPP_APP_SECRET || '').trim();
    return {
        token,
        phoneNumberId,
        verifyToken,
        appSecret,
        version: graphVersion(),
        ok: Boolean(token && phoneNumberId)
    };
}

function graphUrl(path) {
    const cfg = config();
    return `https://graph.facebook.com/${cfg.version}/${String(path).replace(/^\//, '')}`;
}

function verifySignature(rawBody, headerValue) {
    const { appSecret } = config();
    if (!appSecret) return { ok: true, skipped: true };
    const incoming = String(headerValue || '');
    const match = incoming.match(/^sha256=(.+)$/i);
    if (!match) return { ok: false, skipped: false };
    const expected = crypto
        .createHmac('sha256', appSecret)
        .update(rawBody || '')
        .digest('hex');
    const a = Buffer.from(match[1], 'utf8');
    const b = Buffer.from(expected, 'utf8');
    if (a.length !== b.length) return { ok: false, skipped: false };
    return { ok: crypto.timingSafeEqual(a, b), skipped: false };
}

function challengeResponse(query) {
    const mode = String(query['hub.mode'] || '');
    const token = String(query['hub.verify_token'] || '');
    const challenge = String(query['hub.challenge'] || '');
    const expected = config().verifyToken;
    if (mode === 'subscribe' && expected && token === expected) {
        return { ok: true, challenge };
    }
    return { ok: false, challenge: '' };
}

function extractMessages(body) {
    const out = [];
    for (const entry of body?.entry || []) {
        for (const change of entry.changes || []) {
            const value = change.value || {};
            if (change.field && change.field !== 'messages') continue;
            const contact = (value.contacts || [])[0] || {};
            for (const msg of value.messages || []) {
                out.push(normalizeIncoming(msg, contact, value.metadata || {}));
            }
        }
    }
    return out;
}

function normalizeIncoming(msg, contact, metadata) {
    const type = String(msg.type || 'text');
    const interactive = msg.interactive || {};
    const buttonReply = interactive.button_reply || {};
    const listReply = interactive.list_reply || {};
    const nfm = interactive.nfm_reply || {};
    let text = '';
    if (type === 'text') text = String(msg.text?.body || '').trim();
    else if (type === 'button') text = String(msg.button?.text || msg.button?.payload || '').trim();
    else if (type === 'interactive') {
        text = String(buttonReply.title || listReply.title || nfm.response_json || '').trim();
    } else if (type === 'location' && msg.location) {
        const loc = msg.location;
        text = `[Ubicación compartida: ${loc.latitude}, ${loc.longitude}${loc.name ? ` (${loc.name})` : ''}${loc.address ? `, ${loc.address}` : ''}]`;
    } else if (type === 'image') text = '[La clienta envió una foto]';
    else if (type === 'video') text = '[La clienta envió un video]';
    else if (type === 'audio' || type === 'voice') text = '[La clienta envió un audio. Pedile que escriba, no podemos escuchar audios.]';
    else if (type === 'sticker') text = '[Sticker]';
    else if (type === 'document') text = '[La clienta envió un archivo]';

    return {
        wamid: msg.id,
        from: String(msg.from || ''),
        timestamp: msg.timestamp,
        type,
        text,
        location: msg.location
            ? {
                lat: Number(msg.location.latitude),
                lng: Number(msg.location.longitude),
                name: msg.location.name || '',
                address: msg.location.address || ''
            }
            : null,
        imageId: msg.image?.id || '',
        videoId: msg.video?.id || '',
        audioId: msg.audio?.id || msg.voice?.id || '',
        buttonId: String(buttonReply.id || listReply.id || msg.button?.payload || '').trim(),
        contactName: contact.profile?.name || '',
        phoneNumberId: metadata.phone_number_id || ''
    };
}

async function graphFetch(path, { method = 'GET', body, raw = false } = {}) {
    const cfg = config();
    if (!cfg.token) throw new Error('Falta WHATSAPP_TOKEN');
    const headers = { Authorization: `Bearer ${cfg.token}` };
    if (body && !raw) headers['Content-Type'] = 'application/json';
    const response = await fetch(graphUrl(path), {
        method,
        headers,
        body: body == null ? undefined : (raw ? body : JSON.stringify(body))
    });
    const text = await response.text();
    let json = null;
    try { json = text ? JSON.parse(text) : {}; } catch { json = { raw: text }; }
    if (!response.ok) {
        const err = new Error(json?.error?.message || `WhatsApp Graph ${response.status}`);
        err.status = response.status;
        err.payload = json;
        throw err;
    }
    return json;
}

async function sendPayload(to, payload) {
    const cfg = config();
    if (!cfg.ok) throw new Error('Falta WHATSAPP_TOKEN o WHATSAPP_PHONE_NUMBER_ID');
    return graphFetch(`${cfg.phoneNumberId}/messages`, {
        method: 'POST',
        body: {
            messaging_product: 'whatsapp',
            recipient_type: 'individual',
            to: String(to).replace(/\D/g, ''),
            ...payload
        }
    });
}

function chunkText(text, max = 3900) {
    const raw = String(text || '').trim();
    if (!raw) return [];
    if (raw.length <= max) return [raw];
    const parts = [];
    let rest = raw;
    while (rest.length > max) {
        let cut = rest.lastIndexOf('\n', max);
        if (cut < max * 0.5) cut = rest.lastIndexOf(' ', max);
        if (cut < max * 0.5) cut = max;
        parts.push(rest.slice(0, cut).trim());
        rest = rest.slice(cut).trim();
    }
    if (rest) parts.push(rest);
    return parts;
}

async function sendText(to, text) {
    const chunks = chunkText(text);
    let last = null;
    for (const body of chunks) {
        last = await sendPayload(to, { type: 'text', text: { body, preview_url: true } });
    }
    return last;
}

async function sendImage(to, link, caption) {
    return sendPayload(to, {
        type: 'image',
        image: { link, caption: caption ? String(caption).slice(0, 1024) : undefined }
    });
}

async function sendVideo(to, link, caption) {
    return sendPayload(to, {
        type: 'video',
        video: { link, caption: caption ? String(caption).slice(0, 1024) : undefined }
    });
}

async function sendButtons(to, bodyText, buttons) {
    const items = (buttons || []).slice(0, 3).map((b) => ({
        type: 'reply',
        reply: {
            id: String(b.id).slice(0, 256),
            title: String(b.title).slice(0, 20)
        }
    }));
    return sendPayload(to, {
        type: 'interactive',
        interactive: {
            type: 'button',
            body: { text: String(bodyText).slice(0, 1024) },
            action: { buttons: items }
        }
    });
}

async function sendList(to, bodyText, buttonLabel, rows) {
    return sendPayload(to, {
        type: 'interactive',
        interactive: {
            type: 'list',
            body: { text: String(bodyText).slice(0, 1024) },
            action: {
                button: String(buttonLabel || 'Ver opciones').slice(0, 20),
                sections: [{
                    title: 'Opciones',
                    rows: (rows || []).slice(0, 10).map((r) => ({
                        id: String(r.id).slice(0, 200),
                        title: String(r.title).slice(0, 24),
                        description: r.description ? String(r.description).slice(0, 72) : undefined
                    }))
                }]
            }
        }
    });
}

async function sendLocationRequest(to, bodyText) {
    return sendPayload(to, {
        type: 'interactive',
        interactive: {
            type: 'location_request_message',
            body: { text: String(bodyText || 'Compartí tu ubicación 💖').slice(0, 1024) },
            action: { name: 'send_location' }
        }
    });
}

async function markReadTyping(messageId) {
    const cfg = config();
    if (!cfg.ok || !messageId) return { skipped: true };
    try {
        return await graphFetch(`${cfg.phoneNumberId}/messages`, {
            method: 'POST',
            body: {
                messaging_product: 'whatsapp',
                status: 'read',
                message_id: messageId,
                typing_indicator: { type: 'text' }
            }
        });
    } catch (err) {
        console.warn('[whatsapp] mark-read/typing:', err.message);
        return { skipped: true };
    }
}

async function mediaUrl(mediaId) {
    if (!mediaId) return null;
    const json = await graphFetch(mediaId);
    return json?.url || null;
}

async function downloadMedia(mediaId) {
    const url = await mediaUrl(mediaId);
    if (!url) throw new Error('WhatsApp no devolvió URL de media');
    const cfg = config();
    const response = await fetch(url, { headers: { Authorization: `Bearer ${cfg.token}` } });
    if (!response.ok) throw new Error(`No se pudo bajar media de WhatsApp (${response.status})`);
    const buffer = Buffer.from(await response.arrayBuffer());
    const contentType = response.headers.get('content-type') || 'image/jpeg';
    return { buffer, contentType };
}

async function sendReplies(to, replies) {
    const list = Array.isArray(replies) ? replies : [replies];
    for (const reply of list) {
        if (!reply) continue;
        try {
            if (reply.type === 'text' || !reply.type) await sendText(to, reply.text || reply);
            else if (reply.type === 'image') await sendImage(to, reply.link, reply.caption);
            else if (reply.type === 'video') {
                try {
                    await sendVideo(to, reply.link, reply.caption);
                } catch (err) {
                    console.warn('[whatsapp] video falló, mando link:', err.message);
                    await sendText(to, `${reply.caption || 'Video'}\n${reply.link}`);
                }
            } else if (reply.type === 'buttons') await sendButtons(to, reply.text, reply.buttons);
            else if (reply.type === 'list') await sendList(to, reply.text, reply.button, reply.rows);
            else if (reply.type === 'location_request') {
                try {
                    await sendLocationRequest(to, reply.text);
                } catch (err) {
                    console.warn('[whatsapp] location_request no disponible:', err.message);
                    await sendText(to, reply.text || 'Linda, compartime tu ubicación con el clip 📎 → Ubicación, así vemos si te llega Motobolt o encomienda 💖');
                }
            }
        } catch (err) {
            console.error('[whatsapp] send reply', reply.type, err.message, err.payload || '');
            if (reply.type !== 'text') {
                try { await sendText(to, reply.text || reply.caption || 'Un toque linda, se me trabó un archivo 💖'); } catch { /* ignore */ }
            }
        }
        await new Promise((r) => setTimeout(r, 250));
    }
}

const queues = new Map();
function enqueue(waId, fn) {
    const key = String(waId || 'unknown');
    const prev = queues.get(key) || Promise.resolve();
    const next = prev.then(fn, fn).catch((err) => {
        console.error('[whatsapp] queue', key, err);
    });
    queues.set(key, next);
    return next;
}

module.exports = {
    config,
    verifySignature,
    challengeResponse,
    extractMessages,
    normalizeIncoming,
    sendText,
    sendImage,
    sendVideo,
    sendButtons,
    sendList,
    sendLocationRequest,
    sendReplies,
    markReadTyping,
    downloadMedia,
    enqueue,
    chunkText
};
