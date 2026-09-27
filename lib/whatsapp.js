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
    const incoming = String(headerValue || '').trim();
    const match = incoming.match(/^sha256=([a-f0-9]+)$/i);
    if (!match) return { ok: false, skipped: false, reason: 'header' };
    const expected = crypto.createHmac('sha256', appSecret).update(rawBody || '').digest();
    const given = Buffer.from(match[1], 'hex');
    if (given.length !== expected.length) return { ok: false, skipped: false, reason: 'length' };
    return { ok: crypto.timingSafeEqual(given, expected), skipped: false };
}

function summarizeWebhook(body) {
    const notes = [];
    const entries = body?.entry || [];
    if (!entries.length) notes.push('payload sin entry');
    for (const entry of entries) {
        const changes = entry?.changes || [];
        if (!changes.length) notes.push('entry sin changes');
        for (const change of changes) {
            const value = change?.value || {};
            const field = change?.field || '?';
            const messages = value.messages || [];
            const statuses = value.statuses || [];
            const errors = value.errors || [];
            if (messages.length) {
                notes.push(`${messages.length} mensaje(s) field=${field}`);
            } else if (statuses.length) {
                const st = statuses.map((s) => s.status).filter(Boolean).join(',') || 'desconocido';
                notes.push(`sin mensaje de clienta, solo status=${st} field=${field}`);
            } else if (errors.length) {
                const detail = errors.map((e) => e.message || e.title || e.code).filter(Boolean).join('; ');
                notes.push(`error de Meta: ${detail || 'sin detalle'} field=${field}`);
            } else {
                notes.push(`field=${field} sin messages`);
            }
        }
    }
    return notes.join(' | ') || 'payload vacío';
}

function explainGraphError(err) {
    const code = err?.code || err?.payload?.error?.code;
    const sub = err?.payload?.error?.error_subcode;
    const msg = err?.message || 'error de WhatsApp';
    const bits = [`code=${code || '?'}`];
    if (sub) bits.push(`sub=${sub}`);
    bits.push(msg);
    let hint = '';
    if (code === 190 || /access token/i.test(msg) || /session has expired/i.test(msg) || /OAuthException/i.test(msg)) {
        hint = ' El WHATSAPP_TOKEN venció o es inválido. El token temporal de Meta dura unas horas; hace falta uno permanente de un system user.';
    } else if (code === 100 || /does not exist/i.test(msg) || /nonexisting/i.test(msg) || /Unsupported post request/i.test(msg)) {
        hint = ' Revisá WHATSAPP_PHONE_NUMBER_ID: es el Phone number ID de API Setup, no el teléfono 595...';
    } else if (code === 131030 || /not in allowed list/i.test(msg)) {
        hint = ' La app está en modo desarrollo: agregá ese WhatsApp como número de prueba, o pasá la app a modo Live.';
    } else if (code === 131047 || /re-engagement/i.test(msg)) {
        hint = ' Fuera de la ventana de 24 h. La clienta tiene que escribir de nuevo.';
    } else if (code === 10 || code === 200 || /permission/i.test(msg)) {
        hint = ' El token no tiene permiso whatsapp_business_messaging.';
    }
    return `${bits.join(' ')}.${hint}`;
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

async function graphFetch(path, { method = 'GET', body, raw = false, timeoutMs = 20000 } = {}) {
    const cfg = config();
    if (!cfg.token) throw new Error('Falta WHATSAPP_TOKEN');
    const headers = { Authorization: `Bearer ${cfg.token}` };
    if (body && !raw) headers['Content-Type'] = 'application/json';
    const response = await fetch(graphUrl(path), {
        method,
        headers,
        body: body == null ? undefined : (raw ? body : JSON.stringify(body)),
        signal: AbortSignal.timeout(timeoutMs)
    });
    const text = await response.text();
    let json = null;
    try { json = text ? JSON.parse(text) : {}; } catch { json = { raw: text }; }
    if (!response.ok) {
        const err = new Error(json?.error?.message || `WhatsApp Graph ${response.status}`);
        err.status = response.status;
        err.code = json?.error?.code;
        err.payload = json;
        throw err;
    }
    return json;
}

async function sendPayload(to, payload, phoneNumberId) {
    const cfg = config();
    const id = String(phoneNumberId || cfg.phoneNumberId || '').trim();
    if (!cfg.token || !id) throw new Error('Falta WHATSAPP_TOKEN o WHATSAPP_PHONE_NUMBER_ID');
    return graphFetch(`${id}/messages`, {
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

async function sendText(to, text, phoneNumberId) {
    const chunks = chunkText(text);
    let last = null;
    for (const body of chunks) {
        last = await sendPayload(to, { type: 'text', text: { body, preview_url: true } }, phoneNumberId);
    }
    return last;
}

async function sendImage(to, link, caption, phoneNumberId) {
    return sendPayload(to, {
        type: 'image',
        image: { link, caption: caption ? String(caption).slice(0, 1024) : undefined }
    }, phoneNumberId);
}

async function sendVideo(to, link, caption, phoneNumberId) {
    return sendPayload(to, {
        type: 'video',
        video: { link, caption: caption ? String(caption).slice(0, 1024) : undefined }
    }, phoneNumberId);
}

async function sendButtons(to, bodyText, buttons, phoneNumberId) {
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
    }, phoneNumberId);
}

async function sendList(to, bodyText, buttonLabel, rows, phoneNumberId) {
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
    }, phoneNumberId);
}

async function sendLocationRequest(to, bodyText, phoneNumberId) {
    return sendPayload(to, {
        type: 'interactive',
        interactive: {
            type: 'location_request_message',
            body: { text: String(bodyText || 'Compartí tu ubicación 💖').slice(0, 1024) },
            action: { name: 'send_location' }
        }
    }, phoneNumberId);
}

async function markReadTyping(messageId, phoneNumberId) {
    const cfg = config();
    const id = String(phoneNumberId || cfg.phoneNumberId || '').trim();
    if (!cfg.token || !id || !messageId) return { skipped: true };
    try {
        return await graphFetch(`${id}/messages`, {
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

async function sendReplies(to, replies, phoneNumberId) {
    const list = Array.isArray(replies) ? replies : [replies];
    let sent = 0;
    let failed = 0;
    for (const reply of list) {
        if (!reply) continue;
        try {
            if (reply.type === 'text' || !reply.type) await sendText(to, reply.text || reply, phoneNumberId);
            else if (reply.type === 'image') await sendImage(to, reply.link, reply.caption, phoneNumberId);
            else if (reply.type === 'video') {
                try {
                    await sendVideo(to, reply.link, reply.caption, phoneNumberId);
                } catch (err) {
                    console.warn('[whatsapp] video falló, mando link:', explainGraphError(err));
                    await sendText(to, `${reply.caption || 'Video'}\n${reply.link}`, phoneNumberId);
                }
            } else if (reply.type === 'buttons') await sendButtons(to, reply.text, reply.buttons, phoneNumberId);
            else if (reply.type === 'list') await sendList(to, reply.text, reply.button, reply.rows, phoneNumberId);
            else if (reply.type === 'location_request') {
                try {
                    await sendLocationRequest(to, reply.text, phoneNumberId);
                } catch (err) {
                    console.warn('[whatsapp] location_request no disponible:', explainGraphError(err));
                    await sendText(to, reply.text || 'Linda, compartime tu ubicación con el clip 📎 → Ubicación, así vemos si te llega Motobolt o encomienda 💖', phoneNumberId);
                }
            }
            sent += 1;
            console.log('[whatsapp] respuesta enviada a', String(to).replace(/\D/g, ''), reply.type || 'text');
        } catch (err) {
            failed += 1;
            console.error('[whatsapp] NO se pudo enviar la respuesta:', explainGraphError(err));
            if (reply.type && reply.type !== 'text') {
                try {
                    await sendText(to, reply.text || reply.caption || 'Un toque linda, se me trabó un archivo 💖', phoneNumberId);
                    sent += 1;
                } catch (fallbackErr) {
                    console.error('[whatsapp] el texto de respaldo tampoco salió:', explainGraphError(fallbackErr));
                }
            }
        }
        await new Promise((r) => setTimeout(r, 250));
    }
    return { sent, failed };
}

function phoneIdLooksLikeHandset(phoneNumberId) {
    return /^595\d{6,10}$/.test(String(phoneNumberId || '').trim());
}

async function logAccountStatus() {
    const cfg = config();
    const base = String(process.env.BASE_URL || '').replace(/\/$/, '');
    const webhookUrl = base ? `${base}/api/whatsapp/webhook` : '';
    console.log(`[whatsapp] diagnóstico: token=${cfg.token ? 'sí' : 'NO'} phone_number_id=${cfg.phoneNumberId || 'NO'} verify_token=${cfg.verifyToken ? 'sí' : 'NO'} app_secret=${cfg.appSecret ? 'sí' : 'no'} webhook=${webhookUrl || '(falta BASE_URL)'}`);
    if (!cfg.verifyToken) {
        console.warn('[whatsapp] Falta WHATSAPP_VERIFY_TOKEN. Sin eso Meta no puede verificar el webhook y no manda los mensajes.');
    }
    if (phoneIdLooksLikeHandset(cfg.phoneNumberId)) {
        console.warn('[whatsapp] WHATSAPP_PHONE_NUMBER_ID parece un teléfono 595.... Tiene que ser el Phone number ID de API Setup, no el número al que escriben.');
    }
    if (!cfg.ok) return;
    const fieldSets = [
        'display_phone_number,verified_name,quality_rating,code_verification_status,platform_type,webhook_configuration,status,name_status,account_mode',
        'display_phone_number,verified_name,quality_rating'
    ];
    let info = null;
    let lastErr = null;
    for (const fields of fieldSets) {
        try {
            info = await graphFetch(`${cfg.phoneNumberId}?fields=${fields}`);
            break;
        } catch (err) {
            lastErr = err;
        }
    }
    if (!info) {
        console.error('[whatsapp] NO pude leer el número en Meta.', explainGraphError(lastErr));
        console.error('[whatsapp] Con el token o el Phone number ID mal, el bot no puede responder aunque le escriban.');
        return;
    }
    const hook = info.webhook_configuration || null;
    console.log('[whatsapp] número en Meta:', JSON.stringify({
        id: info.id,
        display_phone_number: info.display_phone_number,
        verified_name: info.verified_name,
        status: info.status,
        account_mode: info.account_mode,
        code_verification_status: info.code_verification_status,
        name_status: info.name_status,
        quality_rating: info.quality_rating,
        platform_type: info.platform_type,
        webhook: hook
    }));
    if (info.display_phone_number) {
        console.log(`[whatsapp] Para probar, escribí por WhatsApp al ${info.display_phone_number}. Si el de la web es otro, ese no entra a este bot.`);
    }
    const configured = hook?.application || hook?.override_callback_uri || '';
    if (configured && webhookUrl && String(configured).replace(/\/$/, '') !== webhookUrl) {
        console.warn('[whatsapp] Meta tiene otro webhook en el número:', configured, '| este server escucha', webhookUrl);
    }
    if (info.status && info.status !== 'CONNECTED') {
        console.warn(`[whatsapp] El número no está CONNECTED (está ${info.status}). Meta no avisa los mensajes reales hasta que esté conectado.`);
    }
    console.log('[whatsapp] Cuando alguien escriba, en esta consola tiene que aparecer "SÍ llegó mensaje". Si no aparece, Meta no está llamando al webhook: en Configuration suscribí el campo messages y, si la app sigue en desarrollo, pasala a Live o agregá ese WhatsApp como número de prueba.');
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
    summarizeWebhook,
    explainGraphError,
    normalizeIncoming,
    logAccountStatus,
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
