'use strict';

const BANKS = ['ueno', 'itau', 'itaú', 'continental', 'familiar', 'atlas', 'gnb', 'sudameris', 'bnf', 'vision', 'visión', 'interfisa', 'solar'];

function moneyFrom(text) {
    const match = String(text || '').match(/(?:gs\.?|guaran[ií]es|monto|importe)\s*[:.]?\s*([\d.]+(?:[.,]\d+)?)/i)
        || String(text || '').match(/\b([\d.]{4,})\s*(?:gs|guaran)/i);
    if (!match) return null;
    const amount = parseInt(String(match[1]).replace(/\./g, '').replace(',', ''), 10);
    return Number.isFinite(amount) && amount > 0 ? amount : null;
}

function parseTransferText(text) {
    const raw = String(text || '').replace(/\s+/g, ' ').trim();
    const bank = BANKS.find((name) => raw.toLowerCase().includes(name)) || '';
    const recipient = (raw.match(/(?:destinatario|beneficiario|para)\s*[:\-]?\s*([A-Za-zÁÉÍÓÚÑáéíóúñ .]{3,60})/i) || [])[1] || '';
    const sender = (raw.match(/(?:ordenante|remitente|emisor|origen)\s*[:\-]?\s*([A-Za-zÁÉÍÓÚÑáéíóúñ .]{3,60})/i) || [])[1] || '';
    const amount = moneyFrom(raw);
    return {
        isTransfer: Boolean(amount || bank || recipient || sender),
        amount,
        bank: bank ? bank[0].toUpperCase() + bank.slice(1) : '',
        recipientName: recipient.trim(),
        senderName: sender.trim()
    };
}

function visionConfigured() {
    const key = String(process.env.GEMINI_API_KEY || '').trim();
    const model = String(process.env.WA_VISION_MODEL || 'gemini-2.0-flash').trim();
    return { ok: Boolean(key), key, model };
}

async function readReceiptImage(buffer, mime, fetchImpl = fetch) {
    const cfg = visionConfigured();
    if (!cfg.ok || !buffer) return { available: false, parsed: parseTransferText('') };
    const url = `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(cfg.model)}:generateContent?key=${encodeURIComponent(cfg.key)}`;
    const response = await fetchImpl(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            contents: [{
                parts: [
                    { text: 'Leé esta imagen de un comprobante bancario de Paraguay. Respondé solo JSON con es_transferencia, monto (número entero de guaraníes), banco, destinatario y emisor. Si no es una transferencia, es_transferencia false y el resto vacío. No agregues texto.' },
                    { inline_data: { mime_type: mime || 'image/jpeg', data: Buffer.from(buffer).toString('base64') } }
                ]
            }]
        }),
        signal: AbortSignal.timeout(20000)
    });
    const json = await response.json().catch(() => ({}));
    if (!response.ok) {
        const error = new Error(json?.error?.message || 'No pude leer el comprobante.');
        error.status = response.status;
        throw error;
    }
    const text = (json?.candidates?.[0]?.content?.parts || []).map((part) => part.text || '').join('');
    const start = text.indexOf('{');
    const end = text.lastIndexOf('}');
    let data = {};
    if (start >= 0 && end > start) {
        try { data = JSON.parse(text.slice(start, end + 1)); } catch { data = {}; }
    }
    const parsed = {
        isTransfer: data.es_transferencia !== false && Boolean(data.monto || data.banco || data.destinatario || data.emisor),
        amount: Number(data.monto) > 0 ? Math.round(Number(data.monto)) : null,
        bank: String(data.banco || '').slice(0, 40),
        recipientName: String(data.destinatario || '').slice(0, 80),
        senderName: String(data.emisor || '').slice(0, 80)
    };
    if (!parsed.isTransfer) parsed.isTransfer = false;
    return { available: true, parsed };
}

function trashStillVisible(rejectedAt, now = new Date()) {
    if (!rejectedAt) return false;
    const age = now.getTime() - new Date(rejectedAt).getTime();
    return age >= 0 && age <= 30 * 24 * 60 * 60 * 1000;
}

module.exports = {
    parseTransferText,
    readReceiptImage,
    visionConfigured,
    trashStillVisible
};
